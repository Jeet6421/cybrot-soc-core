# Storage: partitions, retention, ingest limits, backup and recovery

This is what PR 13 changes at the database boundary, how to operate it, and the thresholds that should trigger
the next step (Kafka or anything else). Kafka is deferred. PostgreSQL is validated first.

## What changed

| Area | Behaviour |
|---|---|
| `events`, `audit_events` | Monthly range partitions on `occurred_at`. Primary keys include `occurred_at`, as partitioning requires. |
| Retention | Whole partitions are dropped once they end before `now() - RETENTION_DAYS`. Default 180 days. Values below 180 are refused by the app and by the database. |
| Idempotent ingest | A repeated event is stored once. Identity is `source_event_id` when the sender provides it, otherwise a SHA-256 of the canonical payload. |
| Rate limits | Per (tenant, log source) per minute: events and payload bytes. Over the limit returns `429` with `Retry-After`. Other hospitals are unaffected. |
| Size caps | Maximum events per request, and maximum body bytes. Over the cap returns `413` with a JSON error. |
| Time window | Events older than the retention window, or more than a day in the future, return `400`. |
| Maintenance | The worker creates upcoming partitions and drops expired ones once an hour. |
| Recovery | `scripts/recovery_drill.py` snapshots and verifies a restored database. |

`POST /ingest` in the original brief is `POST /api/events` in this codebase.

## Partitions and retention

- `partition_catalog` records every partition: its range, when it was dropped, and how many rows it held.
- `ensure_time_partitions()` creates monthly partitions from the start of the retention window through two months
  ahead. It is idempotent and runs at every schema apply and every worker maintenance pass.
- `drop_expired_partitions(days)` drops every catalogued partition whose range ends at or before the cutoff. It
  raises if `days < 180`. Because each dropped partition is entirely older than the cutoff, every row newer than
  the cutoff is kept. Rows are kept for at least the retention window, and at most the window plus one month.
- Both functions run as the owner (`SECURITY DEFINER`). The runtime role may execute them and nothing else.
- `tenants.retention_days` (PR 17, default and minimum 180) is each hospital's agreed retention. Partitions are shared,
  so the worker calls `drop_expired_partitions(effective_retention_days(RETENTION_DAYS))`, which never drops data a
  longer-retaining hospital still needs.

Retention applies to `audit_events` too, on the same window. Confirm with your compliance owner that 180 days of
audit history is acceptable, since CERT-In requires at least that much.

### Migrating an existing database

Fresh installs get partitioned tables directly. An existing database must be converted once:

```bash
pg_dump -Fc "$MIGRATE_DATABASE_URL" > soc-before-partitions.dump   # keep this until the copy is verified
docker compose stop app worker
MIGRATE_DATABASE_URL=postgresql://soc:...@db:5432/soc python scripts/partition_migrate.py
docker compose up -d app worker
```

The script renames the legacy tables to `events_legacy` and `audit_events_legacy`, applies the schema, copies every
row, and checks the counts. All of it runs in one transaction, so a failure rolls back. The legacy tables are kept.
Archive them under your retention policy, then drop them yourself, or pass `--drop-legacy` once the copy is verified.

Until the conversion runs, the app still works on the legacy tables. The partition functions skip them with a
notice. The new ingest-key and dedupe columns are added to the legacy table as nullable columns.

## Idempotent ingest

- The response reports `events` (received), `stored`, `duplicates` and `alerts_created`.
- The unique index is `(tenant, log source, dedupe_key, occurred_at)`. Including `occurred_at` lets PostgreSQL enforce
  it per partition, and a replay of the same event always has the same timestamp.
- A duplicate is not stored and does not raise a second alert.
- **Trade-off:** without `source_event_id`, two genuinely identical lines with the same timestamp count as one event.
  Senders whose logs can repeat a line within the same second should send a `source_event_id`.
- A correction that changes the timestamp is a different event under this rule.

## Rate limits and size caps

| Setting | Default | Meaning |
|---|---|---|
| `INGEST_EVENTS_PER_MINUTE` | 60000 | Events per (tenant, log source) per minute |
| `INGEST_BYTES_PER_MINUTE` | 60000000 | Payload bytes per (tenant, log source) per minute |
| `INGEST_MAX_BATCH` | 1000 | Events in one request (`413` above this) |
| `INGEST_MAX_BODY_BYTES` | 1000000 | Request body size (`413` above this) |

- The quota is a fixed one-minute window counted in PostgreSQL, so every app process shares it. A refused request
  writes nothing.
- A fixed window allows up to twice the limit across a minute boundary. Use the limit as a per-minute ceiling, not an
  exact rate.
- Limits are read on each request, so a change applies without a restart.

## Backup and point-in-time recovery

PITR needs a base backup plus continuous WAL archiving. Configure the database (owner) like this:

```
archive_mode = on
archive_command = 'test ! -f /wal-archive/%f && cp %p /wal-archive/%f'   # use a volume that is not the data volume
wal_level = replica
```

Take a base backup daily, and keep at least 14 days of base backups and WAL since the oldest one:

```bash
pg_basebackup -h db -U soc -D /backups/base-$(date +%F) -Ft -z -X stream -P
```

### Restore to a point in time

1. Stop the app and worker. Start a clean PostgreSQL instance on a restore volume.
2. Extract the base backup into its data directory.
3. Set `restore_command = 'cp /wal-archive/%f %p'` and `recovery_target_time = '2026-11-28 10:00:00+05:30'`.
4. Create `recovery.signal` in the data directory, then start PostgreSQL. Wait until recovery finishes and the
   database accepts writes.
5. Run the verifier against the restored database (see below). Only then point the app at it.

### Recovery drill

Run the drill after every restore, and at least quarterly:

```bash
# On the source, at the moment the backup was taken (quiet period preferred):
MIGRATE_DATABASE_URL=postgresql://soc:...@db/soc python scripts/recovery_drill.py snapshot > snapshot.json

# On the restored copy:
MIGRATE_DATABASE_URL=postgresql://soc:...@restored/soc \
DATABASE_URL=postgresql://soc_app:...@restored/soc \
  python scripts/recovery_drill.py verify snapshot.json            # add --exact for a quiesced restore
```

The verifier checks, and exits 1 on any failure:

- row counts per tenant and table (at least the snapshot; exactly it with `--exact`)
- row-level security enabled and forced on every tenant table
- no unvalidated constraints
- every catalogued partition exists
- the audit append-only triggers exist
- isolation as the runtime role: each hospital sees exactly its own rows in `events`, `alerts`, `assets` and
  `log_sources`, and never another hospital's

Record the RPO (time between the restore target and the last committed write you could recover) and the RTO (time
from the decision to restore until the verifier passes). **These targets are not yet measured.** Measure them on the
restore volume during the first drill and write the numbers here.

## When to introduce Kafka

Kafka is not introduced now. The thresholds below are **proposals**, not measured values. Before any of them can be
trusted, measure this deployment's own limits with `scripts/load_test.py` against a VM sized like production, and
record the results in this section.

| Signal | Proposed trigger for a buffer such as Kafka | How to measure |
|---|---|---|
| Sustained database writes | Above 70% of the measured sustainable insert rate for seven consecutive days | Insert rate from `load_test.py` at the p95 latency target, compared with production counts |
| WAL and archive | Archive lag above 15 minutes at p95, or more than 50 GB of WAL per day for seven days | `pg_stat_archiver`, WAL size per day |
| Burst absorption | A 15-minute peak above three times the 24-hour median that the per-source quotas cannot shape without dropping legitimate events | Ingest counts per source per minute, from `ingest_rate` |
| Multi-consumer replay | Two or more independent consumers that each need the same events, with replay older than one hour | Consumer list and replay requests |
| Partition size | A monthly partition above 200 GB, or `events` queries above 500 ms at p95 after index tuning | `pg_total_relation_size`, query logs |

Any single trigger starts a review. Two or more confirm the need. Until then, the boundary is PostgreSQL with
partitions, quotas and the drill above.
