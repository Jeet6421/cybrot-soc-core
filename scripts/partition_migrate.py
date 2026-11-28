"""One-time conversion of an existing database to partitioned events and audit_events (PR 13).

Run as the OWNER role. Take a pg_dump first, and run this with the app stopped:

    MIGRATE_DATABASE_URL=postgresql://soc:...@db:5432/soc python scripts/partition_migrate.py

All steps run in one transaction. If any step fails, the transaction rolls back and the legacy tables are unchanged:

  1. Rename events, audit_events and their indexes and sequences to *_legacy.
  2. Apply db/schema.sql. This creates the partitioned tables with their policies, grants, triggers and indexes.
  3. Create the monthly partitions that cover the oldest copied row.
  4. Copy every row. occurred_at for events is derived from ts; a time with no zone is read as UTC.
     Copied events get dedupe_key 'legacy:<id>', so the new unique index cannot reject them.
  5. Check the row counts match, then move the id sequences past the copied ids.

The legacy tables are kept. Archive them under your retention policy and drop them yourself after you have verified
the copy. Pass --drop-legacy to drop them in the same transaction. docs/STORAGE.md has the full procedure.
"""
import pathlib
import os
import sys

import psycopg
from psycopg import sql

SCHEMA_FILE = pathlib.Path(__file__).resolve().parent.parent / "db" / "schema.sql"
# A ts with a zone keeps it; a ts without one is read as UTC. Mirrors _occurred_at in app.py.
TS_TO_TIMESTAMPTZ = ("CASE WHEN ts ~ '(Z|[+-][0-9]{2}:?[0-9]{2})$' THEN ts::timestamptz "
                     "ELSE ts::timestamp AT TIME ZONE 'UTC' END")


def relkind(conn, name):
    row = conn.execute("SELECT relkind FROM pg_class WHERE relname = %s "
                       "AND relnamespace = 'public'::regnamespace", (name,)).fetchone()
    return row[0] if row else None


def legacy_columns(conn, table):
    rows = conn.execute("SELECT column_name FROM information_schema.columns "
                        "WHERE table_schema = 'public' AND table_name = %s ORDER BY ordinal_position", (table,))
    return [r[0] for r in rows.fetchall()]


def rename_legacy(conn, table, id_column):
    legacy = table + "_legacy"
    conn.execute(sql.SQL("ALTER TABLE {} RENAME TO {}").format(sql.Identifier(table), sql.Identifier(legacy)))
    for (index,) in conn.execute("SELECT indexname FROM pg_indexes WHERE schemaname = 'public' "
                                 "AND tablename = %s", (legacy,)).fetchall():
        conn.execute(sql.SQL("ALTER INDEX {} RENAME TO {}").format(
            sql.Identifier(index), sql.Identifier(index + "_legacy")))
    seq = conn.execute("SELECT pg_get_serial_sequence(%s, %s)", (f"public.{legacy}", id_column)).fetchone()[0]
    if seq:
        seq_name = seq.split(".", 1)[1]
        conn.execute(sql.SQL("ALTER SEQUENCE {} RENAME TO {}").format(
            sql.Identifier(seq_name), sql.Identifier(seq_name + "_legacy")))


def copy_rows(conn, table, legacy_cols, extra):
    """Copy every legacy row. extra maps the new column name to a SQL expression over the legacy columns."""
    cols = [c for c in legacy_cols if c not in extra]
    target_cols = cols + list(extra)
    select_exprs = [sql.Identifier(c) for c in cols] + [sql.SQL(expr) for expr in extra.values()]
    conn.execute(sql.SQL("INSERT INTO {} ({}) SELECT {} FROM {}").format(
        sql.Identifier(table),
        sql.SQL(", ").join(sql.Identifier(c) for c in target_cols),
        sql.SQL(", ").join(select_exprs),
        sql.Identifier(table + "_legacy")))


def count(conn, table):
    return conn.execute(sql.SQL("SELECT count(*) FROM {}").format(sql.Identifier(table))).fetchone()[0]


def migrate(url, drop_legacy=False):
    schema = SCHEMA_FILE.read_text()
    with psycopg.connect(url) as conn:
        events_kind, audit_kind = relkind(conn, "events"), relkind(conn, "audit_events")
        if events_kind == "p" and audit_kind == "p":
            print("already partitioned; nothing to do")
            return
        if events_kind not in ("r", None) or audit_kind not in ("r", None):
            raise RuntimeError("unexpected table kinds: events=%s audit_events=%s" % (events_kind, audit_kind))

        report = {}
        if events_kind == "r":
            events_cols = legacy_columns(conn, "events")
            rename_legacy(conn, "events", "id")
            events_cols_legacy = events_cols
        if audit_kind == "r":
            audit_cols = legacy_columns(conn, "audit_events")
            rename_legacy(conn, "audit_events", "audit_id")

        conn.execute(schema)  # creates the partitioned tables; the legacy tables are no longer in the way

        if events_kind == "r":
            oldest = conn.execute(f"SELECT min({TS_TO_TIMESTAMPTZ}) FROM events_legacy").fetchone()[0]
            if oldest is not None:
                conn.execute("SELECT ensure_time_partitions(%s)", (oldest,))
            copy_rows(conn, "events", events_cols_legacy,
                      {"occurred_at": TS_TO_TIMESTAMPTZ, "dedupe_key": "'legacy:' || id"})
            report["events"] = (count(conn, "events_legacy"), count(conn, "events"))
            max_id = conn.execute("SELECT max(id) FROM events").fetchone()[0]
            if max_id is not None:
                conn.execute("SELECT setval(pg_get_serial_sequence('public.events', 'id'), %s, true)", (max_id,))
        if audit_kind == "r":
            oldest = conn.execute("SELECT min(occurred_at) FROM audit_events_legacy").fetchone()[0]
            if oldest is not None:
                conn.execute("SELECT ensure_time_partitions(%s)", (oldest,))
            copy_rows(conn, "audit_events", audit_cols, {})
            report["audit_events"] = (count(conn, "audit_events_legacy"), count(conn, "audit_events"))
            max_id = conn.execute("SELECT max(audit_id) FROM audit_events").fetchone()[0]
            if max_id is not None:
                conn.execute("SELECT setval(pg_get_serial_sequence('public.audit_events', 'audit_id'), %s, true)",
                             (max_id,))

        for table, (legacy_rows, new_rows) in report.items():
            if legacy_rows != new_rows:
                raise RuntimeError(f"{table}: {legacy_rows} legacy rows but {new_rows} copied; rolled back")
            print(f"{table}: {new_rows} rows copied and verified")

        if drop_legacy:
            for table in ("events_legacy", "audit_events_legacy"):
                if relkind(conn, table) == "r":
                    conn.execute(sql.SQL("DROP TABLE {}").format(sql.Identifier(table)))
            print("legacy tables dropped")
        else:
            print("legacy tables kept as events_legacy and audit_events_legacy until you archive and drop them")


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    url = os.environ.get("MIGRATE_DATABASE_URL", "")
    if not url:
        print("set MIGRATE_DATABASE_URL to the owner role", file=sys.stderr)
        return 2
    migrate(url, drop_legacy="--drop-legacy" in argv)
    return 0


if __name__ == "__main__":
    sys.exit(main())
