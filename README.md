# Cybrot SOC Core (prototype, v1.0)

Core pipeline for the hospital/clinic SOC service: **logs in -> detection rules -> alert with severity ->
triage queue with a named owner and response step -> metrics -> exit criteria**. Test data only - never real patient data.

This version follows the internal test plan in the prototype plan document: the four roadmap gates
(Foundation, Detection, Response, Review) are checked by the app and by scripts.

## Run locally
    # PostgreSQL 16 is required. Start one (the defaults below match DATABASE_URL's default):
    docker run -d --name soc-pg -e POSTGRES_USER=soc -e POSTGRES_PASSWORD=soc -e POSTGRES_DB=soc -p 5432:5432 postgres:16
    pip install -r requirements.txt
    python app.py                 # http://localhost:5000
    # Click "Load demo data", then "Auto-label (lab)", or triage alerts by hand (Ack / TP / FP / ?)
    python generate.py            # or push synthetic logs from the command line

## Run with Docker
    docker compose up -d --build  # http://localhost:5000
    # Settings are read from a .env file next to docker-compose.yml. Never commit .env.
    # .env must set POSTGRES_PASSWORD (letters and digits only, so it fits in the connection URL).
    # The database runs in its own container with a named volume (pg-data) and is not published to the host.
    # The Docker build runs in GitHub Actions on every push (see .github/workflows/tests.yml).

## Configuration
| Variable | Default | Purpose |
|---|---|---|
| `DATABASE_URL` | `postgresql://soc:soc@localhost:5432/soc` (Docker: built from `POSTGRES_PASSWORD`) | PostgreSQL connection string. The schema is created on first connect. |
| `POSTGRES_PASSWORD` | required in Docker | Password for the `soc` database role (docker-compose only) |
| `ANALYSTS` | `analyst1,analyst2,analyst3` | Owners for alerts, assigned round-robin |
| `LAB_ENDPOINTS` | `1` | `0` disables `/api/demo`, `/api/autolabel`, `/api/reset` (they return 404) |
| `SOC_API_TOKEN` | empty (no token) | If set, every `/api/` call needs `Authorization: Bearer <token>` |
| `FP_TARGET` | not set | The false-positive ceiling the team agrees, as a fraction (e.g. `0.10`). Until set, the Review gate is `not_measured`. |
| `PLAYBOOK_WEBHOOK` | empty (off) | v0.7: each new alert is POSTed as JSON to this URL, e.g. a Shuffle webhook. Sent after the database commit; a failed send is logged and never blocks ingest. |
| `PLAYBOOK_TIMEOUT` | `3` | Seconds to wait for the playbook webhook |
| `PLAYBOOK_SECRET` | empty (unsigned) | v0.8: if set, each playbook request carries `X-Cybrot-Signature` (HMAC-SHA256). Set it whenever `PLAYBOOK_WEBHOOK` is set. |
| `PORT` | `5000` | HTTP port when running `python app.py` |

## Tests
Tests need a PostgreSQL server. Each test session creates its own database and drops it at the end,
so the tests never touch your data. The admin URL must be allowed to create and drop databases.

    pip install pytest
    TEST_ADMIN_URL=postgresql://soc:soc@localhost:5432/postgres pytest -q tests   # this is the default

## Test plan tools (scripts/)
These use only the Python standard library. Run them against an instance with no real data.

- **Attack simulations** (test plan step 3): posts failed-login burst, bulk record access, and suspicious process,
  checks each raises its alert, and checks that one failed login stays quiet.
  ```
  python scripts/attack_sim.py http://localhost:5000 --token "$SOC_API_TOKEN"
  ```
- **Load test** (test plan step 2): sends a set number of benign events and checks none are lost.
  Run it on an instance with no other traffic, because the count compares the stored total before and after.
  ```
  python scripts/load_test.py http://localhost:5000 --events 5000 --batch 500 --token "$SOC_API_TOKEN"
  ```

## Exit criteria
`GET /api/exit-criteria` returns each roadmap gate as `pass`, `fail`, or `not_measured`, plus `all_pass`.

| Gate | Passes when |
|---|---|
| Foundation: logs flow end to end | At least one event is stored |
| Detection: all planted attacks detected | Every planted attack has an alert |
| Response: every alert has an owner and a step | Every alert has an owner and a response step |
| Review: false positives within target | The false-positive rate is at or below `FP_TARGET` |

The dashboard shows these at the top. `GET /api/metrics` also returns `false_positive_rate_by_week`, so the weekly
trend (test plan step 4) can be tracked.

## Layout
- `app.py`      Flask API + PostgreSQL (psycopg 3): `/api/events`, `/api/ingest/wazuh`, `/api/alerts`, `/api/alerts/<id>/handoff`, `/api/metrics`, `/api/exit-criteria`
- `detect.py`   built-in rules and playbooks; Wazuh playbooks by rule id (`WAZUH_PLAYBOOK`), with a level-based fallback
- `generate.py` synthetic clinic logs with 3 planted attacks (ground truth in `attack_id`)
- `scripts/`    attack simulations and load test (see above)
- `static/`     triage dashboard (`index.html`)
- `tests/`      pytest suite; `fixtures/` holds a real Wazuh alert (Sysmon rule 92213)
- `wazuh/`      Wazuh rules and webhook config (tuning rules 100200 and 100201 tested on the lab Windows VM)
- `.github/workflows/tests.yml`  runs the tests and the Docker build on every push and pull request

## Built-in detection rules
| Rule | Severity | Fires when |
|---|---|---|
| `FAILED_LOGIN_BURST` | high | 5 or more failed logins from one IP within 5 minutes |
| `BULK_RECORD_ACCESS` | high | One user opens 15 or more patient records within 10 minutes |
| `OFFHOURS_ACCESS` | low | Record access between 22:00 and 05:59 (intentionally noisy, for the FP-rate test) |
| `SUSPICIOUS_PROCESS` | critical | A process command line contains `mimikatz`, `certutil -urlcache`, `nc -e`, or `vssadmin delete shadows`, or passes a base64 payload with `-e`, `-ec`, `-enc` or `-EncodedCommand` |

## Wazuh integration
- Wazuh alerts arrive at `POST /api/ingest/wazuh?tenant=<hospital>`. Level 12+ is critical, 10+ high, 7+ medium.
- Each alert keeps its key facts (file path, process) in the `detail` column, shown under the summary.
- Rule 92213 (Sysmon file drop) has its own response step. Other Wazuh rules use a level-based step.
- Repeats of the same rule, host, file and process within 10 minutes are suppressed. A different file alerts again.
- Tuning rule 100200 in `wazuh/local_rules.xml` silences the benign PowerShell execution-policy test file.
  Tested on the lab Windows VM (v0.5): the `__PSScriptPolicyTest_*` file is suppressed, and a different file dropped
  in the same folder still raises rule 92213.
- Tuning rule 100201 silences Disk Cleanup (`cleanmgr.exe`) drops of signed Windows DLLs into a temp GUID folder.
  It matches only that exact writer and path. Deployed on the lab VM (v0.5.2); not yet confirmed on a live Disk Cleanup run.
- Encoded PowerShell commands raise critical Wazuh alerts (rules 92057 and 92071), which reach the triage queue.
- The internal test plan's Atomic Red Team test (T1059.001-15) was detected this way on the lab VM.

## Security (before any real data)
- Set `LAB_ENDPOINTS=0`. The dashboard still shows the lab buttons, but they will return 404.
- Set `SOC_API_TOKEN` to a long random value. It is the operator token for every `/api/` call. The dashboard asks for it once per browser tab.
- Each hospital gets its own **ingest key** (see Tenants below). A key can only send events and Wazuh alerts for its own hospital. It cannot read, change or write into another hospital.
- Wazuh's built-in integration cannot send headers, so `/api/ingest/*` also accepts `?token=` in the URL. The same goes for an ingest key.
  That URL can end up in logs, so keep the webhook on a private network or behind a reverse proxy.
- Serve the app over HTTPS behind a reverse proxy.
- The operator token is still a shared secret, not user login. Per-user accounts, roles and MFA are Phase 2 of `docs/MULTITENANT.md`.
- With `SOC_API_TOKEN` unset, the API is open. That is for the lab only.

## Tenants and ingest keys (v1.1)
Each hospital is a **tenant**. Tenant ids are 2 to 63 lowercase letters, digits or hyphens.

| Step | Call (operator token) | Result |
|---|---|---|
| Create a hospital | `POST /api/tenants` with `{"id":"city-hospital","name":"City Hospital"}` | `201`. `409` if it exists |
| Issue an ingest key | `POST /api/tenants/<id>/keys` with `{"label":"wazuh-ehr"}` | `201`, with the key in the reply. **Shown once.** Only its SHA-256 hash is stored |
| List keys | `GET /api/tenants/<id>/keys` | Metadata only, never the key |
| Revoke a key | `POST /api/keys/<key-id>/revoke` | Revoked keys get `401` |

Events and Wazuh alerts sent with a key are stored under that key's hospital. The `tenant` in the body or the query is ignored for keys. A body that names another hospital gets `403`.

## Hospital data scope (v1.1)
- `GET /api/metrics?tenant=<id>` and `GET /api/exit-criteria?tenant=<id>` count one hospital's data. Without `tenant`, they count everything (operator view).
- `GET /api/alerts?tenant=<id>` filters the queue as before.
- Handoff history rows carry the hospital of their alert.

## API
| Endpoint | Purpose |
|---|---|
| `POST /api/events` | Ingest events; runs the built-in rules |
| `POST /api/ingest/wazuh` | Ingest a Wazuh integration alert |
| `GET /api/alerts` | Newest 200 alerts; filter with `tenant`, `status`, `owner` |
| `POST /api/alerts/<id>/ack` | Acknowledge an alert |
| `POST /api/alerts/<id>/verdict` | Close with `tp`, `fp` or `unclear`, and an optional `note` |
| `POST /api/alerts/<id>/handoff` | Pass an open alert to another analyst: `to_owner`, `note` |
| `GET /api/alerts/<id>/handoffs` | Handoff history for an alert |
| `GET /api/analysts` | Analysts that alerts can be handed to |
| `GET /api/metrics` | Counts, false-positive rate (overall and weekly), detection rate, mean time to ack |
| `GET /api/exit-criteria` | The four roadmap gates, as `pass`, `fail` or `not_measured` |

## Changes
**v1.1 (tenants and ingest keys, Phase 1 of `docs/MULTITENANT.md`)**
- New tables `tenants` (with a `default` lab tenant) and `ingest_keys` (hash only). Handoff history records the hospital.
- Ingest keys: `/api/events` and `/api/ingest/wazuh` accept a key. The tenant comes from the key. A mismatched body tenant gets `403`.
- Keys cannot call any other endpoint (`401`). Revoked and unknown keys get `401`.
- Metrics and exit gates take `?tenant=`.
- `/api/demo` stores events directly instead of calling the API through the test client. Before, it failed with `401` when `SOC_API_TOKEN` was set.
- Tests: `tests/test_tenants.py` (14 tests): cross-hospital writes and reads refused, Wazuh tenant from the key, revocation, hashed keys, scoped metrics.
- Still open in Phase 1: row-level security in PostgreSQL. It needs a separate database role for the app, so the policies apply. That is the next PR.

**v1.0 (PostgreSQL)**
- The database is PostgreSQL 16 (was SQLite). `DATABASE_URL` sets the connection; `docker compose` runs a `db` service with a named volume.
- One connection per request, closed at the end of the request. The schema is created on the first connect to each database.
- Row-level security and per-tenant roles are not in this version. They are the next step (see `docs/MULTITENANT.md`).
- Weekly false-positive labels use ISO weeks (`2026-W47`). The old SQLite labels were `%Y-W%W`, so a week at a year boundary can get a different label.
- SQLite data is not migrated. The prototype data is test data, so start with an empty database.
- Tests create and drop their own PostgreSQL databases. They also check that an old `alerts` table gets the new columns.

**v0.8**
- Playbook webhook is signed when `PLAYBOOK_SECRET` is set: `X-Cybrot-Signature` (HMAC-SHA256 over `<timestamp>.<raw body>`),
  `X-Cybrot-Timestamp`, and `X-Cybrot-Event-Id` (`alert-<id>`, the same on retries so the receiver can de-duplicate).
- Retries: up to 3 attempts for server and network errors (1 s, 2 s backoff). 4xx replies are not retried.
- `docs/SHUFFLE.md`: how to connect Shuffle, verify the signature, test it, and troubleshoot.
- Tests: 4 more in `tests/test_playbook.py` (signature, no signature without a secret, retry, no retry on 4xx). 46 tests in total.

**v0.7.1**
- The dashboard shows each alert's latest handoff under the summary ("Handoff: analyst2 -> analyst1: note").
  Before this, a handoff note was saved in the history only, and the row showed only the closing note.
- `GET /api/alerts` adds a `last_handoff` field (null when the alert was never handed off).

**v0.7**
- Playbook hook (roadmap phase 3, Response): with `PLAYBOOK_WEBHOOK` set, each new alert is POSTed as JSON
  (`{"event": "alert.created", "alert": {...}}`) to that URL, so Shuffle or another SOAR tool can run a playbook.
- Sends happen after the database commit, on a background thread, with a timeout. A duplicate alert is sent once.
  Failures are logged without the URL and never fail ingest. The API token is never sent.
- New settings `PLAYBOOK_WEBHOOK` and `PLAYBOOK_TIMEOUT`, passed through docker-compose.yml.
- Tests: `tests/test_playbook.py` (6 tests), including a real HTTP round trip to a local receiver.

**v0.6**
- Simple case queue: `POST /api/alerts/<id>/handoff` passes an open alert to another analyst, and
  `GET /api/alerts/<id>/handoffs` shows the history (from, to, time, note). Closed alerts are refused (409).
- `POST /api/alerts/<id>/verdict` takes an optional `note`, kept as the alert's resolution.
- Dashboard: "Hand off" button on open alerts, and the closing note shows under each alert.
- `GET /api/analysts` lists the analysts for the handoff.
- `/api/reset` also clears handoff history.

**v0.5.2**
- Wazuh rule 100201 suppresses Disk Cleanup DLL drops (exact `cleanmgr.exe` writer and path only).

**v0.5.1**
- `scripts/attack_sim.py` uses unique keys per run and counts only alerts from that run, so it passes on repeat runs.
  Regression test added.

**v0.5**
- `SUSPICIOUS_PROCESS` now catches the PowerShell encoded-command flags `-e`, `-ec`, `-enc` and `-EncodedCommand`
  when followed by a base64 payload. The old `-enc ` check missed the `-E` form that Atomic Red Team uses.
- Tests for the flag forms and for plain text that must not match (`tests/test_detect.py`).
- Wazuh rule 100200 tested on the lab Windows VM.

**v0.4**
- Attack simulations (`scripts/attack_sim.py`) and load test (`scripts/load_test.py`) from the test plan.
- `GET /api/exit-criteria` with the four roadmap gates, and the `FP_TARGET` setting.
- Weekly false-positive rate in `/api/metrics`.
- GitHub Actions: tests and Docker build on every push.

**v0.3**
- `SOC_API_TOKEN` gates the `/api/` endpoints. The dashboard prompts for the token.
- `/api/ingest/*` also accepts `?token=` for Wazuh's built-in integration.
- Tests for the token rules.

**v0.2**
- Wazuh alerts store the file path and process in the `detail` column.
- Wazuh alerts get rule-specific response steps and file-aware dedupe.
- Existing databases are migrated automatically (adds the `detail` column).
- `LAB_ENDPOINTS` switch for the lab-only endpoints.
- Wazuh tuning rule 100200 (untested).

## Not built yet (next)
- External case tool (TheHive or Jira Service Management). v0.6 has a simple case queue inside SOC Core instead.
- Per-user login and roles (hospital viewer/admin, Cybrot analyst)
- Fluent Bit log shipping and Kafka buffer
- Live Wazuh connection on the VM (agents, Kali attacker VM)
- Shuffle playbooks (v0.7 sends alerts to a webhook; Shuffle itself is not set up yet)
- MISP and Sigma rule conversion
- Hospital-facing portal, PDF reports, plan-based feature gating
