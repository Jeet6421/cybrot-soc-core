# Cybrot SOC Core (prototype, v1.0)

Core pipeline for the hospital/clinic SOC service: **logs in -> detection rules -> alert with severity ->
triage queue with a named owner and response step -> metrics -> exit criteria**. Test data only - never real patient data.

This version follows the internal test plan in the prototype plan document: the four roadmap gates
(Foundation, Detection, Response, Review) are checked by the app and by scripts.

## Run locally
    # PostgreSQL 16 is required. Start one with the owner role (soc) and a database (soc).
    docker run -d --name soc-pg -e POSTGRES_USER=soc -e POSTGRES_PASSWORD=soc -e POSTGRES_DB=soc -p 5432:5432 postgres:16
    pip install -r requirements.txt
    # 1) Apply the schema, row-level security and the runtime role, as the owner:
    MIGRATE_DATABASE_URL=postgresql://soc:soc@localhost:5432/soc SOC_APP_PASSWORD=local-app-pw python migrate.py
    # 2) Run the app as the runtime role soc_app (never as soc):
    DATABASE_URL=postgresql://soc_app:local-app-pw@localhost:5432/soc python app.py    # http://localhost:5000
    # 3) Create the vendor admin and a hospital (see "First-time setup" below). Then sign in and triage.
    python generate.py            # or push synthetic logs with a hospital's ingest key

## Run with Docker
    docker compose up -d --build  # http://localhost:5000
    # Settings are read from a .env file next to docker-compose.yml. Never commit .env.
    # Three services: db (PostgreSQL), migrate (runs once as the owner, then exits), soc-core (runs as soc_app).
    # .env must set POSTGRES_PASSWORD (letters and digits only, so it fits in the connection URL).
    # The database runs in its own container with a named volume (pg-data) and is not published to the host.
    # The Docker build runs in GitHub Actions on every push (see .github/workflows/tests.yml).

## Configuration
| Variable | Default | Purpose |
|---|---|---|
| `DATABASE_URL` | required | The **runtime** connection, as role `soc_app` (e.g. `postgresql://soc_app:<pw>@db:5432/soc`). The app never connects as the owner. |
| `MIGRATE_DATABASE_URL` | required for migrate and admin | The **owner** connection (`soc`). Used by `migrate.py` and `manage.py` only. Never set it on the app container. |
| `SOC_APP_PASSWORD` | required for migrate | The password of the `soc_app` role. Letters and digits only (it goes into a URL). |
| `POSTGRES_PASSWORD` | required in Docker | Password for the owner role `soc` (docker-compose only). Letters and digits only. |
| `SOC_SESSION_HOURS` | `8` | How long a sign-in lasts |
| `LAB_DATABASE_URL` | empty | Owner URL for the lab-only endpoints. Empty = `/api/demo`, `/api/autolabel`, `/api/reset` return 503. **Lab VM only.** |
| `LAB_ENDPOINTS` | `1` | `0` disables `/api/demo`, `/api/autolabel`, `/api/reset` (they return 404) |
| `ANALYSTS` | `analyst1,analyst2,analyst3` | Owner names for alerts, assigned round-robin per hospital, and the names handoffs can use |
| `FP_TARGET` | not set | The false-positive ceiling the team agrees, as a fraction (e.g. `0.10`). Until set, the Review gate is `not_measured`. |
| `PLAYBOOK_WEBHOOK` | empty (off) | v0.7: each new alert is POSTed as JSON to this URL, e.g. a Shuffle webhook. Sent after the database commit; a failed send is logged and never blocks ingest. |
| `PLAYBOOK_TIMEOUT` | `3` | Seconds to wait for the playbook webhook |
| `PLAYBOOK_SECRET` | empty (unsigned) | v0.8: if set, each playbook request carries `X-Cybrot-Signature` (HMAC-SHA256). Set it whenever `PLAYBOOK_WEBHOOK` is set. |
| `PORT` | `5000` | HTTP port when running `python app.py` |

`SOC_API_TOKEN` (the shared operator token) was removed in v1.2. Nothing reads it any more.

## Tests
Tests need a PostgreSQL server. Each test session creates its own database, migrates it as the owner, and drops it
at the end, so the tests never touch your data. Access checks connect as `soc_app`, never as the owner.

    pip install -r requirements.txt pytest
    TEST_ADMIN_URL=postgresql://soc:soc@localhost:5432/postgres pytest -q tests   # defaults shown
    # optional: TEST_APP_PASSWORD (the soc_app password the tests use; a fixed default is set)

`tests/test_rbac_rls.py` checks isolation inside PostgreSQL itself. `tests/test_identity.py` checks roles through the API.

## Test plan tools (scripts/)
These use only the Python standard library. Run them against an instance with no real data.

- **Attack simulations** (test plan step 3): posts failed-login burst, bulk record access, and suspicious process,
  checks each raises its alert, and checks that one failed login stays quiet.
  ```
  python scripts/attack_sim.py http://localhost:5000 --ingest-key "$INGEST_KEY" --session "$SOC_SESSION"
  ```
- **Load test** (test plan step 2): sends a set number of benign events and checks none are lost.
  Run it on an instance with no other traffic, because the count compares the stored total before and after.
  ```
  python scripts/load_test.py http://localhost:5000 --events 5000 --batch 500 --ingest-key "$INGEST_KEY" --session "$SOC_SESSION"
  ```
- The ingest key sends the events; the session (from `POST /api/login`) reads the results. A key cannot read, and a session cannot send events.

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
- `app.py`      Flask API + PostgreSQL (psycopg 3, runtime role `soc_app`): identity, roles, `/api/events`, `/api/ingest/wazuh`, `/api/alerts`, `/api/alerts/<id>/handoff`, `/api/metrics`, `/api/exit-criteria`
- `auth.py`    scrypt password hashing and token hashing (standard library)
- `db/schema.sql` tables, row-level security policies, the SECURITY DEFINER lookups and grants (idempotent)
- `migrate.py` applies `db/schema.sql` as the owner and sets the `soc_app` password (compose service `migrate`)
- `manage.py`  owner-only bootstrap and admin: tenants, users, log sources, ingest keys, break-glass grants
- `detect.py`   built-in rules and playbooks; Wazuh playbooks by rule id (`WAZUH_PLAYBOOK`), with a level-based fallback
- `generate.py` synthetic clinic logs with 3 planted attacks (ground truth in `attack_id`)
- `scripts/`    attack simulations and load test (see above)
- `static/`     triage dashboard (`index.html`)
- `tests/`      pytest suite: `test_rbac_rls.py` (isolation inside PostgreSQL), `test_identity.py` (roles through the API), `test_tenants.py` (keys and log sources), the rest for detection, handoff, playbook and tools; `support.py` holds shared helpers; `fixtures/` holds a real Wazuh alert (Sysmon rule 92213)
- `wazuh/`      Wazuh rules and webhook config (tuning rules 100200 and 100201 tested on the lab Windows VM)
- `.github/workflows/tests.yml`  runs the tests and the Docker build on every push and pull request

## Built-in detection rules
| Rule | Severity | Fires when |
|---|---|---|
| `FAILED_LOGIN_BURST` | high | 5 or more failed logins from one IP within 5 minutes |
| `BULK_RECORD_ACCESS` | high | One user opens 15 or more patient records within 10 minutes |
| `OFFHOURS_ACCESS` | low | Record access between 22:00 and 05:59 (intentionally noisy, for the FP-rate test) |
| `SUSPICIOUS_PROCESS` | critical | A process command line contains `mimikatz`, `certutil -urlcache`, `nc -e`, or `vssadmin delete shadows`, or passes a base64 payload with `-e`, `-ec`, `-enc` or `-EncodedCommand` |
| `HC-END-001` | critical | 50 distinct file paths are renamed, modified, or deleted on one host within 5 minutes |
| `HC-END-004` | high | A normalized endpoint event reports security-agent or EDR tampering outside an approved change |
| `HC-DLP-002` | high | A transfer marked `phi`, `patient_data`, or `sensitive` targets a destination explicitly marked unapproved |
| `HC-OPS-002` | high | A backup repository is deleted, retention changes outside an approved change, or 3 jobs fail for one host within 24 hours |
| `HC-MED-004` | high | A trusted network event marks a flow between clinical zones as a segmentation violation |
| `HC-AUD-001` | high | A normalized event reports audit-log clearing, audit service stop, forwarding disablement, or audit configuration change |

The six `HC-*` rules are a pilot implementation of the P1 items in the healthcare detection report. Their event contract, required fields, tuning risks, and validation approach are in [docs/DETECTION_RULES.md](docs/DETECTION_RULES.md). The file-activity and backup-failure thresholds are starting values only; the rules have not been validated against hospital baselines. They emit alerts and do not perform containment.

## Wazuh integration
- Wazuh alerts arrive at `POST /api/ingest/wazuh` with the hospital's ingest key (header, or `?token=` for Wazuh's integration). The key sets the hospital; `tenant` in the URL is ignored. Level 12+ is critical, 10+ high, 7+ medium.
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
- Set `LAB_ENDPOINTS=0` and leave `LAB_DATABASE_URL` empty. The lab buttons then return 404 or 503.
- Every person signs in with their own account (`POST /api/login`, or the dashboard form). There is no shared token.
- The app connects as `soc_app`: no superuser, no `BYPASSRLS`, no DDL, no `TRUNCATE`. Row-level security is `FORCE`d on every hospital table, so the database itself refuses cross-hospital reads and writes, even if the API had a bug.
- The owner password (`POSTGRES_PASSWORD`) is given only to the `migrate` service and to admins running `manage.py`. The app container never gets it.
- Ingest keys are stored as SHA-256 hashes and shown once. Revoke a key that leaks; it stops at once.
- Passwords are hashed with scrypt (N=2^14). Login returns the same error for a wrong password and an unknown user.
- Wazuh's built-in integration cannot send headers, so `/api/ingest/*` also accepts `?token=` in the URL (an ingest key only). That URL can end up in logs, so keep the webhook on a private network or behind a reverse proxy.
- Serve the app over HTTPS behind a reverse proxy.
- **Not yet built:** MFA (Phase 2 of `docs/MULTITENANT.md`), login rate limiting and account lockout. Until MFA is in, use strong passwords and keep the app on a private network.

## First-time setup (vendor admin and first hospital)
Run these from the Docker host, as the owner role. None of them is an API call, and the password is typed at a prompt.

    docker compose run --rm migrate python manage.py create-user platform vendor vendor_admin
    docker compose run --rm migrate python manage.py create-tenant city-hospital "City Hospital"
    docker compose run --rm migrate python manage.py create-user city-hospital admin hospital_admin
    docker compose run --rm migrate python manage.py create-log-source city-hospital ehr-feed --kind wazuh
    docker compose run --rm migrate python manage.py create-ingest-key city-hospital ehr-feed --label wazuh-01

The hospital admin then signs in, adds analysts with `POST /api/users`, and issues more ingest keys with
`POST /api/credentials` (one key per log source). A break-glass grant for the vendor admin is created by a database administrator:

    docker compose run --rm migrate python manage.py grant-break-glass vendor city-hospital --hours 4 --reason "INC-123"

## Accounts, roles and ingest keys (v1.2)
Each hospital is a **tenant**, with a stable id (2 to 63 lowercase letters, digits or hyphens). The vendor's own tenant is `platform`.
The tenant of every request comes from the caller's identity. A `tenant_id` in the request can narrow within that scope; any other value gets `403` before a query runs.

| Role | Can | Cannot |
|---|---|---|
| `hospital_admin` | Manage its hospital's users, log sources, ingest keys and display name; read events and triage alerts; hand off; close alerts; approve response requests; read audit | See another hospital |
| `l1` | Read its events and alerts; acknowledge; hand off; request a response approval | Close alerts (verdict); approve response requests; manage users, keys, log sources or settings |
| `l2` | Everything `l1` can, plus final verdicts (`tp`, `fp`, `unclear`) that close alerts and approve or reject response requests | Manage users, keys, log sources or settings |
| `viewer` | Read its hospital's alerts, handoffs and metrics | Change anything |
| `vendor_admin` (platform tenant) | Create and list tenants; read one hospital's events, alerts and handoffs with a time-limited **break-glass** grant (read-only, audited) | Routine access to hospital data, users, credentials |
| ingest key | `POST /api/events` and `POST /api/ingest/*` for its own hospital and log source | Any read or change |

| Step | Call | Who | Result |
|---|---|---|---|
| Sign in | `POST /api/login` `{"tenant","username","password"}` | anyone | `200` with a session `token` (shown once; send as `Authorization: Bearer`). `401` for any failure |
| Sign out | `POST /api/logout` | user | Ends the session |
| Who am I | `GET /api/me` | user | Tenant, role, username |
| Add a user | `POST /api/users` `{"username","role","password"}` | hospital_admin | `201`. Roles above, except `vendor_admin`. Password 12+ characters |
| Disable a user | `POST /api/users/<id>/disable` | hospital_admin | Their sessions stop at once |
| Add a log source | `POST /api/log-sources` `{"name","kind"}` | hospital_admin | `201` |
| Issue an ingest key | `POST /api/credentials` `{"log_source_id","label"}` | hospital_admin | `201`, with the key. **Shown once** |
| Revoke a key | `POST /api/credentials/<id>/revoke` | hospital_admin | Revoked keys get `401` |
| Create a hospital | `POST /api/tenants` `{"id","name"}` | vendor_admin | `201`. `409` if it exists |

Events and Wazuh alerts sent with a key are stored under that key's hospital and log source. Any `tenant` or `log_source_id` in the body is ignored, or refused if it names another hospital.

## Row-level security (how the database enforces it)
- `db/schema.sql` turns on `ROW LEVEL SECURITY` and `FORCE ROW LEVEL SECURITY` on `tenants`, `users`, `log_sources`, `ingest_keys`, `events`, `alerts`, `handoffs`, `sessions`, `audit_log` and `break_glass_grants`.
- `response_approvals` also has forced tenant isolation. Hospital admins can change only their own tenant's display name.
- Every transaction carries the caller's tenant, role and user id in transaction-local settings (`set_config(..., true)`). They end at `COMMIT` or `ROLLBACK`, so a pooled connection never keeps one request's identity. Unset or empty means no rows and no writes.
- Login, session and ingest-key checks run through narrow `SECURITY DEFINER` functions, because they must run before the tenant is known. They return one row each.
- `soc_app` has only `SELECT`, `INSERT`, `UPDATE`, `DELETE` on the app tables (`INSERT`/`SELECT` on `audit_log`, `SELECT` on `break_glass_grants`). It cannot `TRUNCATE`, `CREATE`, or change policies.
- `migrate.py` refuses to run unless the owner is a superuser or has `BYPASSRLS`, because the lookups read across tenants by design.

## Hospital data scope (v1.2)
- `GET /api/alerts`, `/api/metrics`, `/api/exit-criteria`, `/api/analysts` and the handoff history use the caller's hospital.
- `?tenant_id=<id>` (or `?tenant=`) may only name the caller's own hospital; anything else is `403`.
- Acting on another hospital's alert, ingest key, user or log source returns `404`, the same as an id that does not exist.
- Handoff history rows carry the hospital of their alert.

## API
| Endpoint | Who | Purpose |
|---|---|---|
| `POST /api/login`, `POST /api/logout`, `GET /api/me` | users | Sessions |
| `POST /api/events` | ingest key | Ingest events; runs the built-in rules |
| `GET /api/events` | `hospital_admin`, `l1`, `l2`; vendor with break-glass | Read tenant events; supports `limit`, `before_id`, `type` and `host` filters |
| `POST /api/ingest/wazuh` | ingest key | Ingest a Wazuh integration alert |
| `GET /api/alerts` | hospital roles; vendor with break-glass | Newest 200 alerts; filter with `status`, `owner` |
| `POST /api/alerts/<id>/ack` | `hospital_admin`, `l1`, `l2` | Acknowledge an alert |
| `POST /api/alerts/<id>/verdict` | `hospital_admin`, `l2` | Close with `tp`, `fp` or `unclear`, and an optional `note` |
| `POST /api/alerts/<id>/handoff` | `hospital_admin`, `l1`, `l2` | Pass an open alert to another analyst: `to_owner`, `note` |
| `GET /api/alerts/<id>/handoffs` | hospital roles; vendor with break-glass | Handoff history for an alert |
| `GET /api/analysts` | hospital roles | Analysts that alerts can be handed to |
| `GET /api/metrics` | hospital roles; vendor with break-glass | Counts, false-positive rate (overall and weekly), detection rate, mean time to ack |
| `GET /api/exit-criteria` | hospital roles; vendor with break-glass | The four roadmap gates, as `pass`, `fail` or `not_measured` |
| `GET/POST /api/users`, `POST /api/users/<id>/disable` | `hospital_admin` | Users of one hospital |
| `GET/POST /api/log-sources`, `POST /api/log-sources/<id>/disable` | read: hospital roles; write: `hospital_admin` | Log sources |
| `GET/POST /api/credentials`, `POST /api/credentials/<id>/revoke` | `hospital_admin` | Ingest keys |
| `GET/POST /api/tenants` | `vendor_admin` | Hospitals |
| `GET/PUT /api/settings` | `hospital_admin` | Read or update its hospital display name |
| `GET/POST /api/alerts/<id>/response-approvals` | `hospital_admin`, `l1`, `l2` | List or request an allowlisted response action approval |
| `POST /api/response-approvals/<id>/decision` | `hospital_admin`, `l2` | Approve or reject another user's request; no action is executed |
| `POST /api/demo`, `/api/autolabel`, `/api/reset` | `vendor_admin`, lab only | Synthetic data; need `LAB_DATABASE_URL` |

## Changes
**v1.2 (tenant-scoped identity, RBAC and PostgreSQL row-level security; PR 1 of the multi-tenant work)**
- The shared `SOC_API_TOKEN` is gone. Every call is a user session or an ingest key.
- Users, roles (`hospital_admin`, `l1`, `l2`, `viewer`, `vendor_admin`), sessions and scrypt password hashes.
- The app runs as the `soc_app` role. Migrations and bootstrap run as the owner: `migrate.py` (compose service `migrate`) and `manage.py`.
- Row-level security with `FORCE` on every hospital table, transaction-local identity, and fail-closed behaviour when the identity is unset.
- Break-glass grants for the vendor admin: time-limited, read-only, audited.
- Ingest keys are bound to a log source. Keys created before v1.2 have no log source and stop working; issue new ones.
- Scripts take `--ingest-key` and `--session`. The dashboard shows a sign-in form.
- Tests: `tests/test_rbac_rls.py` (isolation as `soc_app`, inside PostgreSQL), `tests/test_identity.py` (roles and break-glass through the API), `tests/test_tenants.py` (keys, log sources, tenants).

**Deviations from the PR 1 spec, and what is not there yet**
- The column is still called `tenant`, and the API also accepts `tenant_id`. `credentials` is the existing `ingest_keys` table, now bound to a log source.
- `docs/MULTITENANT.md` uses other role names (Platform admin, Hospital admin, SOC analyst, Viewer). The roles above are the ones in the code; the design doc needs updating.
- Response approvals record an allowlisted action request and an independent `hospital_admin` or `l2` decision. They do not execute isolation, account-disabling or IP-blocking actions.
- The database lets `l1` update alerts (acknowledge, hand off). Only the API stops `l1` from giving a verdict. Column-level rules would move this into the database.
- Alert owners are still names from `ANALYSTS`, not user accounts.
- Lab endpoints use the owner role through `LAB_DATABASE_URL`, so the lab VM holds the owner URL. Never set it with real data.
- MFA, login rate limits and lockout are Phase 2.

**v1.1 (tenants and ingest keys, Phase 1 of `docs/MULTITENANT.md`)**
- New tables `tenants` (with a `default` lab tenant) and `ingest_keys` (hash only). Handoff history records the hospital.
- Ingest keys: `/api/events` and `/api/ingest/wazuh` accept a key. The tenant comes from the key. A mismatched body tenant gets `403`.
- Keys cannot call any other endpoint. Revoked and unknown keys get `401`.
- Metrics and exit gates take `?tenant=`.
- `/api/demo` stores events directly instead of calling the API through the test client.
- Tests: `tests/test_tenants.py`: cross-hospital writes and reads refused, Wazuh tenant from the key, revocation, hashed keys, scoped metrics.

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
- MFA, login rate limits and account lockout (Phase 2 of `docs/MULTITENANT.md`)
- Fluent Bit log shipping and Kafka buffer
- Live Wazuh connection on the VM (agents, Kali attacker VM)
- Shuffle playbooks (v0.7 sends alerts to a webhook; Shuffle itself is not set up yet)
- MISP and Sigma rule conversion
- Hospital-facing portal, PDF reports, plan-based feature gating

