# Cybrot SOC Core (prototype, v0.4)

Core pipeline for the hospital/clinic SOC service: **logs in -> detection rules -> alert with severity ->
triage queue with a named owner and response step -> metrics -> exit criteria**. Test data only - never real patient data.

This version follows the internal test plan in the prototype plan document: the four roadmap gates
(Foundation, Detection, Response, Review) are checked by the app and by scripts.

## Run locally
    pip install -r requirements.txt
    python app.py                 # http://localhost:5000
    # Click "Load demo data", then "Auto-label (lab)", or triage alerts by hand (Ack / TP / FP / ?)
    python generate.py            # or push synthetic logs from the command line

## Run with Docker
    docker compose up -d --build  # http://localhost:5000
    # Settings are read from a .env file next to docker-compose.yml. Never commit .env.
    # The Docker build runs in GitHub Actions on every push (see .github/workflows/tests.yml).

## Configuration
| Variable | Default | Purpose |
|---|---|---|
| `SOC_DB` | `soc.db` (`/data/soc.db` in Docker) | SQLite database path |
| `ANALYSTS` | `analyst1,analyst2,analyst3` | Owners for alerts, assigned round-robin |
| `LAB_ENDPOINTS` | `1` | `0` disables `/api/demo`, `/api/autolabel`, `/api/reset` (they return 404) |
| `SOC_API_TOKEN` | empty (no token) | If set, every `/api/` call needs `Authorization: Bearer <token>` |
| `FP_TARGET` | not set | The false-positive ceiling the team agrees, as a fraction (e.g. `0.10`). Until set, the Review gate is `not_measured`. |
| `PORT` | `5000` | HTTP port when running `python app.py` |

## Tests
    pip install pytest
    pytest -q tests              # 18 tests

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
| Response: handoff tested | Every alert has an owner and a response step |
| Review: false positives within target | The false-positive rate is at or below `FP_TARGET` |

The dashboard shows these at the top. `GET /api/metrics` also returns `false_positive_rate_by_week`, so the weekly
trend (test plan step 4) can be tracked.

## Layout
- `app.py`      Flask API + SQLite: `/api/events`, `/api/ingest/wazuh`, `/api/alerts`, `/api/metrics`, `/api/exit-criteria`
- `detect.py`   built-in rules and playbooks; Wazuh playbooks by rule id (`WAZUH_PLAYBOOK`), with a level-based fallback
- `generate.py` synthetic clinic logs with 3 planted attacks (ground truth in `attack_id`)
- `scripts/`    attack simulations and load test (see above)
- `static/`     triage dashboard (`index.html`)
- `tests/`      pytest suite; `fixtures/` holds a real Wazuh alert (Sysmon rule 92213)
- `wazuh/`      sample Wazuh rules and webhook config (not yet tested on a Wazuh manager)
- `.github/workflows/tests.yml`  runs the tests and the Docker build on every push and pull request

## Built-in detection rules
| Rule | Severity | Fires when |
|---|---|---|
| `FAILED_LOGIN_BURST` | high | 5 or more failed logins from one IP within 5 minutes |
| `BULK_RECORD_ACCESS` | high | One user opens 15 or more patient records within 10 minutes |
| `OFFHOURS_ACCESS` | low | Record access between 22:00 and 05:59 (intentionally noisy, for the FP-rate test) |
| `SUSPICIOUS_PROCESS` | critical | A process command line contains `mimikatz`, `-enc `, `certutil -urlcache`, `nc -e`, or `vssadmin delete shadows` |

## Wazuh integration
- Wazuh alerts arrive at `POST /api/ingest/wazuh?tenant=<hospital>`. Level 12+ is critical, 10+ high, 7+ medium.
- Each alert keeps its key facts (file path, process) in the `detail` column, shown under the summary.
- Rule 92213 (Sysmon file drop) has its own response step. Other Wazuh rules use a level-based step.
- Repeats of the same rule, host, file and process within 10 minutes are suppressed. A different file alerts again.
- Tuning rule 100200 in `wazuh/local_rules.xml` silences the benign PowerShell execution-policy test file.
  **Untested:** check it with `wazuh-logtest` on `tests/fixtures/wazuh_92213_psscriptpolicy.json` before deploying.

## Security (before any real data)
- Set `LAB_ENDPOINTS=0`. The dashboard still shows the lab buttons, but they will return 404.
- Set `SOC_API_TOKEN` to a long random value. The dashboard asks for the token once per browser tab.
- Wazuh's built-in integration cannot send headers, so `/api/ingest/*` also accepts `?token=` in the URL.
  That URL can end up in logs, so keep the webhook on a private network or behind a reverse proxy.
- Serve the app over HTTPS behind a reverse proxy.
- This is a shared secret, not user login. There are no per-user accounts or roles yet.

## Changes
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
- Case tool (TheHive or Jira Service Management). The plan leaves this choice open.
- Per-user login and roles (hospital viewer/admin, Cybrot analyst)
- Fluent Bit log shipping and Kafka buffer
- Live Wazuh connection on the VM (agents, Kali attacker VM)
- Shuffle playbooks
- MISP and Sigma rule conversion
- Hospital-facing portal, PDF reports, plan-based feature gating
