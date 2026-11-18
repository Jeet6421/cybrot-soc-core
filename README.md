# Cybrot SOC Core (prototype, v0.2)

Core pipeline for the hospital/clinic SOC service: **logs in -> detection rules -> alert with severity ->
triage queue with a named owner and response step -> metrics** (alert volume, false-positive rate,
detection rate on planted attacks, mean time to acknowledge). Test data only - never real patient data.

## Run
    pip install -r requirements.txt
    python app.py                 # http://localhost:5000
    # click "Load demo data", then "Auto-label (lab)", or triage alerts by hand (Ack / TP / FP)
    python generate.py            # or push synthetic logs from the CLI
    # Docker: docker compose up --build

## Test
    pip install pytest && pytest -q tests

## Layout
- `app.py`      Flask API + SQLite: `/api/events`, `/api/ingest/wazuh`, `/api/alerts`, `/api/metrics`
- `detect.py`   built-in rules + playbooks; Wazuh playbooks by rule id (`WAZUH_PLAYBOOK`), level fallback
- `generate.py` synthetic clinic logs with 3 planted attacks (ground truth in `attack_id`)
- `static/`     triage dashboard
- `tests/`      pytest suite; `fixtures/` holds a real Wazuh alert (Sysmon rule 92213)
- `wazuh/`      sample Wazuh rules + webhook config (untested in this build)

## Changes in v0.2
- Wazuh alerts store the key facts (file path, process) in a `detail` column, shown under the summary.
- Wazuh alerts get rule-specific response steps (rule 92213 has one) instead of the generic step.
- Dedupe for Wazuh alerts includes the file/process, so a different file on the same host alerts again.
- Existing databases are migrated automatically (adds the `detail` column).
- `LAB_ENDPOINTS=0` disables `/api/demo`, `/api/autolabel` and `/api/reset`. Keep it at 1 for the lab only.
- Wazuh tuning rule 100200 (wazuh/local_rules.xml) silences the benign PowerShell policy test file. Untested.

## Security (before any real data)
- Set `LAB_ENDPOINTS=0`. The dashboard still has the lab buttons; they will return 404.
- The API has no login yet. Put it behind a reverse proxy with authentication, or wait for the login/roles build.

## Not built yet (next)
Kafka buffer, Fluent Bit shipping, Shuffle playbooks, TheHive/Jira, MISP, Sigma conversion,
auth/roles, plan-based feature gating, hospital-facing portal, PDF reports.
