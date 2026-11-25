# Drill: handoff and time to acknowledge (test plan step 5)

**Date:** 2026-11-25
**Environment:** lab VM `SOC-UBUNTU`, Docker Compose, app v1.0 (PostgreSQL 16), `main` at `3f3a10d`
**Operator:** lab operator, on the VM, through the API with the shared token
**Scope:** check that an alert can be acknowledged and handed off, that the handoff keeps its note in history, and that the time to acknowledge is recorded.

This is a lab drill. It is not a measurement of a real on-call team. No patient data is involved.

## What was run

All calls used `Authorization: Bearer $TOKEN` from the VM's `.env`. The token is not recorded here.

| Step | Call | Result |
|---|---|---|
| Queue check | `GET /api/alerts` | 4 alerts, owners set by round-robin (alert 2 was still `new` before the acknowledge below; the listing after it shows 3 `new`, 1 `ack`) |
| Acknowledge | `POST /api/alerts/2/ack` | `{"ok":true}`; alert 2 is now `ack` |
| Handoff, valid | `POST /api/alerts/1/handoff` with `to_owner=analyst2`, note "checking the host" | `{"ok":true,"from_owner":"analyst1","to_owner":"analyst2"}` |
| Handoff, same owner | `POST /api/alerts/2/handoff` with `to_owner=analyst2` | `400`, "alert is already owned by analyst2" (refused as designed) |
| History | `GET /api/alerts/1/handoffs` | One entry: `analyst1` to `analyst2`, note "checking the host", with a timestamp |
| Metrics | `GET /api/metrics` | `mean_time_to_ack_s: 230.0`, `unacknowledged: 3` |

Queue after the drill:

| id | owner | status | rule |
|---|---|---|---|
| 1 | analyst2 | new | FAILED_LOGIN_BURST |
| 2 | analyst2 | ack | BULK_RECORD_ACCESS |
| 3 | analyst3 | new | SUSPICIOUS_PROCESS |
| 4 | analyst1 | new | WAZUH:533 |

## Findings

- Acknowledge, handoff, handoff history and the same-owner refusal all work on the PostgreSQL build.
- The handoff note is kept in history, and the alert list shows the latest handoff.
- Alert 4 is a live Wazuh alert (rule 533, listened ports changed), not a planted simulation alert. It came in through the Wazuh path and was routed to an analyst.
- Alert 4 uses the level-based fallback response step, because rule 533 has no rule-specific step.

## Limits of this drill

- **Sample size is one.** The 230 s mean is the time to acknowledge for one alert, measured from its creation. It does not show a typical time to acknowledge.
- **No target yet.** The team has not agreed a time-to-acknowledge target, so this run cannot pass or fail step 5.
- **Single operator.** The same person opened, acknowledged and handed off the alerts. Nobody else worked the queue.

## Follow-up

1. Agree the time-to-acknowledge target with the SOC team, and record it in the test plan.
2. Repeat the drill with at least 10 alerts and at least two analysts, so the mean is meaningful.
3. Triage alert 4 and record the verdict with a note. Decide whether rule 533 needs its own response step.
4. Decide who owns triage when a handoff is made, so the queue does not depend on one person.
