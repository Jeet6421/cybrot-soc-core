"""Durable response jobs (response_jobs): approval queues work, the worker survives crashes, and duplicates are refused.

The worker runs in-process here with a fake executor. Real executors arrive with PR 11.
"""
import pathlib
import random
import re
import uuid

import psycopg

import app as soc
import worker
from support import Api, CITY, ORTHO, failed_logins

ACTIONS = ("isolate_host", "disable_account", "block_ip")
REPO = pathlib.Path(__file__).resolve().parents[1]


def owner_rows(world, sql, params=()):
    with psycopg.connect(world.owner_url) as owner:
        return owner.execute(sql, params).fetchall()


def actor(world, tenant, username):
    return owner_rows(world, "SELECT id FROM users WHERE tenant=%s AND username=%s", (tenant, username))[0][0]


def approved_job(world):
    """Seed an alert, request a response as analyst-l1, approve it as analyst-l2. Returns (approval id, job id)."""
    Api(world, CITY, "l1").post("/api/events", json=failed_logins(CITY))
    alert_id = next(a["id"] for a in Api(world, CITY, "l1").get("/api/alerts").get_json()
                    if a.get("status") != "closed")
    request = Api(world, CITY, "l1").post(f"/api/alerts/{alert_id}/response-approvals", json={
        "action": "isolate_host", "target": f"ws-{uuid.uuid4().hex[:8]}", "reason": "queue test"})
    assert request.status_code == 201
    approval_id = request.get_json()["id"]
    decided = Api(world, CITY, "l2").post(f"/api/response-approvals/{approval_id}/decision",
                                          json={"decision": "approved"})
    assert decided.status_code == 200
    body = decided.get_json()
    assert body["execution"] == "queued" and body["job_id"]
    return approval_id, body["job_id"]


def job_state(world, job_id):
    return owner_rows(world, "SELECT status, attempts, locked_by, next_run_at > now(), "
                             "jsonb_array_length(errors), result FROM response_jobs WHERE job_id=%s", (job_id,))[0]


def succeed_all(job):
    return {"executed": job["job_id"]}


def drain(world, job_id, executors=None, rounds=30, worker_id="worker-drain"):
    """Run the worker until the job is finished (or no progress is possible). Other queued jobs may run too."""
    executors = executors or {action: succeed_all for action in ACTIONS}
    with soc.connect() as conn:
        for _ in range(rounds):
            worker.run_once(conn, worker_id, executors=executors, limit=100)
            if job_state(world, job_id)[0] in ("succeeded", "dead"):
                break
    return job_state(world, job_id)


def test_approval_queues_exactly_one_job(world):
    approval_id, job_id = approved_job(world)
    row = owner_rows(world, "SELECT idempotency_key, status, action_type, requested_by, approved_by "
                            "FROM response_jobs WHERE job_id=%s", (job_id,))[0]
    assert row == (f"approval:{approval_id}", "queued", "isolate_host",
                   actor(world, CITY, "analyst-l1"), actor(world, CITY, "analyst-l2"))
    # A second decision on the same approval is refused, so no second job appears.
    again = Api(world, CITY, "l2").post(f"/api/response-approvals/{approval_id}/decision",
                                        json={"decision": "approved"})
    assert again.status_code == 409
    assert owner_rows(world, "SELECT count(*) FROM response_jobs WHERE idempotency_key=%s",
                      (f"approval:{approval_id}",))[0][0] == 1


def test_duplicate_idempotency_key_does_not_create_a_second_job(world):
    _, job_id = approved_job(world)
    key, tenant_id = owner_rows(world, "SELECT idempotency_key, tenant_id FROM response_jobs WHERE job_id=%s",
                                (job_id,))[0]
    with soc.connect() as conn:
        soc._bind(conn, CITY, "l2", actor(world, CITY, "analyst-l2"))  # the approver's own session
        row = conn.execute(
            "INSERT INTO response_jobs(tenant_id, alert_id, action_type, target_host, idempotency_key, "
            "requested_by, approved_by, approved_at) SELECT tenant_id, alert_id, action_type, target_host, "
            "idempotency_key, requested_by, approved_by, approved_at FROM response_jobs WHERE job_id=%s "
            "ON CONFLICT (tenant_id, idempotency_key) DO NOTHING RETURNING job_id", (job_id,)).fetchone()
        assert row is None  # the database refused the duplicate and created nothing
    assert owner_rows(world, "SELECT count(*) FROM response_jobs WHERE tenant_id=%s AND idempotency_key=%s",
                      (tenant_id, key))[0][0] == 1


def test_queued_job_survives_a_worker_restart(world):
    _, job_id = approved_job(world)
    # No worker runs. The connection is closed, as it would be when a worker process stops.
    assert job_state(world, job_id)[0] == "queued"
    # A new worker process starts later and completes it.
    assert drain(world, job_id)[0] == "succeeded"


def test_jobs_wait_without_an_executor_and_do_not_use_up_attempts(world):
    _, job_id = approved_job(world)
    with soc.connect() as conn:
        worker.run_once(conn, "worker-no-executor", executors={}, limit=100)
    status, attempts, locked_by, _, _, _ = job_state(world, job_id)
    assert (status, attempts, locked_by) == ("queued", 0, None)


def test_expired_lease_is_reclaimed_and_completed(world):
    _, job_id = approved_job(world)
    with soc.connect() as crashed:  # worker A claims the job, then dies without finishing it
        crashed.execute("SELECT * FROM claim_response_jobs('worker-a', 100, 60)").fetchall()
        crashed.commit()
    assert job_state(world, job_id)[:3] == ("running", 1, "worker-a")
    owner_rows_exec(world, "UPDATE response_jobs SET lease_expires_at = now() - interval '1 second' "
                           "WHERE job_id=%s", (job_id,))
    status, attempts, locked_by, _, _, _ = drain(world, job_id, worker_id="worker-b")
    assert (status, attempts, locked_by) == ("succeeded", 2, None)


def owner_rows_exec(world, sql, params=()):
    with psycopg.connect(world.owner_url) as owner:
        owner.execute(sql, params)


def test_a_worker_that_lost_its_lease_cannot_finish_the_job(world):
    _, job_id = approved_job(world)
    with soc.connect() as conn:
        conn.execute("SELECT * FROM claim_response_jobs('worker-a', 100, 60)").fetchall()
        conn.commit()
    owner_rows_exec(world, "UPDATE response_jobs SET lease_expires_at = now() - interval '1 second' "
                           "WHERE job_id=%s", (job_id,))
    with soc.connect() as conn:
        conn.execute("SELECT * FROM claim_response_jobs('worker-b', 100, 60)").fetchall()
        conn.commit()
        outcome = conn.execute("SELECT finish_response_job(%s, 'worker-a', 'succeeded', '{}'::jsonb, NULL, 0) "
                               "AS o", (job_id,)).fetchone()["o"]
        conn.commit()
    assert outcome == "lost_lease"
    assert job_state(world, job_id)[:3] == ("running", 2, "worker-b")


def test_failures_back_off_and_then_dead_letter(world):
    _, job_id = approved_job(world)
    owner_rows_exec(world, "UPDATE response_jobs SET max_attempts = 2 WHERE job_id=%s", (job_id,))

    def flaky(job):
        if job["job_id"] == job_id:
            raise worker.Retryable("device busy")
        return {}

    executors = {action: flaky for action in ACTIONS}
    with soc.connect() as conn:
        worker.run_once(conn, "worker-retry", executors=executors, limit=100)
    status, attempts, _, future, errors, _ = job_state(world, job_id)
    assert (status, attempts, future, errors) == ("queued", 1, True, 1)  # waits before the next attempt
    owner_rows_exec(world, "UPDATE response_jobs SET next_run_at = now() - interval '1 second' WHERE job_id=%s",
                    (job_id,))
    with soc.connect() as conn:
        worker.run_once(conn, "worker-retry", executors=executors, limit=100)
    status, attempts, _, _, errors, _ = job_state(world, job_id)
    assert (status, attempts, errors) == ("dead", 2, 2)


def test_a_permanent_error_dead_letters_at_once(world):
    _, job_id = approved_job(world)

    def refused(job):
        if job["job_id"] == job_id:
            raise worker.Permanent("target no longer exists")
        return {}

    status, attempts, _, _, errors, _ = drain(world, job_id, executors={a: refused for a in ACTIONS})
    assert (status, attempts, errors) == ("dead", 1, 1)


def test_backoff_grows_and_has_jitter():
    rng = random.Random(7)
    samples = [worker.backoff_seconds(1, rng) for _ in range(20)]
    assert all(worker.BACKOFF_BASE / 2 <= s <= worker.BACKOFF_BASE for s in samples)
    assert len(set(samples)) > 1  # jitter: retries do not all land together
    late = worker.backoff_seconds(20, rng)
    assert worker.BACKOFF_CAP / 2 <= late <= worker.BACKOFF_CAP


def test_completing_a_job_does_not_change_the_alert(world):
    approval_id, job_id = approved_job(world)
    alert_id = owner_rows(world, "SELECT alert_id FROM response_jobs WHERE job_id=%s", (job_id,))[0][0]
    before = owner_rows(world, "SELECT owner, status, verdict FROM alerts WHERE id=%s", (alert_id,))[0]
    assert drain(world, job_id)[0] == "succeeded"
    after = owner_rows(world, "SELECT owner, status, verdict FROM alerts WHERE id=%s", (alert_id,))[0]
    assert before == after


def test_jobs_are_invisible_to_another_hospital(world):
    _, job_id = approved_job(world)
    with soc.connect() as conn:
        soc._bind(conn, ORTHO, "hospital_admin", None)
        count = conn.execute("SELECT count(*) FROM response_jobs WHERE job_id=%s", (job_id,)).fetchone()["count"]
    assert count == 0


def test_no_shuffle_or_playbook_webhook_references_remain():
    banned = re.compile("shu" + "ffle|PLAYBOOK_(WEBHOOK|SECRET|TIMEOUT)", re.IGNORECASE)
    skip_dirs = {".git", "__pycache__", ".pytest_cache", ".ruff_cache"}
    this_file = pathlib.Path(__file__).resolve()
    hits = []
    for path in REPO.rglob("*"):
        if not path.is_file() or path.resolve() == this_file or skip_dirs & set(path.parts):
            continue
        if path.suffix in (".png", ".jpg", ".pyc"):
            continue
        for number, line in enumerate(path.read_text(encoding="utf-8", errors="ignore").splitlines(), 1):
            if banned.search(line):
                hits.append(f"{path.relative_to(REPO)}:{number}")
    assert hits == []
