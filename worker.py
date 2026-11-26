"""Durable response-job worker (response_jobs).

Approved responses are queued in PostgreSQL by the approval decision. This process claims due jobs,
runs the executor registered for each action type, and records the outcome. The queue is the record:
a job survives a restart, a crashed worker's job is reclaimed when its lease expires, and a job that keeps
failing is dead-lettered instead of retried forever.

Executors must be idempotent: the same job can run again after a crash, and each job carries its
idempotency_key for the downstream system to use. An executor never changes alerts, owners or status.
"""
import os
import random
import socket
import time
import uuid

import psycopg
from psycopg.types.json import Jsonb

import app as soc

LEASE_SECONDS = int(os.environ.get("WORKER_LEASE_SECONDS", "120"))
BATCH = int(os.environ.get("WORKER_BATCH", "10"))
POLL_SECONDS = float(os.environ.get("WORKER_POLL_SECONDS", "5"))
BACKOFF_BASE = 5      # seconds before the first retry
BACKOFF_CAP = 900     # longest wait between attempts


class Retryable(Exception):
    """A transient failure (network, timeout, busy device). The job is retried after a backoff."""


class Permanent(Exception):
    """A failure that retrying cannot fix (bad target, action refused). The job is dead-lettered at once."""


# action_type -> callable(job_row) -> dict. PR 10 registers none: approved jobs wait (deferred) until an
# executor exists for their action. PR 11 adds the Ansible-backed executors here.
EXECUTORS = {}


def backoff_seconds(attempt, rng=random):
    """Exponential backoff with equal jitter: half the ceiling is fixed, half is random, so retries from many
    jobs spread out instead of arriving together."""
    ceiling = min(BACKOFF_CAP, BACKOFF_BASE * (2 ** max(0, attempt - 1)))
    return ceiling / 2 + rng.uniform(0, ceiling / 2)


def _finish(conn, job_id, worker_id, outcome, result=None, error=None, retry_seconds=0):
    row = conn.execute(
        "SELECT finish_response_job(%s, %s, %s, %s, %s, %s) AS outcome",
        (job_id, worker_id, outcome, Jsonb(result or {}), error, int(retry_seconds))).fetchone()
    conn.commit()
    if row["outcome"] == "lost_lease":
        print(f"job {job_id}: lease was taken over by another worker; this result was not recorded", flush=True)
    return row["outcome"]


def run_once(conn, worker_id, executors=None, limit=None, lease=None, rng=None):
    """Claim due jobs and run them. Returns how many jobs were claimed (0 means nothing was due)."""
    executors = EXECUTORS if executors is None else executors
    rng = rng or random
    rows = conn.execute("SELECT * FROM claim_response_jobs(%s, %s, %s)",
                        (worker_id, limit or BATCH, lease or LEASE_SECONDS)).fetchall()
    conn.commit()  # the lease is recorded before any work starts
    for job in rows:
        executor = executors.get(job["action_type"])
        if executor is None:
            # No executor yet for this action: leave the job queued for a later worker, without counting the attempt.
            _finish(conn, job["job_id"], worker_id, "defer", retry_seconds=POLL_SECONDS * 12)
            continue
        try:
            result = executor(job)
        except Permanent as e:
            _finish(conn, job["job_id"], worker_id, "dead", error=type(e).__name__ + ": " + str(e))
        except Retryable as e:
            _finish(conn, job["job_id"], worker_id, "retry", error=type(e).__name__ + ": " + str(e),
                    retry_seconds=backoff_seconds(job["attempts"], rng))
        except Exception as e:  # an unexpected fault is treated as transient; the error text is not stored
            _finish(conn, job["job_id"], worker_id, "retry", error=type(e).__name__,
                    retry_seconds=backoff_seconds(job["attempts"], rng))
        else:
            _finish(conn, job["job_id"], worker_id, "succeeded", result=result)
    return len(rows)


def main():
    worker_id = f"{socket.gethostname()}-{os.getpid()}-{uuid.uuid4().hex[:6]}"
    print(f"worker {worker_id} started", flush=True)
    while True:
        try:
            with soc.connect() as conn:
                claimed = run_once(conn, worker_id)
        except psycopg.OperationalError as e:
            print(f"worker database error: {type(e).__name__}; retrying", flush=True)
            time.sleep(POLL_SECONDS)
            continue
        if claimed == 0:
            time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    main()
