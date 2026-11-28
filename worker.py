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
MAINTENANCE_SECONDS = float(os.environ.get("STORAGE_MAINTENANCE_SECONDS", "3600"))
BACKOFF_BASE = 5      # seconds before the first retry
BACKOFF_CAP = 900     # longest wait between attempts


class Retryable(Exception):
    """A transient failure (network, timeout, busy device). The job is retried after a backoff."""


class Permanent(Exception):
    """A failure that retrying cannot fix (bad target, action refused). The job is dead-lettered at once."""


# action_type -> callable(job_row) -> dict. main() fills this with the Ansible executors (ansible_runner.py).
# With no executor for an action, its jobs wait (deferred) and no attempt is used.
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


def maintain_storage(conn):
    """Create the upcoming monthly partitions, then drop partitions that have passed the retention window. Both are
    SECURITY DEFINER functions, so the runtime role can call them and nothing else. Returns what changed."""
    created = conn.execute("SELECT ensure_time_partitions()").fetchone()[0]
    # Partitions are shared, so keep them as long as the longest-retaining hospital needs (tenants.retention_days).
    dropped = conn.execute("SELECT partition_name, rows_dropped "
                           "FROM drop_expired_partitions(effective_retention_days(%s))",
                           (soc.RETENTION_DAYS,)).fetchall()
    conn.commit()
    return created, [(row[0], row[1]) for row in dropped]


def main():
    # Register the Ansible executors. Imported here, after the exception classes exist, to avoid a cycle.
    import ansible_runner
    EXECUTORS.update(ansible_runner.executors())
    worker_id = f"{socket.gethostname()}-{os.getpid()}-{uuid.uuid4().hex[:6]}"
    print(f"worker {worker_id} started", flush=True)
    next_maintenance = 0.0
    while True:
        if time.monotonic() >= next_maintenance:
            try:
                with soc.connect() as conn:
                    created, dropped = maintain_storage(conn)
                print(f"storage maintenance: {created} partitions created; dropped {dropped}", flush=True)
                next_maintenance = time.monotonic() + MAINTENANCE_SECONDS
            except Exception as e:  # maintenance must never stop the worker; retry in five minutes
                print(f"storage maintenance failed: {type(e).__name__}; retrying in 300 seconds", flush=True)
                next_maintenance = time.monotonic() + 300
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
    # Run through the importable module, so the exception classes are the same objects ansible_runner imports.
    import worker
    worker.main()
