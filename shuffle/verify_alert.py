"""Checks for SOC Core playbook requests. Standard library only, so it can be pasted into a Shuffle Python step.

Use:
    ok = verify(secret, headers["X-Cybrot-Timestamp"], raw_body, headers["X-Cybrot-Signature"])
    if ok and dedupe.first_time(headers["X-Cybrot-Event-Id"]):
        ...run the playbook...

raw_body must be the exact bytes SOC Core sent. Parsing and re-serializing the JSON changes the bytes.
"""
import hashlib
import hmac
import time

MAX_AGE_SECONDS = 300  # requests older (or further in the future) than this are rejected


def expected_signature(secret, timestamp, raw_body):
    mac = hmac.new(secret.encode(), f"{timestamp}.".encode() + raw_body, hashlib.sha256)
    return "sha256=" + mac.hexdigest()


def verify(secret, timestamp, raw_body, signature, now=None, max_age=MAX_AGE_SECONDS):
    """True only when the timestamp is fresh and the HMAC matches the raw body exactly."""
    if not secret or not timestamp or not signature:
        return False
    try:
        ts = int(timestamp)
    except ValueError:
        return False
    now = time.time() if now is None else now
    if abs(now - ts) > max_age:
        return False
    return hmac.compare_digest(expected_signature(secret, timestamp, raw_body), signature)


class DedupeLog:
    """Remembers event ids for `ttl` seconds, so a retried request is handled once.

    In memory only: it resets when the Shuffle worker restarts. For production, keep the ids in
    Shuffle's datastore, or check the alert id in SOC Core before acting."""

    def __init__(self, ttl=24 * 3600):
        self.ttl = ttl
        self._seen = {}

    def first_time(self, event_id, now=None):
        now = time.time() if now is None else now
        self._seen = {k: t for k, t in self._seen.items() if now - t < self.ttl}
        if event_id in self._seen:
            return False
        self._seen[event_id] = now
        return True
