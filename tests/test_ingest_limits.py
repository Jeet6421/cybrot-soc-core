"""Per (tenant, log source) quotas, batch and body limits, and the retention window on ingest (PR 13).

Each test uses its own log source, so the per-minute windows of other tests cannot count against it.
"""
import uuid
from datetime import datetime, timedelta, timezone

import psycopg

import app as soc
import manage
from support import CITY, ORTHO


def _source(world, tenant):
    """A fresh log source and ingest key for one hospital. Returns (auth headers, log source id)."""
    name = f"limit-{uuid.uuid4().hex[:8]}"
    with psycopg.connect(world.owner_url) as owner:
        manage.create_log_source(owner, tenant, name, "test")
        key = manage.create_ingest_key(owner, tenant, name, "limit test")
        sid = owner.execute("SELECT id FROM log_sources WHERE tenant = %s AND name = %s", (tenant, name)).fetchone()[0]
        owner.commit()
    return {"Authorization": f"Bearer {key}"}, sid


def _event(i, minutes_ago=5):
    when = datetime.now(timezone.utc) - timedelta(minutes=minutes_ago, seconds=i)
    return {"ts": when.isoformat(), "source": "auth", "type": "auth_fail", "user": f"u{i}",
            "ip": "10.1.1.1", "detail": f"attempt {i}"}


def _stored(world, tenant, sid):
    with psycopg.connect(world.owner_url) as owner:
        return owner.execute("SELECT count(*) FROM events WHERE tenant = %s AND log_source_id = %s",
                             (tenant, sid)).fetchone()[0]


def test_tenant_over_quota_gets_429_and_another_tenant_still_ingests(world, monkeypatch):
    monkeypatch.setenv("INGEST_EVENTS_PER_MINUTE", "3")
    noisy, noisy_sid = _source(world, CITY)
    quiet, quiet_sid = _source(world, ORTHO)
    c = world.client

    assert c.post("/api/events", json=[_event(1), _event(2)], headers=noisy).status_code == 200
    over = c.post("/api/events", json=[_event(3), _event(4)], headers=noisy)  # 2 + 2 is over 3
    assert over.status_code == 429
    assert int(over.headers["Retry-After"]) >= 1
    assert over.get_json()["retry_after"] == int(over.headers["Retry-After"])
    assert _stored(world, CITY, noisy_sid) == 2                     # the refused batch wrote nothing

    assert c.post("/api/events", json=[_event(5)], headers=quiet).status_code == 200
    assert _stored(world, ORTHO, quiet_sid) == 1


def test_a_single_batch_over_the_quota_is_refused_without_writing(world, monkeypatch):
    monkeypatch.setenv("INGEST_EVENTS_PER_MINUTE", "3")
    headers, sid = _source(world, CITY)
    r = world.client.post("/api/events", json=[_event(i) for i in range(4)], headers=headers)
    assert r.status_code == 429
    assert _stored(world, CITY, sid) == 0


def test_batch_size_is_capped(world, monkeypatch):
    monkeypatch.setenv("INGEST_MAX_BATCH", "2")
    headers, sid = _source(world, CITY)
    r = world.client.post("/api/events", json=[_event(i) for i in range(3)], headers=headers)
    assert r.status_code == 413 and "at most 2" in r.get_json()["error"]
    assert _stored(world, CITY, sid) == 0


def test_request_body_size_is_capped_with_a_json_error(world, monkeypatch):
    monkeypatch.setitem(soc.app.config, "MAX_CONTENT_LENGTH", 300)
    headers, sid = _source(world, CITY)
    big = [dict(_event(i), detail="x" * 200) for i in range(3)]
    r = world.client.post("/api/events", json=big, headers=headers)
    assert r.status_code == 413 and r.is_json
    assert _stored(world, CITY, sid) == 0


def test_events_outside_the_retention_window_are_refused(world):
    headers, sid = _source(world, CITY)
    old = dict(_event(1), ts=(datetime.now(timezone.utc) - timedelta(days=400)).isoformat())
    r = world.client.post("/api/events", json=[old], headers=headers)
    assert r.status_code == 400 and "retention window" in r.get_json()["error"]

    future = dict(_event(2), ts=(datetime.now(timezone.utc) + timedelta(days=2)).isoformat())
    assert world.client.post("/api/events", json=[future], headers=headers).status_code == 400
    assert _stored(world, CITY, sid) == 0


def test_a_timestamp_without_a_zone_is_read_as_utc(world):
    headers, sid = _source(world, CITY)
    naive = (datetime.now(timezone.utc) - timedelta(minutes=10)).replace(tzinfo=None).isoformat()
    assert world.client.post("/api/events", json=[dict(_event(1), ts=naive)], headers=headers).status_code == 200
    with psycopg.connect(world.owner_url) as owner:
        occurred, expected = owner.execute(
            "SELECT occurred_at, %s::timestamp AT TIME ZONE 'UTC' FROM events WHERE log_source_id = %s",
            (naive, sid)).fetchone()
    assert occurred == expected
