"""Re-sending the same events stores nothing new (PR 13). Identity is the sender's source event id when it has one,
otherwise a SHA-256 of the canonical payload. Each test uses its own log source."""
import uuid
from datetime import datetime, timedelta, timezone

import psycopg

import manage
from support import CITY, ORTHO


def _source(world, tenant):
    name = f"idem-{uuid.uuid4().hex[:8]}"
    with psycopg.connect(world.owner_url) as owner:
        manage.create_log_source(owner, tenant, name, "custom")
        key = manage.create_ingest_key(owner, tenant, name, "idempotency test")
        sid = owner.execute("SELECT id FROM log_sources WHERE tenant = %s AND name = %s", (tenant, name)).fetchone()[0]
        owner.commit()
    return {"Authorization": f"Bearer {key}"}, sid


def _stored(world, tenant, sid):
    with psycopg.connect(world.owner_url) as owner:
        return owner.execute("SELECT count(*) FROM events WHERE tenant = %s AND log_source_id = %s",
                             (tenant, sid)).fetchone()[0]


def _batch(tag, n=3):
    base = datetime.now(timezone.utc) - timedelta(minutes=20)
    return [{"ts": (base + timedelta(seconds=i)).isoformat(), "source": "auth", "type": "auth_fail",
             "user": f"{tag}-{i}", "ip": "10.2.2.2", "detail": f"{tag} {i}"} for i in range(n)]


def test_resending_a_batch_with_source_event_ids_stores_zero_duplicates(world):
    headers, sid = _source(world, CITY)
    batch = [dict(e, source_event_id=f"evt-{i}") for i, e in enumerate(_batch("a"))]

    first = world.client.post("/api/events", json=batch, headers=headers).get_json()
    assert (first["stored"], first["duplicates"]) == (3, 0)
    again = world.client.post("/api/events", json=batch, headers=headers).get_json()
    assert (again["stored"], again["duplicates"]) == (0, 3)
    assert _stored(world, CITY, sid) == 3


def test_resending_identical_payloads_without_ids_is_idempotent(world):
    headers, sid = _source(world, CITY)
    batch = _batch("b")
    world.client.post("/api/events", json=batch, headers=headers)
    again = world.client.post("/api/events", json=batch, headers=headers).get_json()
    assert again["duplicates"] == 3 and again["stored"] == 0
    assert _stored(world, CITY, sid) == 3


def test_an_identical_event_twice_in_one_request_is_stored_once(world):
    headers, sid = _source(world, CITY)
    event = _batch("c", 1)[0]
    body = world.client.post("/api/events", json=[event, dict(event)], headers=headers).get_json()
    assert (body["stored"], body["duplicates"]) == (1, 1)
    assert _stored(world, CITY, sid) == 1


def test_a_corrected_timestamp_is_a_new_event(world):
    headers, sid = _source(world, CITY)
    event = _batch("d", 1)[0]
    world.client.post("/api/events", json=[event], headers=headers)
    moved = dict(event, ts=(datetime.fromisoformat(event["ts"]) + timedelta(seconds=1)).isoformat())
    body = world.client.post("/api/events", json=[moved], headers=headers).get_json()
    assert body["stored"] == 1  # a different occurred_at is a different event; the key includes it
    assert _stored(world, CITY, sid) == 2


def test_dedupe_is_scoped_to_the_hospital(world):
    headers_city, sid_city = _source(world, CITY)
    headers_ortho, sid_ortho = _source(world, ORTHO)
    batch = [dict(e, source_event_id="shared-id") for e in _batch("e", 1)]
    assert world.client.post("/api/events", json=batch, headers=headers_city).get_json()["stored"] == 1
    assert world.client.post("/api/events", json=batch, headers=headers_ortho).get_json()["stored"] == 1
    assert _stored(world, CITY, sid_city) == 1 and _stored(world, ORTHO, sid_ortho) == 1
