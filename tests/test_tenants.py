"""Hospitals (tenants), ingest keys (credentials) and log sources.

An ingest key is bound to one hospital and one log source. It may write that log source's events and Wazuh alerts,
and nothing else: it cannot read, change, or write into another hospital.
"""
import hashlib, uuid

import psycopg
import pytest

from support import Api, CITY, ORTHO, failed_logins

c = None


@pytest.fixture(autouse=True)
def _api(world):
    global c
    c = Api(world)


def admin(world, tenant=CITY):
    return Api(world, tenant, "hospital_admin")


def alerts_of(world, tenant):
    return Api(world, tenant, "viewer").get(f"/api/alerts?tenant={tenant}").get_json()


def key_headers(key):
    return {"Authorization": f"Bearer {key}"}


def test_key_ingests_into_its_own_hospital(world):
    c.post("/api/reset")
    r = c.post("/api/events", json=failed_logins(CITY))
    assert r.status_code == 200 and r.get_json()["alerts_created"] == 1
    assert len(alerts_of(world, CITY)) == 1
    assert alerts_of(world, ORTHO) == []


def test_tenant_comes_from_the_key_when_the_body_omits_it(world):
    c.post("/api/reset")
    events = failed_logins(CITY)
    for e in events:
        del e["tenant"]
    assert c.post("/api/events", json=events).status_code == 200
    assert len(alerts_of(world, CITY)) == 1


def test_key_cannot_write_into_another_hospital(world):
    c.post("/api/reset")
    r = c.post("/api/events", json=failed_logins(ORTHO))
    assert r.status_code == 403
    assert Api(world, ORTHO, "viewer").get("/api/metrics").get_json()["events"] == 0


def test_key_cannot_read_or_change_anything(world):
    c.post("/api/reset")
    c.post("/api/events", json=failed_logins(CITY))
    alert_id = alerts_of(world, CITY)[0]["id"]
    key = world.ingest(CITY)
    assert c.get("/api/events", headers=key).status_code == 403
    assert c.get("/api/alerts", headers=key).status_code == 403
    assert c.get("/api/metrics", headers=key).status_code == 403
    assert c.get("/api/tenants", headers=key).status_code == 403
    assert c.get("/api/credentials", headers=key).status_code == 403
    assert c.post(f"/api/alerts/{alert_id}/ack", headers=key).status_code == 403
    assert c.post(f"/api/alerts/{alert_id}/verdict", json={"verdict": "tp"}, headers=key).status_code == 403
    assert c.post(f"/api/alerts/{alert_id}/handoff", json={"to_owner": "analyst2"}, headers=key).status_code == 403
    assert c.get(f"/api/alerts/{alert_id}/handoffs", headers=key).status_code == 403


def test_wazuh_tenant_comes_from_the_key_not_the_query(world):
    c.post("/api/reset")
    body = {"rule": {"id": "5712", "level": 10, "description": "sshd brute force"},
            "agent": {"name": "ehr-02"}, "timestamp": "2026-11-25T10:00:00"}
    r = c.post(f"/api/ingest/wazuh?tenant={ORTHO}", json=body)
    assert r.status_code == 200 and r.get_json()["alert_id"]
    assert len(alerts_of(world, CITY)) == 1
    assert alerts_of(world, ORTHO) == []


def test_revoked_key_is_refused(world):
    c.post("/api/reset")
    created = admin(world).post("/api/credentials", json={"log_source_id": _log_source_id(world, CITY, "ehr-feed")})
    assert created.status_code == 201
    body = created.get_json()
    assert c.post("/api/events", json=failed_logins(CITY), headers=key_headers(body["key"])).status_code == 200
    assert admin(world).post(f"/api/credentials/{body['id']}/revoke").status_code == 200
    assert c.post("/api/events", json=failed_logins(CITY), headers=key_headers(body["key"])).status_code == 401


def test_unknown_key_is_refused():
    r = c.post("/api/events", json=failed_logins(CITY), headers=key_headers("not-a-real-key"))
    assert r.status_code == 401


def test_key_is_stored_only_as_a_hash(world):
    created = admin(world).post("/api/credentials", json={"log_source_id": _log_source_id(world, CITY, "ehr-feed")})
    key = created.get_json()["key"]
    with psycopg.connect(world.owner_url) as owner:  # the owner may read the table; the runtime role may not
        hashes = [r[0] for r in owner.execute("SELECT key_hash FROM ingest_keys").fetchall()]
    assert key not in hashes
    assert hashlib.sha256(key.encode()).hexdigest() in hashes


def test_credential_list_never_returns_the_key(world):
    created = admin(world).post("/api/credentials", json={"log_source_id": _log_source_id(world, CITY, "ehr-feed")})
    key = created.get_json()["key"]
    listed = admin(world).get("/api/credentials").get_json()
    assert listed and key not in str(listed)


def test_credential_is_bound_to_its_log_source(world):
    c.post("/api/reset")
    sid = admin(world).post("/api/log-sources", json={"name": f"wazuh-{uuid.uuid4().hex[:6]}", "kind": "wazuh"}).get_json()["id"]
    key = admin(world).post("/api/credentials", json={"log_source_id": sid, "label": "w"}).get_json()["key"]
    body = failed_logins(CITY)
    for e in body:
        e["log_source_id"] = 999999  # a body value must not override the key's log source
    assert c.post("/api/events", json=body, headers=key_headers(key)).status_code == 200
    with psycopg.connect(world.owner_url) as owner:
        stored = {r[0] for r in owner.execute("SELECT log_source_id FROM events WHERE tenant = %s", (CITY,)).fetchall()}
    assert stored == {sid}


def test_hospital_admin_cannot_use_another_hospitals_log_source(world):
    other = _log_source_id(world, ORTHO, "ehr-feed")
    r = admin(world).post("/api/credentials", json={"log_source_id": other})
    assert r.status_code == 404
    assert admin(world).post(f"/api/log-sources/{other}/disable").status_code == 404


def test_disabled_log_source_stops_its_key(world):
    c.post("/api/reset")
    sid = admin(world).post("/api/log-sources", json={"name": f"tmp-{uuid.uuid4().hex[:6]}"}).get_json()["id"]
    key = admin(world).post("/api/credentials", json={"log_source_id": sid}).get_json()["key"]
    assert c.post("/api/events", json=failed_logins(CITY), headers=key_headers(key)).status_code == 200
    assert admin(world).post(f"/api/log-sources/{sid}/disable").status_code == 200
    assert c.post("/api/events", json=failed_logins(CITY), headers=key_headers(key)).status_code == 401


def test_duplicate_log_source_is_refused(world):
    name = f"dup-{uuid.uuid4().hex[:6]}"
    assert admin(world).post("/api/log-sources", json={"name": name}).status_code == 201
    assert admin(world).post("/api/log-sources", json={"name": name}).status_code == 409


def test_vendor_creates_tenants(world):
    tid = f"new-{uuid.uuid4().hex[:8]}"
    vendor = Api(world, "platform", "vendor_admin")
    assert vendor.post("/api/tenants", json={"id": tid, "name": tid}).status_code == 201
    assert vendor.post("/api/tenants", json={"id": tid}).status_code == 409
    assert vendor.post("/api/tenants", json={"id": "Bad Name!"}).status_code == 400
    assert vendor.post("/api/tenants", json={"id": "platform"}).status_code == 400
    assert admin(world).post("/api/tenants", json={"id": f"x-{tid}"}).status_code == 403
    assert admin(world).get("/api/tenants").status_code == 403
    assert any(t["id"] == tid for t in vendor.get("/api/tenants").get_json())


def test_metrics_are_scoped_to_one_hospital(world):
    c.post("/api/reset")
    c.post("/api/events", json=failed_logins(CITY))
    ma = admin(world).get("/api/metrics").get_json()
    mb = Api(world, ORTHO, "viewer").get("/api/metrics").get_json()
    assert ma["events"] == 5 and ma["alerts"] == 1
    assert mb["events"] == 0 and mb["alerts"] == 0
    gates = admin(world).get("/api/exit-criteria").get_json()["gates"]
    assert {g["id"]: g["status"] for g in gates}["foundation"] == "pass"


def test_handoff_keeps_the_hospital_on_the_history_row(world):
    c.post("/api/reset")
    c.post("/api/events", json=failed_logins(CITY))
    alert = alerts_of(world, CITY)[0]
    other = next(x for x in ["analyst1", "analyst2", "analyst3"] if x != alert["owner"])
    assert c.post(f"/api/alerts/{alert['id']}/handoff", json={"to_owner": other, "note": "scoped"}).status_code == 200
    with psycopg.connect(world.owner_url) as owner:
        row = owner.execute("SELECT tenant FROM handoffs WHERE alert_id=%s", (alert["id"],)).fetchone()
    assert row[0] == CITY


def _log_source_id(world, tenant, name):
    """The owner looks the id up directly; the API tests above do not depend on this helper's result."""
    with psycopg.connect(world.owner_url) as owner:
        return owner.execute("SELECT id FROM log_sources WHERE tenant=%s AND name=%s", (tenant, name)).fetchone()[0]

