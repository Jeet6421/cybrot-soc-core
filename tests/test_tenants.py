"""Phase 1 of the multi-tenant design: hospitals (tenants), per-hospital ingest keys, and tenant-scoped data.

A hospital's ingest key may only write its own events and Wazuh alerts. It must not read, change or write
into another hospital. These tests run with an operator token set, the way a shared deployment runs."""
import hashlib, uuid

import pytest

import app as soc

c = soc.app.test_client()
OPERATOR_TOKEN = "operator-test-token"
OPERATOR = {"Authorization": f"Bearer {OPERATOR_TOKEN}"}


@pytest.fixture(autouse=True)
def operator_mode(monkeypatch):
    monkeypatch.setattr(soc, "API_TOKEN", OPERATOR_TOKEN)


def new_tenant(label="h"):
    tid = f"{label}-{uuid.uuid4().hex[:8]}"  # unique per test, because the test database is shared
    r = c.post("/api/tenants", json={"id": tid, "name": tid}, headers=OPERATOR)
    assert r.status_code == 201, r.get_json()
    return tid


def new_key(tid, label="test"):
    r = c.post(f"/api/tenants/{tid}/keys", json={"label": label}, headers=OPERATOR)
    assert r.status_code == 201, r.get_json()
    body = r.get_json()
    return body["key"], body["id"]


def as_key(key):
    return {"Authorization": f"Bearer {key}"}


def failed_logins(tenant, ip, n=5):
    """Five failed logins from one IP within a minute: enough to raise FAILED_LOGIN_BURST."""
    return [{"ts": f"2026-11-25T10:00:0{i}", "tenant": tenant, "source": "auth", "type": "auth_fail",
             "user": "u", "ip": ip} for i in range(n)]


def alerts_for(tenant):
    return c.get(f"/api/alerts?tenant={tenant}", headers=OPERATOR).get_json()


def test_key_ingests_into_its_own_hospital():
    a, b = new_tenant("a"), new_tenant("b")
    key_a, _ = new_key(a)
    r = c.post("/api/events", json=failed_logins(a, "203.0.113.50"), headers=as_key(key_a))
    assert r.status_code == 200 and r.get_json()["alerts_created"] == 1
    assert len(alerts_for(a)) == 1
    assert alerts_for(b) == []


def test_tenant_comes_from_the_key_when_the_body_omits_it():
    a = new_tenant("a")
    key, _ = new_key(a)
    events = failed_logins(a, "198.51.100.7")
    for e in events:
        del e["tenant"]
    r = c.post("/api/events", json=events, headers=as_key(key))
    assert r.status_code == 200
    assert len(alerts_for(a)) == 1


def test_key_cannot_write_into_another_hospital():
    a, b = new_tenant("a"), new_tenant("b")
    key_a, _ = new_key(a)
    r = c.post("/api/events", json=failed_logins(b, "203.0.113.60"), headers=as_key(key_a))
    assert r.status_code == 403
    assert c.get(f"/api/metrics?tenant={b}", headers=OPERATOR).get_json()["events"] == 0


def test_key_cannot_read_or_change_alerts():
    a = new_tenant("a")
    key, _ = new_key(a)
    c.post("/api/events", json=failed_logins(a, "203.0.113.70"), headers=as_key(key))
    alert_id = alerts_for(a)[0]["id"]
    assert c.get("/api/alerts", headers=as_key(key)).status_code == 401
    assert c.get("/api/metrics", headers=as_key(key)).status_code == 401
    assert c.get("/api/tenants", headers=as_key(key)).status_code == 401
    assert c.post(f"/api/alerts/{alert_id}/ack", headers=as_key(key)).status_code == 401
    assert c.post(f"/api/alerts/{alert_id}/verdict", json={"verdict": "tp"}, headers=as_key(key)).status_code == 401
    assert c.get(f"/api/alerts/{alert_id}/handoffs", headers=as_key(key)).status_code == 401


def test_wazuh_tenant_comes_from_the_key_not_the_query():
    a, b = new_tenant("a"), new_tenant("b")
    key, _ = new_key(a)
    body = {"rule": {"id": "5712", "level": 10, "description": "sshd brute force"},
            "agent": {"name": "ehr-02"}, "timestamp": "2026-11-25T10:00:00"}
    r = c.post(f"/api/ingest/wazuh?token={key}&tenant={b}", json=body)
    assert r.status_code == 200 and r.get_json()["alert_id"]
    assert len(alerts_for(a)) == 1
    assert alerts_for(b) == []


def test_revoked_key_is_refused():
    a = new_tenant("a")
    key, kid = new_key(a)
    assert c.post(f"/api/keys/{kid}/revoke", headers=OPERATOR).status_code == 200
    r = c.post("/api/events", json=failed_logins(a, "203.0.113.80"), headers=as_key(key))
    assert r.status_code == 401


def test_unknown_key_is_refused():
    a = new_tenant("a")
    r = c.post("/api/events", json=failed_logins(a, "203.0.113.90"), headers=as_key("not-a-real-key"))
    assert r.status_code == 401


def test_key_is_stored_only_as_a_hash():
    a = new_tenant("a")
    key, _ = new_key(a)
    conn = soc.connect()
    try:
        hashes = [r["key_hash"] for r in conn.execute("SELECT key_hash FROM ingest_keys").fetchall()]
    finally:
        conn.close()
    assert key not in hashes
    assert hashlib.sha256(key.encode()).hexdigest() in hashes


def test_key_list_never_returns_the_key():
    a = new_tenant("a")
    key, _ = new_key(a)
    listed = c.get(f"/api/tenants/{a}/keys", headers=OPERATOR).get_json()
    assert len(listed) == 1 and key not in str(listed)


def test_duplicate_tenant_is_refused():
    a = new_tenant("a")
    assert c.post("/api/tenants", json={"id": a}, headers=OPERATOR).status_code == 409


def test_bad_tenant_id_is_refused():
    assert c.post("/api/tenants", json={"id": "Bad Name!"}, headers=OPERATOR).status_code == 400


def test_key_for_unknown_hospital_is_refused():
    assert c.post("/api/tenants/no-such-hospital/keys", json={}, headers=OPERATOR).status_code == 404


def test_metrics_and_gates_are_scoped_to_one_hospital():
    a, b = new_tenant("a"), new_tenant("b")
    key_a, _ = new_key(a)
    c.post("/api/events", json=failed_logins(a, "203.0.113.100"), headers=as_key(key_a))
    ma = c.get(f"/api/metrics?tenant={a}", headers=OPERATOR).get_json()
    mb = c.get(f"/api/metrics?tenant={b}", headers=OPERATOR).get_json()
    assert ma["events"] == 5 and ma["alerts"] == 1
    assert mb["events"] == 0 and mb["alerts"] == 0
    gates = c.get(f"/api/exit-criteria?tenant={a}", headers=OPERATOR).get_json()["gates"]
    assert {g["id"]: g["status"] for g in gates}["foundation"] == "pass"


def test_handoff_keeps_the_hospital_on_the_history_row():
    a = new_tenant("a")
    key, _ = new_key(a)
    c.post("/api/events", json=failed_logins(a, "203.0.113.110"), headers=as_key(key))
    alert = alerts_for(a)[0]
    other = next(x for x in soc.ANALYSTS if x != alert["owner"])  # round-robin owner can be any analyst
    r = c.post(f"/api/alerts/{alert['id']}/handoff", json={"to_owner": other, "note": "scoped"}, headers=OPERATOR)
    assert r.status_code == 200
    conn = soc.connect()
    try:
        row = conn.execute("SELECT tenant FROM handoffs WHERE alert_id=%s", (alert["id"],)).fetchone()
    finally:
        conn.close()
    assert row["tenant"] == a
