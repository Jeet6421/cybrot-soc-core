"""Logins, sessions, roles and what each role may do through the API.

Each test creates the users or alerts it needs, so the tests do not depend on each other.
"""
import uuid

import psycopg
import pytest

import manage
from support import Api, CITY, ORTHO, PASSWORD, failed_logins


def login(world, tenant, username, password=PASSWORD):
    return world.client.post("/api/login", json={"tenant": tenant, "username": username, "password": password})


def owner_rows(world, sql, params=()):
    with psycopg.connect(world.owner_url) as owner:
        return owner.execute(sql, params).fetchall()


def new_alert(world, tenant):
    """Raise one alert through the tenant's ingest key and return its id."""
    r = Api(world, tenant).post("/api/events", json=failed_logins(tenant))
    assert r.get_json()["alerts_created"] == 1
    return Api(world, tenant, "viewer").get(f"/api/alerts?tenant={tenant}").get_json()[0]["id"]


def new_user(world, tenant, role, admin_role="hospital_admin"):
    username = f"u-{uuid.uuid4().hex[:8]}"
    r = Api(world, tenant, admin_role).post("/api/users", json={"username": username, "role": role, "password": PASSWORD})
    assert r.status_code == 201, r.get_json()
    return username, r.get_json()["id"]


# ---- Logins and sessions ---------------------------------------------------------------------------

def test_login_returns_a_token_and_the_role(world):
    r = login(world, CITY, "analyst-l1")
    assert r.status_code == 200
    body = r.get_json()
    assert body["role"] == "l1" and body["tenant"] == CITY and body["token"]


def test_wrong_password_and_unknown_user_look_the_same(world):
    wrong = login(world, CITY, "admin", "not the password at all")
    unknown = login(world, CITY, "nobody-here")
    assert wrong.status_code == unknown.status_code == 401
    assert wrong.get_json() == unknown.get_json()


def test_me_reports_the_session_identity(world):
    r = Api(world, CITY, "l2").get("/api/me")
    assert r.get_json() == {"kind": "session", "username": "analyst-l2", "tenant": CITY, "role": "l2"}


def test_logout_ends_the_session(world):
    token = login(world, CITY, "viewer").get_json()["token"]
    headers = {"Authorization": f"Bearer {token}"}
    assert world.client.get("/api/metrics", headers=headers).status_code == 200
    assert world.client.post("/api/logout", headers=headers).status_code == 200
    assert world.client.get("/api/metrics", headers=headers).status_code == 401


def test_disabled_user_loses_access_at_once(world):
    username, uid = new_user(world, CITY, "viewer")
    token = login(world, CITY, username).get_json()["token"]
    headers = {"Authorization": f"Bearer {token}"}
    assert world.client.get("/api/metrics", headers=headers).status_code == 200
    assert Api(world, CITY).post(f"/api/users/{uid}/disable").status_code == 200
    assert world.client.get("/api/metrics", headers=headers).status_code == 401
    assert login(world, CITY, username).status_code == 401


# ---- Scope: tenant_id can only narrow -------------------------------------------------------------

def test_tenant_id_can_only_narrow_within_the_callers_hospital(world):
    admin = Api(world, CITY, "hospital_admin")
    assert admin.get(f"/api/alerts?tenant_id={ORTHO}").status_code == 403
    assert admin.get(f"/api/metrics?tenant={ORTHO}").status_code == 403
    assert admin.get(f"/api/alerts?tenant_id={CITY}").status_code == 200


def test_l1_can_read_only_its_hospital_events(world):
    new_alert(world, CITY)
    l1 = Api(world, CITY, "l1")
    response = l1.get("/api/events?limit=20&type=auth_fail")
    assert response.status_code == 200
    body = response.get_json()
    assert body["events"] and all(event["tenant"] == CITY for event in body["events"])
    assert all(event["type"] == "auth_fail" for event in body["events"])
    assert l1.get(f"/api/events?tenant_id={ORTHO}").status_code == 403
    assert Api(world, CITY, "viewer").get("/api/events").status_code == 403
    assert l1.get("/api/events?limit=501").status_code == 400


def test_hospital_admin_can_update_only_its_hospital_name_setting(world):
    admin = Api(world, CITY, "hospital_admin")
    ortho = Api(world, ORTHO, "hospital_admin")
    assert admin.get("/api/settings").get_json()["name"] == "City Hospital"
    updated = admin.put("/api/settings", json={"name": "City Hospital Test"})
    assert updated.status_code == 200 and updated.get_json()["name"] == "City Hospital Test"
    assert ortho.get("/api/settings").get_json()["name"] == "Ortho Clinic"
    assert Api(world, CITY, "l1").put("/api/settings", json={"name": "Nope"}).status_code == 403
    assert admin.put(f"/api/settings?tenant_id={ORTHO}", json={"name": "Nope"}).status_code == 403
    rows = owner_rows(world, "SELECT count(*) FROM audit_log WHERE tenant=%s AND action='tenant.settings.update'",
                      (CITY,))
    assert rows[0][0] == 1
    assert admin.put("/api/settings", json={"name": "City Hospital"}).status_code == 200


# ---- What each role may do -----------------------------------------------------------------------

def test_viewer_reads_but_cannot_change(world):
    alert_id = new_alert(world, CITY)
    viewer = Api(world, CITY, "viewer")
    assert viewer.get("/api/alerts").status_code == 200
    assert viewer.post(f"/api/alerts/{alert_id}/ack").status_code == 403
    assert viewer.post(f"/api/alerts/{alert_id}/verdict", json={"verdict": "tp"}).status_code == 403
    assert viewer.post(f"/api/alerts/{alert_id}/handoff", json={"to_owner": "analyst2"}).status_code == 403
    assert viewer.post("/api/log-sources", json={"name": "x"}).status_code == 403
    assert viewer.post("/api/credentials", json={"log_source_id": 1}).status_code == 403
    assert viewer.get("/api/users").status_code == 403


def test_l1_triages_and_hands_off_but_does_not_close_or_administer(world):
    alert_id = new_alert(world, CITY)
    l1 = Api(world, CITY, "l1")
    assert l1.post(f"/api/alerts/{alert_id}/ack").status_code == 200
    alerts = Api(world, CITY, "viewer").get("/api/alerts").get_json()
    alert = next(a for a in alerts if a["id"] == alert_id)
    owners = Api(world, CITY, "viewer").get("/api/analysts").get_json()["analysts"]
    next_owner = next(owner for owner in owners if owner != alert["owner"])
    assert l1.post(f"/api/alerts/{alert_id}/handoff", json={"to_owner": next_owner, "note": "check it"}).status_code == 200
    assert l1.post(f"/api/alerts/{alert_id}/verdict", json={"verdict": "tp"}).status_code == 403
    assert l1.post("/api/log-sources", json={"name": "x"}).status_code == 403
    assert l1.post("/api/credentials", json={"log_source_id": 1}).status_code == 403
    assert l1.get("/api/users").status_code == 403


def test_l2_closes_alerts_with_a_verdict(world):
    alert_id = new_alert(world, CITY)
    r = Api(world, CITY, "l2").post(f"/api/alerts/{alert_id}/verdict", json={"verdict": "tp", "note": "confirmed"})
    assert r.status_code == 200
    row = next(a for a in Api(world, CITY, "viewer").get("/api/alerts").get_json() if a["id"] == alert_id)
    assert row["status"] == "closed" and row["verdict"] == "tp"


def test_l2_approval_is_required_for_allowlisted_response_actions(world):
    alert_id = new_alert(world, CITY)
    l1 = Api(world, CITY, "l1")
    l2 = Api(world, CITY, "l2")
    request_body = {"action": "isolate_host", "target": "vpn-01", "reason": "Contain confirmed brute force"}
    created = l1.post(f"/api/alerts/{alert_id}/response-approvals", json=request_body)
    assert created.status_code == 201
    approval_id = created.get_json()["id"]
    assert created.get_json()["execution"] == "not_performed"
    assert l1.post(f"/api/response-approvals/{approval_id}/decision", json={"decision": "approved"}).status_code == 403
    assert l1.post(f"/api/alerts/{alert_id}/response-approvals", json=request_body).status_code == 409
    assert l2.post(f"/api/response-approvals/{approval_id}/decision",
                   json={"decision": "approved", "note": "Confirmed by L2"}).status_code == 200
    listing = l1.get(f"/api/alerts/{alert_id}/response-approvals").get_json()
    assert listing[0]["status"] == "approved" and listing[0]["decision_note"] == "Confirmed by L2"
    assert Api(world, CITY, "viewer").get(f"/api/alerts/{alert_id}/response-approvals").status_code == 403
    assert l1.post(f"/api/alerts/{alert_id}/response-approvals",
                   json={**request_body, "action": "run_shell_command"}).status_code == 400


def test_response_requester_cannot_approve_own_request(world):
    alert_id = new_alert(world, CITY)
    l2 = Api(world, CITY, "l2")
    created = l2.post(f"/api/alerts/{alert_id}/response-approvals", json={
        "action": "block_ip", "target": "203.0.113.10", "reason": "Block confirmed hostile source"})
    assert created.status_code == 201
    approval_id = created.get_json()["id"]
    assert l2.post(f"/api/response-approvals/{approval_id}/decision", json={"decision": "approved"}).status_code == 409


def test_hospital_admin_manages_their_own_users(world):
    admin = Api(world, CITY, "hospital_admin")
    names = {u["username"] for u in admin.get("/api/users").get_json()}
    assert {"admin", "analyst-l1", "viewer"} <= names
    username, uid = new_user(world, CITY, "l1")
    assert login(world, CITY, username).status_code == 200
    assert admin.post("/api/users", json={"username": "vendor-like", "role": "vendor_admin", "password": PASSWORD}).status_code == 400
    assert admin.post("/api/users", json={"username": "shortpw", "role": "l1", "password": "short"}).status_code == 400
    assert admin.post("/api/users", json={"username": username, "role": "l1", "password": PASSWORD}).status_code == 409
    assert admin.post("/api/users/%d/disable" % _own_id(world, CITY, "admin")).status_code == 400


def _own_id(world, tenant, username):
    return owner_rows(world, "SELECT id FROM users WHERE tenant=%s AND username=%s", (tenant, username))[0][0]


def test_admin_cannot_reach_another_hospitals_records(world):
    alert_id = new_alert(world, ORTHO)
    city = Api(world, CITY, "hospital_admin")
    assert city.post(f"/api/alerts/{alert_id}/ack").status_code == 404
    assert city.post(f"/api/alerts/{alert_id}/verdict", json={"verdict": "tp"}).status_code == 404
    assert city.post(f"/api/alerts/{alert_id}/handoff", json={"to_owner": "analyst2"}).status_code == 404
    assert city.get(f"/api/alerts/{alert_id}/handoffs").status_code == 404
    assert city.get(f"/api/alerts/{alert_id}/response-approvals").status_code == 404
    assert city.post(f"/api/alerts/{alert_id}/response-approvals", json={
        "action": "isolate_host", "target": "ehr-01", "reason": "wrong tenant"}).status_code == 404
    assert city.get(f"/api/events?tenant_id={ORTHO}").status_code == 403
    assert city.get(f"/api/settings?tenant_id={ORTHO}").status_code == 403
    ortho_key = Api(world, ORTHO, "hospital_admin").get("/api/credentials").get_json()[0]["id"]
    assert city.post(f"/api/credentials/{ortho_key}/revoke").status_code == 404
    ortho_user = _own_id(world, ORTHO, "viewer")
    assert city.post(f"/api/users/{ortho_user}/disable").status_code == 404
    ortho_source = owner_rows(world, "SELECT id FROM log_sources WHERE tenant=%s", (ORTHO,))[0][0]
    assert city.post(f"/api/log-sources/{ortho_source}/disable").status_code == 404
    city_user_ids = {u["id"] for u in city.get("/api/users").get_json()}
    assert ortho_user not in city_user_ids


# ---- Vendor admin: no routine access, break-glass only ------------------------------------------------

def test_vendor_admin_has_no_routine_access_to_hospital_data(world):
    new_alert(world, CITY)
    vendor = Api(world, "platform", "vendor_admin")
    assert vendor.get("/api/alerts").status_code == 403  # no hospital named
    assert vendor.get(f"/api/alerts?tenant_id={CITY}").status_code == 403  # named, but no grant
    assert vendor.get(f"/api/metrics?tenant_id={CITY}").status_code == 403
    assert vendor.post("/api/users", json={"username": "x-user", "role": "l1", "password": PASSWORD}).status_code == 403
    assert vendor.get("/api/credentials").status_code == 403


def test_break_glass_is_read_only_audited_and_time_limited(world):
    alert_id = new_alert(world, CITY)
    vendor = Api(world, "platform", "vendor_admin")
    with psycopg.connect(world.owner_url) as owner:
        manage.grant_break_glass(owner, "vendor", CITY, 1, "INC-TEST-1", "test")
        owner.commit()
    assert vendor.get(f"/api/alerts?tenant_id={CITY}").status_code == 200
    assert vendor.post(f"/api/alerts/{alert_id}/ack").status_code == 403  # read-only, even with a grant
    assert vendor.get(f"/api/alerts?tenant_id={ORTHO}").status_code == 403  # the grant is for City only
    audited = owner_rows(world, "SELECT count(*) FROM audit_log WHERE tenant=%s AND action='break_glass.read'", (CITY,))
    assert audited[0][0] >= 1

    with psycopg.connect(world.owner_url) as owner:
        owner.execute("UPDATE break_glass_grants SET revoked_at = now() WHERE tenant=%s", (CITY,))
        owner.commit()
    assert vendor.get(f"/api/alerts?tenant_id={CITY}").status_code == 403


def test_expired_break_glass_grant_is_refused(world):
    with psycopg.connect(world.owner_url) as owner:
        manage.grant_break_glass(owner, "vendor", ORTHO, 1, "INC-TEST-2", "test")
        owner.execute("UPDATE break_glass_grants SET expires_at = now() - interval '1 minute' WHERE tenant=%s", (ORTHO,))
        owner.commit()
    assert Api(world, "platform", "vendor_admin").get(f"/api/alerts?tenant_id={ORTHO}").status_code == 403


def test_grant_validation_refuses_bad_input(world):
    with psycopg.connect(world.owner_url) as owner:
        with pytest.raises(ValueError):
            manage.grant_break_glass(owner, "vendor", CITY, 48, "too long", "test")
        with pytest.raises(ValueError):
            manage.grant_break_glass(owner, "vendor", CITY, 1, "  ", "test")
        with pytest.raises(ValueError):
            manage.grant_break_glass(owner, "admin", CITY, 1, "not a vendor", "test")
        owner.rollback()


# ---- Audit -----------------------------------------------------------------------------------------

def test_admin_changes_are_audited(world):
    name = f"audit-{uuid.uuid4().hex[:6]}"
    assert Api(world, CITY, "hospital_admin").post("/api/log-sources", json={"name": name}).status_code == 201
    rows = owner_rows(world, "SELECT count(*) FROM audit_log WHERE tenant=%s AND action='log_source.create' AND detail=%s",
                      (CITY, name))
    assert rows[0][0] == 1

