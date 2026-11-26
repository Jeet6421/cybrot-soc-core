"""Hospital onboarding, asset inventory, intra-tenant handoffs and offboarding, end to end.

Each test builds its own hospital, so the shared City and Ortho fixtures are never changed.
"""
import uuid
from datetime import datetime, timezone

import psycopg
import pytest

import manage
from support import Api, ORTHO, PASSWORD, failed_logins


def todays_burst(tenant):
    """Five failed logins stamped today (UTC), inside the 24-hour data-flow window."""
    return failed_logins(tenant, day=datetime.now(timezone.utc).strftime("%Y-%m-%d"))


class As:
    """Calls the API as one logged-in user of a hospital, using the session token from POST /api/login."""

    def __init__(self, world, tenant, username):
        r = world.client.post("/api/login", json={"tenant": tenant, "username": username, "password": PASSWORD})
        assert r.status_code == 200, r.get_json()
        self.world = world
        self.headers = {"Authorization": f"Bearer {r.get_json()['token']}"}

    def get(self, path):
        return self.world.client.get(path, headers=self.headers)

    def post(self, path, json=None):
        return self.world.client.post(path, json=json, headers=self.headers)

    def patch(self, path, json=None):
        return self.world.client.patch(path, json=json, headers=self.headers)


def owner_rows(world, sql, params=()):
    with psycopg.connect(world.owner_url) as owner:
        return owner.execute(sql, params).fetchall()


def new_hospital(world):
    """A fresh hospital: an admin, two analysts and a viewer, and one wazuh log source with one ingest key."""
    tid = "onboard-" + uuid.uuid4().hex[:8]
    assert Api(world, "platform", "vendor_admin").post(
        "/api/tenants", json={"id": tid, "name": "Onboarding test"}).status_code == 201
    with psycopg.connect(world.owner_url) as owner:
        manage.create_user(owner, tid, "admin", "hospital_admin", PASSWORD, f"admin@{tid}.example.test")
        manage.create_user(owner, tid, "analyst-l1", "l1", PASSWORD, f"l1@{tid}.example.test")
        manage.create_user(owner, tid, "analyst-l2", "l2", PASSWORD, f"l2@{tid}.example.test")
        manage.create_user(owner, tid, "viewer", "viewer", PASSWORD, f"viewer@{tid}.example.test")
        manage.create_log_source(owner, tid, "ehr-feed", "wazuh")
        key = manage.create_ingest_key(owner, tid, "ehr-feed", "onboarding test")
    return tid, key


def ingest(world, key, events):
    return world.client.post("/api/events", json=events, headers={"Authorization": f"Bearer {key}"})


def test_onboarding_to_offboarding_end_to_end(world):
    tid, provisioned_key = new_hospital(world)
    admin = As(world, tid, "admin")
    l1 = As(world, tid, "analyst-l1")
    viewer = As(world, tid, "viewer")

    # The key that manage.py issued at setup already ingests into its own hospital.
    assert ingest(world, provisioned_key, todays_burst(tid)).status_code == 200

    # ---- Asset inventory: clinical equipment is agentless; other devices may run an EDR agent ---------
    mri = {"device_name": "mri-01", "ip_address": "10.20.0.11", "mac_address": "00:1A:2B:3C:4D:5E",
           "department": "Radiology", "asset_class": "mri", "monitoring_mode": "agentless_medical",
           "criticality": "critical"}
    assert admin.post("/api/assets", json={**mri, "monitoring_mode": "edr_managed"}).status_code == 400
    assert admin.post("/api/assets", json=mri).status_code == 201
    assert admin.post("/api/assets", json={"device_name": "ws-01", "asset_class": "workstation",
                                           "monitoring_mode": "edr_managed", "department": "ED"}).status_code == 201
    assert admin.post("/api/assets", json={"device_name": "bad-mac", "monitoring_mode": "unmanaged",
                                           "mac_address": "not-a-mac"}).status_code == 400
    assert admin.post("/api/assets", json={"device_name": "ws-01", "monitoring_mode": "unmanaged"}).status_code == 409
    assets = viewer.get("/api/assets").get_json()
    assert {a["device_name"]: a["monitoring_mode"] for a in assets} == {
        "mri-01": "agentless_medical", "ws-01": "edr_managed"}
    ws = next(a for a in assets if a["device_name"] == "ws-01")
    assert admin.patch(f"/api/assets/{ws['asset_id']}", json={"criticality": "high"}).status_code == 200
    assert admin.patch(f"/api/assets/{ws['asset_id']}", json={"asset_class": "ct"}).status_code == 400
    assert l1.post("/api/assets", json={"device_name": "x", "monitoring_mode": "unmanaged"}).status_code == 403
    assert owner_rows(world, "SELECT count(*) FROM assets WHERE tenant_id=%s AND asset_class='mri' "
                             "AND monitoring_mode='agentless_medical'", (tid,))[0][0] == 1

    # ---- Credentials: prefix and hash only; the secret is shown once; overlap on rotation ---------------
    source_id = admin.get("/api/log-sources").get_json()[0]["id"]
    first = admin.post("/api/credentials", json={"log_source_id": source_id, "label": "wazuh-01"}).get_json()
    assert first["key_prefix"] == first["key"][:8]
    listed = admin.get("/api/credentials").get_json()
    assert all("key" not in row for row in listed)
    stored_prefix, stored_hash = owner_rows(world, "SELECT key_prefix, key_hash FROM ingest_keys WHERE id=%s",
                                            (first["id"],))[0]
    assert stored_prefix == first["key_prefix"] and first["key"] not in stored_hash

    assert ingest(world, first["key"], todays_burst(tid)).status_code == 200
    rotated = admin.post(f"/api/credentials/{first['id']}/rotate", json={"overlap_minutes": 60})
    assert rotated.status_code == 201
    second = rotated.get_json()
    assert ingest(world, second["key"], todays_burst(tid)).status_code == 200
    assert ingest(world, first["key"], todays_burst(tid)).status_code == 200  # overlap: the old key still works
    assert admin.post(f"/api/credentials/{first['id']}/revoke").status_code == 200
    assert ingest(world, first["key"], todays_burst(tid)).status_code == 401

    # ---- Data flow: last seen, accepted and rejected counts, readiness sample -------------------------
    assert ingest(world, second["key"], [1]).status_code == 400  # a rejected event
    flow = admin.get("/api/data-flow").get_json()
    assert flow["last_seen_event_ts"] is not None
    assert flow["accepted_24h"] >= 2 and flow["rejected_24h"] >= 1
    assert flow["sources"][0]["accepted_24h"] >= 2
    assert flow["readiness"]["checked"] >= 2
    assert flow["readiness"]["normalized"] == flow["readiness"]["checked"]
    assert l1.get("/api/data-flow").status_code == 403

    # ---- Intra-tenant handoffs: only to an active analyst of this hospital ----------------------------
    alert = admin.get("/api/alerts").get_json()[0]
    analysts = {a["username"]: a["user_id"] for a in admin.get("/api/analysts").get_json()["analysts"]}
    assert "viewer" not in analysts and "analyst-l2" in analysts
    assert l1.post(f"/api/alerts/{alert['id']}/handoff", json={"to_actor_id": analysts["analyst-l2"]}).status_code == 200
    assert owner_rows(world, "SELECT to_user_id, from_user_id FROM handoffs WHERE alert_id=%s", (alert["id"],))[0] == (
        analysts["analyst-l2"], analysts["analyst-l1"])

    # A user of another hospital cannot receive this hospital's alert.
    ortho_analyst = owner_rows(world, "SELECT id FROM users WHERE tenant=%s AND username='analyst-l1'", (ORTHO,))[0][0]
    assert l1.post(f"/api/alerts/{alert['id']}/handoff", json={"to_actor_id": ortho_analyst}).status_code == 400

    # A disabled analyst cannot receive a handoff.
    gone = admin.post("/api/users", json={"username": "gone-l1", "role": "l1", "password": PASSWORD,
                                          "email": f"gone@{tid}.example.test"}).get_json()["id"]
    assert admin.post(f"/api/users/{gone}/disable").status_code == 200
    assert l1.post(f"/api/alerts/{alert['id']}/handoff", json={"to_actor_id": gone}).status_code == 400

    # ---- Offboarding: the hospital admin starts it; the vendor exports, archives and purges -----------
    started = admin.post("/api/offboarding/start")
    assert started.status_code == 200
    assert started.get_json()["users_disabled"] >= 4 and started.get_json()["keys_revoked"] >= 1
    assert admin.get("/api/users").status_code in (401, 403)  # the admin's own session has ended
    assert world.client.post("/api/login", json={"tenant": tid, "username": "analyst-l1",
                                                 "password": PASSWORD}).status_code in (401, 403)
    assert ingest(world, second["key"], todays_burst(tid)).status_code == 401  # keys stop with the hospital

    vendor = Api(world, "platform", "vendor_admin")
    assert vendor.post(f"/api/tenants/{tid}/offboarding/archive").status_code == 409  # export first
    exported = vendor.post(f"/api/tenants/{tid}/offboarding/export")
    assert exported.status_code == 200 and exported.get_json()["record_counts"]["events"] >= 5
    assert vendor.post(f"/api/tenants/{tid}/offboarding/purge").status_code == 409  # archive first
    assert vendor.post(f"/api/tenants/{tid}/offboarding/archive").status_code == 200
    purged = vendor.post(f"/api/tenants/{tid}/offboarding/purge")
    assert purged.status_code == 200 and sum(purged.get_json()["removed"].values()) > 0
    assert vendor.post(f"/api/tenants/{tid}/offboarding/purge").status_code == 409  # already purged

    assert owner_rows(world, "SELECT count(*) FROM events WHERE tenant=%s", (tid,))[0][0] == 0
    assert owner_rows(world, "SELECT count(*) FROM alerts WHERE tenant=%s", (tid,))[0][0] == 0
    assert owner_rows(world, "SELECT count(*) FROM assets WHERE tenant_id=%s", (tid,))[0][0] == 0
    assert owner_rows(world, "SELECT lifecycle_state FROM tenants WHERE id=%s", (tid,))[0][0] == "purged"
    assert owner_rows(world, "SELECT count(*) FROM users WHERE tenant=%s AND is_active", (tid,))[0][0] == 0
    actions = {row[0] for row in owner_rows(
        world, "SELECT action FROM audit_events WHERE tenant_id=%s", (tid,))}
    assert {"tenant.offboarding.start", "tenant.export", "tenant.archive", "tenant.purge"} <= actions


def test_lifecycle_steps_cannot_be_skipped(world):
    tid, _ = new_hospital(world)
    vendor = Api(world, "platform", "vendor_admin")
    assert vendor.post(f"/api/tenants/{tid}/offboarding/archive").status_code == 409  # not offboarding yet
    assert vendor.post(f"/api/tenants/{tid}/offboarding/purge").status_code == 409
    with pytest.raises(psycopg.Error):  # the database itself refuses an illegal step
        with psycopg.connect(world.owner_url) as owner:
            owner.execute("SELECT set_tenant_lifecycle(%s, 'active', 'archived')", (tid,))


def test_rotation_with_zero_overlap_stops_the_old_key_at_once(world):
    tid, _ = new_hospital(world)
    admin = As(world, tid, "admin")
    source_id = admin.get("/api/log-sources").get_json()[0]["id"]
    first = admin.post("/api/credentials", json={"log_source_id": source_id, "label": "x"}).get_json()
    assert ingest(world, first["key"], todays_burst(tid)).status_code == 200
    rotated = admin.post(f"/api/credentials/{first['id']}/rotate", json={"overlap_minutes": 0}).get_json()
    assert ingest(world, first["key"], todays_burst(tid)).status_code == 401
    assert ingest(world, rotated["key"], todays_burst(tid)).status_code == 200
    assert admin.post(f"/api/credentials/{first['id']}/rotate", json={"overlap_minutes": 5000}).status_code == 400
