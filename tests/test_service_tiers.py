"""PR 17: service tiers, retention config, and the five core playbook scenarios.

City and Ortho are advanced (tests/conftest.py). Each gate test builds its own hospital so the shared ones never change.
"""
import uuid
from datetime import datetime, timezone

import psycopg
import pytest

import ansible_runner  # noqa: F401  (imported by the fixtures below)
import manage
import playbooks
import tiers
from support import Api, CITY, ORTHO, PASSWORD, failed_logins
from test_response_actions import (FakeAnsible, ansible_dirs, job_row, new_asset, open_alert,  # noqa: F401
                                   owner_rows, request_action, run_with)

ESSENTIAL_BLOCKED = ("isolate_host", "disable_account", "block_ip", "revoke_sessions", "medical_device_block_egress")


def new_hospital(world, tier=None):
    """A fresh hospital (default tier essential) with an admin, two analysts, a viewer and an ingest key."""
    tid = "tier-" + uuid.uuid4().hex[:8]
    vendor = Api(world, "platform", "vendor_admin")
    assert vendor.post("/api/tenants", json={"id": tid, "name": "Tier test"}).status_code == 201
    with psycopg.connect(world.owner_url) as owner:
        for username, role in (("admin", "hospital_admin"), ("analyst-l1", "l1"), ("analyst-l2", "l2"),
                               ("viewer", "viewer")):
            manage.create_user(owner, tid, username, role, PASSWORD, f"{username}@{tid}.example.test")
        manage.create_log_source(owner, tid, "ehr-feed", "wazuh")
        key = manage.create_ingest_key(owner, tid, "ehr-feed", "tier test")
    if tier:
        assert vendor.put(f"/api/tenants/{tid}/service", json={"service_tier": tier}).status_code == 200
    return tid, key


class As:
    def __init__(self, world, tenant, username):
        r = world.client.post("/api/login", json={"tenant": tenant, "username": username, "password": PASSWORD})
        assert r.status_code == 200, r.get_json()
        self.world, self.headers = world, {"Authorization": f"Bearer {r.get_json()['token']}"}

    def get(self, path):
        return self.world.client.get(path, headers=self.headers)

    def post(self, path, json=None):
        return self.world.client.post(path, json=json, headers=self.headers)


_SESSIONS = {}


def login_as(world, tenant, username):
    """One login per (hospital, user): every attempt counts against the per-account login rate limit."""
    cached = _SESSIONS.get((tenant, username))
    if cached is None:
        cached = _SESSIONS[(tenant, username)] = As(world, tenant, username)
    return cached


def open_alert_for(world, tid, key):
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    posted = world.client.post("/api/events", json=failed_logins(tid, day=today),
                               headers={"Authorization": f"Bearer {key}"})
    assert posted.status_code == 200 and posted.get_json()["alerts_created"] == 1
    return login_as(world, tid, "viewer").get("/api/alerts").get_json()[0]["id"]


def add_asset(world, tid, name, asset_class="workstation", mode="edr_managed", ip=""):
    created = login_as(world, tid, "admin").post("/api/assets", json={
        "device_name": name, "asset_class": asset_class, "monitoring_mode": mode, "ip_address": ip})
    assert created.status_code == 201, created.get_json()


# ---- defaults, config and validation -------------------------------------------------------------------------------

def test_a_new_hospital_is_essential_with_180_days_retention(world):
    tid, _ = new_hospital(world)
    assert owner_rows(world, "SELECT service_tier, retention_days FROM tenants WHERE id=%s", (tid,))[0] == (
        "essential", 180)
    body = login_as(world, tid, "viewer").get("/api/service-tier").get_json()
    assert body["service_tier"] == "essential" and body["retention_days"] == 180
    assert "automated_containment" not in body["features"]
    assert body["response_actions"]["collect_triage_snapshot"] == {"tier": "read_only", "included": True}
    assert body["response_actions"]["isolate_host"]["included"] is False


def test_the_database_refuses_bad_tiers_and_retention_below_180(world):
    tid, _ = new_hospital(world)
    for statement in ("UPDATE tenants SET service_tier='platinum' WHERE id=%s",
                      "UPDATE tenants SET retention_days=179 WHERE id=%s"):
        with psycopg.connect(world.owner_url) as owner:
            with pytest.raises(psycopg.errors.CheckViolation):
                owner.execute(statement, (tid,))


def test_only_a_vendor_admin_sets_tier_and_retention(world):
    tid, _ = new_hospital(world)
    vendor = Api(world, "platform", "vendor_admin")
    admin = login_as(world, tid, "admin")
    # The hospital cannot upgrade itself, whether through settings or the vendor route.
    assert world.client.put(f"/api/tenants/{tid}/service", json={"service_tier": "enterprise"},
                            headers=admin.headers).status_code == 403
    assert world.client.put("/api/settings", json={"name": "x", "service_tier": "enterprise"},
                            headers=admin.headers).status_code in (200, 400)
    assert owner_rows(world, "SELECT service_tier FROM tenants WHERE id=%s", (tid,))[0][0] == "essential"

    path = f"/api/tenants/{tid}/service"
    assert vendor.put(path, json={}).status_code == 400
    assert vendor.put(path, json={"service_tier": "platinum"}).status_code == 400
    assert vendor.put(path, json={"retention_days": 179}).status_code == 400
    assert vendor.put(path, json={"retention_days": 365.5}).status_code == 400
    assert vendor.put(path, json={"retention_days": True}).status_code == 400
    assert vendor.put(path, json={"service_tier": "advanced", "name": "x"}).status_code == 400
    assert vendor.put("/api/tenants/no-such-hospital/service", json={"service_tier": "advanced"}).status_code == 404
    assert vendor.put("/api/tenants/platform/service", json={"service_tier": "advanced"}).status_code == 409

    ok = vendor.put(path, json={"service_tier": "enterprise", "retention_days": 365})
    assert ok.status_code == 200 and ok.get_json() == {"id": tid, "service_tier": "enterprise", "retention_days": 365}
    assert owner_rows(world, "SELECT service_tier, retention_days FROM tenants WHERE id=%s", (tid,))[0] == (
        "enterprise", 365)
    listed = next(t for t in vendor.get("/api/tenants").get_json() if t["id"] == tid)
    assert (listed["service_tier"], listed["retention_days"]) == ("enterprise", 365)
    audited = owner_rows(world, "SELECT metadata FROM audit_events WHERE action='tenant.service.update' "
                                "AND resource_id=%s", (tid,))
    assert audited and audited[-1][0] == {"retention_days": 365, "service_tier": "enterprise"}


def test_shared_partitions_are_kept_for_the_longest_retaining_hospital(world):
    tid, _ = new_hospital(world)
    assert Api(world, "platform", "vendor_admin").put(
        f"/api/tenants/{tid}/service", json={"retention_days": 400}).status_code == 200
    with psycopg.connect(world.owner_url) as owner:
        assert owner.execute("SELECT effective_retention_days(180)").fetchone()[0] >= 400
        assert owner.execute("SELECT effective_retention_days(500)").fetchone()[0] >= 500
        assert owner.execute("SELECT effective_retention_days(NULL)").fetchone()[0] >= 400


def test_tier_feature_matrix(monkeypatch):
    for feature in ("automated_containment", "medical_device_containment", "executive_summary"):
        assert not tiers.allows("essential", feature)
        assert tiers.allows("advanced", feature) and tiers.allows("enterprise", feature)
    assert not tiers.allows("unknown", "automated_containment") and not tiers.allows(None, "executive_summary")
    monkeypatch.setenv("EXECUTIVE_SUMMARY_MIN_TIER", "essential")
    assert tiers.allows("essential", "executive_summary")
    monkeypatch.setenv("EXECUTIVE_SUMMARY_MIN_TIER", "enterprise")
    assert not tiers.allows("advanced", "executive_summary") and tiers.allows("enterprise", "executive_summary")
    monkeypatch.setenv("EXECUTIVE_SUMMARY_MIN_TIER", "bogus")  # an invalid value falls back to the default
    assert tiers.allows("advanced", "executive_summary") and not tiers.allows("essential", "executive_summary")


# ---- gating: essential is refused, advanced is allowed ---------------------------------------------------------------

@pytest.mark.parametrize("action", ESSENTIAL_BLOCKED)
def test_essential_is_denied_automated_containment_with_403(world, action):
    tid, key = new_hospital(world)
    alert_id = open_alert_for(world, tid, key)
    add_asset(world, tid, "ws-essential")
    l1 = login_as(world, tid, "analyst-l1")
    target = "ops.user" if playbooks.ALLOWLIST[action].target == "account" else "ws-essential"
    if action == "block_ip":
        target = "203.0.113.9"
    denied = l1.post(f"/api/alerts/{alert_id}/response-approvals",
                     json={"action": action, "target": target, "reason": "tier gate"})
    assert denied.status_code == 403
    assert "service tier" in denied.get_json()["error"] and "advanced" in denied.get_json()["error"]
    assert owner_rows(world, "SELECT count(*) FROM response_approvals WHERE tenant=%s", (tid,))[0][0] == 0
    assert owner_rows(world, "SELECT count(*) FROM response_jobs WHERE tenant_id=%s", (tid,))[0][0] == 0


def test_essential_can_still_collect_a_read_only_triage_snapshot(world):
    tid, key = new_hospital(world)
    alert_id = open_alert_for(world, tid, key)
    add_asset(world, tid, "ws-snapshot")
    l1 = login_as(world, tid, "analyst-l1")
    body = {"action": "collect_triage_snapshot", "target": "ws-snapshot", "reason": "enrich alert"}
    first = l1.post(f"/api/alerts/{alert_id}/response-approvals", json=body)
    assert first.status_code == 201, first.get_json()
    made = first.get_json()
    assert (made["job_status"], made["status"], made["id"]) == ("queued", "not_required", None)
    again = l1.post(f"/api/alerts/{alert_id}/response-approvals", json=body)  # no pending approval to collide with
    assert again.status_code == 201 and again.get_json()["job_id"] != made["job_id"]
    status, risk, approved_by = owner_rows(world, "SELECT status, risk_tier, approved_by FROM response_jobs "
                                                  "WHERE job_id=%s", (made["job_id"],))[0]
    assert (status, risk, approved_by) == ("queued", "read_only", None)
    assert owner_rows(world, "SELECT count(*) FROM response_approvals WHERE tenant=%s", (tid,))[0][0] == 0
    # It names an inventoried asset only: an unknown host is refused, and it is still tenant-scoped.
    unknown = l1.post(f"/api/alerts/{alert_id}/response-approvals",
                      json={"action": "collect_triage_snapshot", "target": "not-an-asset", "reason": "x"})
    assert unknown.status_code == 400


def test_advanced_is_allowed_and_a_second_person_still_approves(world):
    tid, key = new_hospital(world, tier="advanced")
    alert_id = open_alert_for(world, tid, key)
    add_asset(world, tid, "ws-advanced")
    l1, l2 = login_as(world, tid, "analyst-l1"), login_as(world, tid, "analyst-l2")
    for action, target in (("isolate_host", "ws-advanced"), ("disable_account", "stolen.account"),
                           ("revoke_sessions", "snooping.user"), ("block_ip", "203.0.113.50")):
        made = l1.post(f"/api/alerts/{alert_id}/response-approvals",
                       json={"action": action, "target": target, "reason": "tier allowed"})
        assert made.status_code == 201, (action, made.get_json())
        assert made.get_json()["job_status"] == "pending_approval"
        decided = l2.post(f"/api/response-approvals/{made.get_json()['id']}/decision", json={"decision": "approved"})
        assert decided.status_code == 200, (action, decided.get_json())


def test_enterprise_is_allowed_too(world):
    tid, key = new_hospital(world, tier="enterprise")
    alert_id = open_alert_for(world, tid, key)
    add_asset(world, tid, "ws-enterprise")
    made = login_as(world, tid, "analyst-l1").post(f"/api/alerts/{alert_id}/response-approvals",
                                             json={"action": "isolate_host", "target": "ws-enterprise", "reason": "x"})
    assert made.status_code == 201


def test_a_downgrade_stops_an_approval_that_is_still_waiting(world):
    tid, key = new_hospital(world, tier="advanced")
    alert_id = open_alert_for(world, tid, key)
    add_asset(world, tid, "ws-downgrade")
    made = login_as(world, tid, "analyst-l1").post(f"/api/alerts/{alert_id}/response-approvals",
                                             json={"action": "isolate_host", "target": "ws-downgrade", "reason": "x"})
    assert made.status_code == 201
    assert Api(world, "platform", "vendor_admin").put(
        f"/api/tenants/{tid}/service", json={"service_tier": "essential"}).status_code == 200
    decided = login_as(world, tid, "analyst-l2").post(f"/api/response-approvals/{made.get_json()['id']}/decision",
                                                json={"decision": "approved"})
    assert decided.status_code == 403
    assert owner_rows(world, "SELECT status FROM response_jobs WHERE job_id=%s",
                      (made.get_json()["job_id"],))[0][0] == "pending_approval"
    # Rejecting is always allowed: a hospital can close a request it can no longer run.
    rejected = login_as(world, tid, "analyst-l2").post(f"/api/response-approvals/{made.get_json()['id']}/decision",
                                                 json={"decision": "rejected"})
    assert rejected.status_code == 200


# ---- medical devices: egress block is safe, isolation is not ----------------------------------------------------------

def test_the_allowlist_covers_the_five_scenarios_and_every_digest_matches():
    assert {"isolate_host", "disable_account", "revoke_sessions", "block_ip", "medical_device_block_egress",
            "collect_triage_snapshot"} <= set(playbooks.ALLOWLIST)
    for pb in playbooks.ALLOWLIST.values():
        assert playbooks.verified_path(pb).is_file()
        assert playbooks.digest_of(playbooks.PLAYBOOK_ROOT / pb.file) == pb.sha256
    assert [a for a, pb in playbooks.ALLOWLIST.items() if pb.medical_safe] == ["medical_device_block_egress"]
    assert playbooks.ALLOWLIST["collect_triage_snapshot"].tier == "read_only"
    assert playbooks.ALLOWLIST["revoke_sessions"].target == "account"
    assert playbooks.validate_target("revoke_sessions", "dr.snooper") == "dr.snooper"
    with pytest.raises(playbooks.TargetRefused):
        playbooks.validate_target("revoke_sessions", "x; rm -rf /")
    with pytest.raises(playbooks.TargetRefused):
        playbooks.validate_target("medical_device_block_egress", "bad host name")


def test_egress_block_is_permitted_on_an_agentless_medical_asset_but_isolate_host_is_blocked(world, ansible_dirs):
    creds, work = ansible_dirs
    ip = f"10.77.{uuid.uuid4().int % 250 + 1}.{uuid.uuid4().int % 250 + 1}"
    device = new_asset(world, asset_class="ventilator", mode="agentless_medical", ip=ip)

    egress, alert_id = request_action(world, "medical_device_block_egress", device)
    assert egress.status_code == 201, egress.get_json()
    assert egress.get_json()["job_status"] == "pending_approval"          # still maker-checker
    isolate, _ = request_action(world, "isolate_host", device, alert_id=alert_id)
    assert isolate.status_code == 409 and "IEC 80001" in isolate.get_json()["error"]
    block_ip, _ = request_action(world, "block_ip", ip, alert_id=alert_id)
    assert block_ip.status_code == 409                                      # cutting the whole address is disruptive

    decided = Api(world, CITY, "l2").post(f"/api/response-approvals/{egress.get_json()['id']}/decision",
                                          json={"decision": "approved"})
    assert decided.status_code == 200, decided.get_json()
    job_id = decided.get_json()["job_id"]

    fake = FakeAnsible()
    run_with(world, job_id, fake, creds, work, rounds=1)
    assert len(fake.calls) == 1 and fake.calls[0]["hosts"] == [device]    # the executor allowed the egress playbook
    assert job_row(world, job_id)[0] == "succeeded"
    assert owner_rows(world, "SELECT count(*) FROM response_jobs WHERE tenant_id=%s AND action_type='isolate_host' "
                             "AND target_host=%s", (CITY, device))[0][0] == 0


def test_the_executor_still_refuses_isolate_host_on_a_medical_asset(world, ansible_dirs):
    """Even if a job row reached the worker (an inventory change after approval), isolation stays blocked."""
    creds, work = ansible_dirs
    device = new_asset(world)
    approved = request_action(world, "isolate_host", device)[0]
    assert approved.status_code == 201
    decided = Api(world, CITY, "l2").post(f"/api/response-approvals/{approved.get_json()['id']}/decision",
                                          json={"decision": "approved"})
    job_id = decided.get_json()["job_id"]
    with psycopg.connect(world.owner_url) as owner:
        owner.execute("UPDATE assets SET asset_class='ct', monitoring_mode='agentless_medical' "
                      "WHERE tenant_id=%s AND device_name=%s", (CITY, device))
    fake = FakeAnsible()
    run_with(world, job_id, fake, creds, work, rounds=1)
    assert fake.calls == [] and job_row(world, job_id)[0] == "dead"


def test_a_snapshot_is_allowed_on_medical_equipment(world):
    device = new_asset(world, asset_class="patient_monitor", mode="agentless_medical")
    made, _ = request_action(world, "collect_triage_snapshot", device)
    assert made.status_code == 201 and made.get_json()["job_status"] == "queued"


def test_revoke_sessions_and_disable_account_need_no_asset(world):
    for action in ("revoke_sessions", "disable_account"):
        made, _ = request_action(world, action, f"user.{uuid.uuid4().hex[:6]}")
        assert made.status_code == 201 and made.get_json()["job_status"] == "pending_approval"


def test_a_hospital_cannot_target_another_hospitals_device_for_egress_block(world):
    other = new_asset(world, tenant=ORTHO, asset_class="ventilator", mode="agentless_medical")
    made, _ = request_action(world, "medical_device_block_egress", other)
    assert made.status_code == 400 and "not an asset of this hospital" in made.get_json()["error"]
