"""PR 17: the monthly traffic-light executive report.

Every hospital here is built fresh, so counts are exact and the shared City and Ortho data never matters.
"""
import json
import uuid
from datetime import datetime, timedelta, timezone

import psycopg
import pytest

import app as soc
from routes import executive as ex
from support import Api, CITY, ORTHO, active_break_glass, revoke_break_glass
from test_service_tiers import add_asset, login_as, new_hospital

FMT = "%Y-%m-%dT%H:%M:%S"
SECTION_IDS = ["asset_edr_coverage", "unmanaged_unknown_assets", "sla_compliance", "detection_response_time",
               "unauthorized_attempts", "fp_review_readiness"]


@pytest.fixture(autouse=True)
def fp_settings(monkeypatch):
    monkeypatch.setenv("FP_TARGET", "0.5")
    monkeypatch.setenv("MIN_LABELED_SAMPLE", "1")


def stamp(delta):
    return (datetime.now(timezone.utc) - delta).strftime(FMT)


def add_alert(world, tid, severity="critical", created_ago=timedelta(days=2), detect_lag=timedelta(minutes=2),
              verdict="true_positive_malicious", respond_after=timedelta(minutes=10), summary="synthetic alert"):
    """An alert inserted by the owner so its times are exact. verdict None leaves it open."""
    created = datetime.now(timezone.utc) - created_ago
    closed = verdict is not None
    with psycopg.connect(world.owner_url) as owner:
        owner.execute(
            "INSERT INTO alerts(created, event_ts, tenant, rule, rule_version, severity, summary, dkey, status, "
            "verdict, verdict_at, source) VALUES (%s, %s, %s, 'TEST-RULE', '1', %s, %s, %s, %s, %s, %s, 'builtin')",
            (created.strftime(FMT), (created - detect_lag).strftime(FMT), tid, severity, summary, uuid.uuid4().hex,
             "closed" if closed else "new", verdict, created + respond_after if closed else None))


def healthy_hospital(world, tier="advanced", edr=10, unmanaged=0):
    """Assets covered, one critical alert answered in time and judged: every area is GREEN."""
    tid, key = new_hospital(world, tier=tier)
    for n in range(edr):
        add_asset(world, tid, f"ws-{n}")
    for n in range(unmanaged):
        add_asset(world, tid, f"legacy-{n}", mode="unmanaged")
    add_asset(world, tid, "ventilator-1", asset_class="ventilator", mode="agentless_medical")
    add_alert(world, tid)
    return tid, key


def summary(world, tid, username="viewer"):
    return login_as(world, tid, username).get("/api/executive-summary")


def by_id(report):
    return {section["id"]: section for section in report["sections"]}


# ---- the pure assessments: boundaries of RED / AMBER / GREEN -----------------------------------------------------

@pytest.mark.parametrize("total,edr,unmanaged,status", [
    (0, 0, 0, "RED"), (3, 0, 0, "GREEN"), (10, 9, 1, "GREEN"), (100, 89, 11, "AMBER"), (100, 75, 25, "AMBER"),
    (100, 74, 26, "RED"), (10, 0, 10, "RED")])
def test_edr_coverage_lights(total, edr, unmanaged, status):
    assert ex.assess_edr_coverage(total, edr, unmanaged)["status"] == status


@pytest.mark.parametrize("total,unmanaged,unknown,status", [
    (10, 0, 0, "GREEN"), (10, 1, 0, "AMBER"), (9, 0, 1, "AMBER"), (10, 2, 0, "RED"), (0, 0, 3, "RED")])
def test_unmanaged_and_unknown_lights(total, unmanaged, unknown, status):
    assert ex.assess_unmanaged(total, unmanaged, unknown)["status"] == status


@pytest.mark.parametrize("breaches,unjudged,status", [
    ([], 0, "GREEN"), ([], 2, "AMBER"), ([False] * 19 + [True], 0, "GREEN"), ([False] * 4 + [True], 0, "AMBER"),
    ([False, True], 0, "RED")])
def test_sla_lights(breaches, unjudged, status):
    assert ex.assess_sla(breaches, unjudged)["status"] == status


@pytest.mark.parametrize("mttd,mttr,status", [
    ([5], [1], "GREEN"), ([30], [1], "AMBER"), ([5], [10], "AMBER"), ([90], [1], "RED"), ([5], [30], "RED"),
    ([], [], "AMBER"), ([5], [], "AMBER")])
def test_response_time_lights(mttd, mttr, status):
    assert ex.assess_response_times(mttd, mttr)["status"] == status


@pytest.mark.parametrize("count,status", [(0, "GREEN"), (1, "AMBER"), (9, "AMBER"), (10, "RED")])
def test_unauthorized_attempt_lights(count, status):
    assert ex.assess_denied(count)["status"] == status


@pytest.mark.parametrize("target,groups,status", [
    (None, ["within_target"], "AMBER"), (0.1, [], "AMBER"), (0.1, ["within_target", "within_target"], "GREEN"),
    (0.1, ["within_target", "above_target"], "RED"), (0.1, ["within_target", "not_eligible"], "AMBER"),
    (0.1, ["undetermined"], "AMBER")])
def test_fp_review_lights(target, groups, status):
    assert ex.assess_fp_review(target, groups)["status"] == status


def test_the_overall_light_is_the_worst_section():
    sections = [{"status": "GREEN"}, {"status": "AMBER"}, {"status": "GREEN"}]
    assert ex.overall(sections)[0] == "AMBER"
    assert ex.overall(sections + [{"status": "RED"}])[0] == "RED"
    assert ex.overall([{"status": "GREEN"}])[0] == "GREEN"


# ---- the endpoint: GREEN, AMBER, RED from real data ----------------------------------------------------------------

def test_a_healthy_hospital_is_green_in_every_area(world):
    tid, _ = healthy_hospital(world)
    response = summary(world, tid)
    assert response.status_code == 200, response.get_json()
    report = response.get_json()
    assert report["overall"]["status"] == "GREEN"
    assert [s["id"] for s in report["sections"]] == SECTION_IDS
    assert {s["status"] for s in report["sections"]} == {"GREEN"}
    assert report["tenant_id"] == tid and report["service_tier"] == "advanced" and report["period"]["days"] == 30
    for section in report["sections"]:
        assert section["headline"] and section["explanation"]      # plain language for each light
    figures = by_id(report)
    assert figures["asset_edr_coverage"]["figures"]["edr_coverage_percent"] == 100.0
    assert figures["sla_compliance"]["figures"]["met_sla"] == 1
    assert figures["detection_response_time"]["figures"]["mttd_minutes"] == 2.0


def test_one_unmanaged_device_turns_the_report_amber(world):
    tid, _ = healthy_hospital(world, edr=9, unmanaged=1)
    report = summary(world, tid).get_json()
    sections = by_id(report)
    assert sections["asset_edr_coverage"]["status"] == "GREEN"        # 9 of 10 computers covered
    assert sections["unmanaged_unknown_assets"]["status"] == "AMBER"
    assert report["overall"]["status"] == "AMBER"


def test_poor_coverage_and_late_alerts_turn_the_report_red(world):
    tid, _ = healthy_hospital(world, edr=2, unmanaged=2)
    add_alert(world, tid, severity="critical", created_ago=timedelta(hours=3), verdict=None)   # open past its 15 minutes
    report = summary(world, tid).get_json()
    sections = by_id(report)
    assert sections["asset_edr_coverage"]["status"] == "RED"          # 2 of 4 computers
    assert sections["sla_compliance"]["status"] == "RED"              # one met, one missed
    assert sections["sla_compliance"]["figures"]["missed_sla"] == 1
    assert report["overall"]["status"] == "RED"


def test_slow_detection_and_response_are_measured(world):
    tid, _ = healthy_hospital(world)
    add_alert(world, tid, severity="medium", detect_lag=timedelta(hours=3), respond_after=timedelta(hours=40))
    times = by_id(summary(world, tid).get_json())["detection_response_time"]
    assert times["status"] == "RED"
    assert times["figures"]["mttd_samples"] == 2 and times["figures"]["mttr_samples"] == 2
    assert times["figures"]["mttd_minutes"] == pytest.approx((2 + 180) / 2, abs=0.1)


def test_alerts_older_than_the_period_are_ignored(world):
    tid, _ = healthy_hospital(world)
    add_alert(world, tid, severity="critical", created_ago=timedelta(days=45),
              respond_after=timedelta(hours=5))                                       # a stale SLA breach
    assert summary(world, tid).get_json()["overall"]["status"] == "GREEN"


def test_unknown_hosts_in_the_logs_are_counted(world):
    tid, key = healthy_hospital(world)
    posted = world.client.post("/api/events", headers={"Authorization": f"Bearer {key}"}, json=[
        {"ts": datetime.now(timezone.utc).strftime(FMT), "tenant": tid, "source": "auth",
         "type": "process_start", "user": "u", "host": "rogue-pc-7"}])
    assert posted.status_code == 200
    unmanaged = by_id(summary(world, tid).get_json())["unmanaged_unknown_assets"]
    assert unmanaged["figures"]["unknown_hosts_seen"] == 1 and unmanaged["status"] == "AMBER"


def test_refused_requests_are_counted_and_turn_the_light(world):
    tid, _ = healthy_hospital(world)
    l1 = login_as(world, tid, "analyst-l1")
    for _ in range(3):
        assert l1.get("/api/executive-summary").status_code == 403        # an analyst is not a report reader
    report = summary(world, tid).get_json()
    assert by_id(report)["unauthorized_attempts"]["figures"]["refused_requests"] == 3
    assert by_id(report)["unauthorized_attempts"]["status"] == "AMBER" and report["overall"]["status"] == "AMBER"
    for _ in range(7):
        l1.get("/api/executive-summary")
    report = summary(world, tid).get_json()
    assert by_id(report)["unauthorized_attempts"]["status"] == "RED" and report["overall"]["status"] == "RED"


def test_cross_hospital_attempts_land_on_the_caller_hospital(world):
    tid, _ = healthy_hospital(world)
    other, _ = healthy_hospital(world)
    admin = login_as(world, tid, "admin")
    assert world.client.get(f"/api/executive-summary?tenant_id={other}", headers=admin.headers).status_code == 403
    mine = by_id(summary(world, tid).get_json())["unauthorized_attempts"]["figures"]["refused_requests"]
    theirs = by_id(summary(world, other).get_json())["unauthorized_attempts"]["figures"]["refused_requests"]
    assert (mine, theirs) == (1, 0)


def test_fp_review_readiness_follows_the_target(world, monkeypatch):
    tid, _ = healthy_hospital(world)
    for _ in range(3):
        add_alert(world, tid, severity="low", verdict="false_positive")
    monkeypatch.setenv("FP_TARGET", "0.1")           # 3 of 4 labeled alerts are false positives
    review = by_id(summary(world, tid).get_json())["fp_review_readiness"]
    assert review["status"] == "RED" and review["figures"]["above_target"] == 1
    monkeypatch.delenv("FP_TARGET")
    assert by_id(summary(world, tid).get_json())["fp_review_readiness"]["status"] == "AMBER"


# ---- access: roles, tier, break-glass -------------------------------------------------------------------------------

def test_only_hospital_admin_and_viewer_may_read_it(world):
    tid, _ = healthy_hospital(world)
    assert summary(world, tid, "admin").status_code == 200
    assert summary(world, tid, "viewer").status_code == 200
    assert summary(world, tid, "analyst-l1").status_code == 403
    assert summary(world, tid, "analyst-l2").status_code == 403


def test_essential_is_refused_unless_the_report_is_made_available(world, monkeypatch):
    tid, _ = healthy_hospital(world, tier="essential")
    refused = summary(world, tid, "admin")
    assert refused.status_code == 403 and "advanced" in refused.get_json()["error"]
    monkeypatch.setenv("EXECUTIVE_SUMMARY_MIN_TIER", "essential")     # the site chooses to include it
    assert summary(world, tid, "admin").status_code == 200
    monkeypatch.setenv("EXECUTIVE_SUMMARY_MIN_TIER", "enterprise")
    assert summary(world, tid, "admin").status_code == 403            # the site can also make it stricter
    assert Api(world, "platform", "vendor_admin").put(
        f"/api/tenants/{tid}/service", json={"service_tier": "advanced"}).status_code == 200
    assert summary(world, tid, "admin").status_code == 403            # advanced is below that bar
    assert Api(world, "platform", "vendor_admin").put(
        f"/api/tenants/{tid}/service", json={"service_tier": "enterprise"}).status_code == 200
    assert summary(world, tid, "admin").status_code == 200


def test_enterprise_is_allowed(world):
    tid, _ = healthy_hospital(world, tier="enterprise")
    assert summary(world, tid, "admin").status_code == 200


def test_vendor_admin_needs_an_active_metrics_read_break_glass(world):
    vendor = Api(world, "platform", "vendor_admin")
    assert vendor.get("/api/executive-summary").status_code == 403                    # no tenant named
    assert vendor.get(f"/api/executive-summary?tenant_id={CITY}").status_code == 403  # no grant
    try:
        active_break_glass(world, CITY, "alerts:read")                                # the wrong scope
        assert vendor.get(f"/api/executive-summary?tenant_id={CITY}").status_code == 403
        active_break_glass(world, CITY, "metrics:read")
        allowed = vendor.get(f"/api/executive-summary?tenant_id={CITY}")
        assert allowed.status_code == 200 and allowed.get_json()["tenant_id"] == CITY
        assert vendor.get(f"/api/executive-summary?tenant_id={ORTHO}").status_code == 403  # the grant is per hospital
        with psycopg.connect(world.owner_url) as owner:
            audited = [row[0] for row in owner.execute(
                "SELECT action FROM audit_events WHERE tenant_id=%s AND auth_context='break_glass'",
                (CITY,)).fetchall()]
        assert "break_glass.access" in audited and "executive_summary.read" in audited
    finally:
        revoke_break_glass(world, CITY)
    assert vendor.get(f"/api/executive-summary?tenant_id={CITY}").status_code == 403  # revoked


# ---- isolation and privacy --------------------------------------------------------------------------------------------

def test_each_hospital_sees_only_its_own_numbers(world):
    red, _ = healthy_hospital(world, edr=1, unmanaged=3)
    green, _ = healthy_hospital(world)
    assert summary(world, red).get_json()["overall"]["status"] == "RED"
    assert summary(world, green).get_json()["overall"]["status"] == "GREEN"
    assert by_id(summary(world, green).get_json())["asset_edr_coverage"]["figures"]["total_assets"] == 11
    assert by_id(summary(world, red).get_json())["asset_edr_coverage"]["figures"]["total_assets"] == 5


def test_the_runtime_role_cannot_read_another_hospitals_rows(world):
    """As soc_app with row-level security: hospital B's identity sees none of hospital A's alerts, assets or audit."""
    a, _ = healthy_hospital(world)
    b, _ = healthy_hospital(world)
    summary(world, a)
    with psycopg.connect(world.owner_url) as owner:
        actor = owner.execute("SELECT id FROM users WHERE tenant=%s AND username='admin'", (b,)).fetchone()[0]
    with soc.connect() as conn:
        soc._bind(conn, b, "hospital_admin", actor)
        assert conn.execute("SELECT count(*) FROM alerts WHERE tenant = %s", (a,)).fetchone()[0] == 0
        assert conn.execute("SELECT count(*) FROM assets WHERE tenant_id = %s", (a,)).fetchone()[0] == 0
        assert conn.execute("SELECT count(*) FROM audit_events WHERE tenant_id = %s", (a,)).fetchone()[0] == 0
        assert [r[0] for r in conn.execute("SELECT id FROM tenants").fetchall()] == [b]
        assert conn.execute("SELECT count(*) FROM alerts WHERE tenant = %s", (b,)).fetchone()[0] == 1
        # The runtime role cannot change a tier itself, even for its own hospital.
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute("UPDATE tenants SET service_tier = 'enterprise' WHERE id = %s", (b,))
    with soc.connect() as conn:
        soc._bind(conn, b, "hospital_admin", actor)
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute("SELECT set_tenant_service(%s::text, 'enterprise', NULL)", (b,))


def test_the_report_carries_no_raw_phi_or_secrets(world):
    tid, key = healthy_hospital(world)
    add_asset(world, tid, "ward-secret-host-77", ip="10.99.88.77")
    add_alert(world, tid, summary="patient=Jane Doe MRN 4471 password=hunter2 token=abc123", severity="critical",
              created_ago=timedelta(hours=1), verdict=None)
    world.client.post("/api/events", headers={"Authorization": f"Bearer {key}"}, json=[
        {"ts": datetime.now(timezone.utc).strftime(FMT), "tenant": tid, "source": "auth", "type": "process_start",
         "user": "jane.doe", "host": "rogue-host-9", "patient": "Jane Doe", "detail": "password=hunter2"}])
    raw = summary(world, tid).get_data(as_text=True)
    for secret in ("Jane", "4471", "hunter2", "abc123", "ward-secret-host-77", "10.99.88.77", "rogue-host-9",
                   "jane.doe", "TEST-RULE", "ehr-feed"):
        assert secret not in raw, secret

    def only_numbers(value):
        if isinstance(value, dict):
            return all(only_numbers(v) for v in value.values())
        return value is None or isinstance(value, (int, float)) and not isinstance(value, bool)
    for section in json.loads(raw)["sections"]:
        assert only_numbers(section["figures"]), section["id"]
