"""Hospital telemetry (PR 16): the log source catalog, Suricata passive medical-device monitoring, the CERT-In clock
check in /api/data-flow, and threat categories and severity SLAs on alerts. Each test uses its own log sources."""
import random
import uuid
from datetime import datetime, timedelta, timezone

import psycopg

import hospital
import manage
from support import CITY, ORTHO, Api, failed_logins


def _now():
    return datetime.now(timezone.utc)


def _eve(at=None):
    return (at or _now()).strftime("%Y-%m-%dT%H:%M:%S.%f+0000")


def _source(world, kind, tenant=CITY):
    """A fresh log source of this kind and its raw ingest key, created directly so the test controls the kind."""
    name = f"{kind[:6]}-{uuid.uuid4().hex[:8]}"
    with psycopg.connect(world.owner_url) as owner:
        sid = manage.create_log_source(owner, tenant, name, kind)
        key = manage.create_ingest_key(owner, tenant, name, "telemetry test")
        owner.commit()
    return sid, {"Authorization": f"Bearer {key}"}


def _suricata_alert(src, dst, sid=None, priority=1, at=None, flow_id=None):
    sid = sid or random.randint(2_000_000, 2_999_999)
    return {"event_type": "alert", "timestamp": _eve(at), "flow_id": flow_id or random.randint(1, 10**12),
            "src_ip": src, "dest_ip": dst, "proto": "TCP", "dest_port": 443,
            "alert": {"signature": "ET MALWARE Possible ransomware beacon", "signature_id": sid,
                      "severity": priority, "category": "Malware"}}


def _alert_for_sid(world, sid):
    rows = Api(world, CITY, "viewer").get(f"/api/alerts?tenant={CITY}").get_json()
    return next((a for a in rows if a["rule"] == f"SURICATA:{sid}"), None)


# ---- Pure rules (no database) -----------------------------------------------------------------------

def test_threat_categories_follow_the_rule_then_the_text():
    assert hospital.categorize("FAILED_LOGIN_BURST") == "credential_abuse_impossible_travel"
    assert hospital.categorize("HC-END-001") == "ransomware"
    assert hospital.categorize("WAZUH:5712", "Phishing link opened by user") == "phishing"
    assert hospital.categorize("SUSPICIOUS_PROCESS", "unknown") == "other"


def test_sla_targets_and_breach_arithmetic():
    now = _now()
    created = (now - timedelta(minutes=20)).strftime("%Y-%m-%dT%H:%M:%S")
    assert hospital.sla_status("critical", created, "new", None, now) == (15, True)
    assert hospital.sla_status("high", created, "new", None, now) == (240, False)
    assert hospital.sla_status("low", None, "new", None, now) == (None, None)
    closed_late = (now - timedelta(minutes=5)).replace(tzinfo=timezone.utc)
    assert hospital.sla_status("critical", created, "closed", closed_late, now) == (15, True)


def test_ntp_threshold_defaults_to_five_seconds(monkeypatch):
    monkeypatch.delenv("MAX_NTP_SKEW_SECONDS", raising=False)
    assert hospital.max_ntp_skew_seconds() == 5.0
    monkeypatch.setenv("MAX_NTP_SKEW_SECONDS", "not-a-number")
    assert hospital.max_ntp_skew_seconds() == 5.0


def test_only_alert_records_normalize_and_medical_egress_is_critical():
    nets = hospital.medical_networks("10.20.0.0/16")
    assert hospital.normalize_suricata({"event_type": "flow"}, nets) is None
    ev = hospital.normalize_suricata(_suricata_alert("10.20.4.4", "93.184.216.9", sid=2000001, priority=1), nets)
    assert ev["threat_category"] == "medical_device_unexpected_egress" and ev["severity"] == "critical"
    internal = hospital.normalize_suricata(_suricata_alert("10.20.4.4", "10.20.8.8", sid=2000002, priority=2), nets)
    assert internal["threat_category"] != "medical_device_unexpected_egress" and internal["severity"] == "medium"


# ---- Log source catalog -----------------------------------------------------------------------------

def test_log_source_kind_must_come_from_the_catalog(world):
    admin = world.session(CITY, "hospital_admin")
    bad = world.client.post("/api/log-sources", json={"name": f"x-{uuid.uuid4().hex[:6]}", "kind": "bogus"},
                            headers=admin)
    assert bad.status_code == 400
    good = world.client.post("/api/log-sources", json={"name": f"s-{uuid.uuid4().hex[:6]}", "kind": "suricata_ids"},
                             headers=admin)
    assert good.status_code == 201 and good.get_json()["kind"] == "suricata_ids"


# ---- Suricata ingest --------------------------------------------------------------------------------

def test_suricata_alert_from_a_medical_device_to_a_public_address_becomes_a_categorised_alert(world, monkeypatch):
    monkeypatch.setenv("MEDICAL_NET_CIDRS", "10.20.0.0/16")
    _, headers = _source(world, "suricata_ids")
    sid = random.randint(2_000_000, 2_999_999)
    r = world.client.post("/api/ingest/suricata", json=_suricata_alert("10.20.5.9", "93.184.216.7", sid=sid),
                          headers=headers)
    assert r.status_code == 200, r.get_json()
    assert (r.get_json()["normalized"], r.get_json()["stored"], r.get_json()["alerts_created"]) == (1, 1, 1)
    alert = _alert_for_sid(world, sid)
    assert alert is not None
    assert alert["source"] == "suricata"
    assert alert["threat_category"] == "medical_device_unexpected_egress"
    assert alert["severity"] == "critical"
    assert alert["sla_target_minutes"] == 15 and alert["sla_breached"] is False


def test_a_key_from_another_kind_of_source_cannot_post_suricata_records(world):
    _, wazuh_headers = _source(world, "wazuh")
    r = world.client.post("/api/ingest/suricata", json=_suricata_alert("10.20.1.1", "93.184.216.1"),
                          headers=wazuh_headers)
    assert r.status_code == 403


def test_non_alert_eve_records_are_counted_and_ignored(world):
    _, headers = _source(world, "suricata_ids")
    r = world.client.post("/api/ingest/suricata", json=[{"event_type": "flow", "timestamp": _eve()},
                                                        _suricata_alert("10.20.1.1", "10.20.2.2")], headers=headers)
    assert r.status_code == 200
    assert (r.get_json()["ignored"], r.get_json()["normalized"]) == (1, 1)


def test_suricata_alerts_are_refused_on_the_generic_events_endpoint(world):
    _, headers = _source(world, "suricata_ids")
    r = world.client.post("/api/events", json=[{"ts": _eve(), "source": "suricata", "type": "suricata_alert",
                                                "host": "10.20.1.1", "sid": 1}], headers=headers)
    assert r.status_code == 400


# ---- CERT-In clock check in /api/data-flow ----------------------------------------------------------

def test_data_flow_flags_a_skewed_source_and_passes_a_synchronised_one(world, monkeypatch):
    monkeypatch.setenv("MAX_NTP_SKEW_SECONDS", "5")
    skewed_sid, skewed = _source(world, "wazuh")
    synced_sid, synced = _source(world, "wazuh")
    empty_sid, _ = _source(world, "wazuh")

    def auth_fail(at):
        return {"ts": at.strftime("%Y-%m-%dT%H:%M:%S.%f+00:00"), "source": "auth", "type": "auth_fail",
                "user": "x", "ip": "10.9.9.9", "detail": "clock test"}

    late = world.client.post("/api/events", json=[auth_fail(_now() - timedelta(seconds=120))], headers=skewed)
    assert late.status_code == 200, late.get_json()
    on_time = world.client.post("/api/events", json=[auth_fail(_now())], headers=synced)
    assert on_time.status_code == 200, on_time.get_json()

    flow = Api(world, CITY).get("/api/data-flow").get_json()
    by_id = {s["id"]: s for s in flow["sources"]}
    assert by_id[skewed_sid]["ntp_in_sync"] is False
    assert by_id[skewed_sid]["max_skew_seconds"] >= 115
    assert by_id[synced_sid]["ntp_in_sync"] is True
    assert by_id[synced_sid]["max_skew_seconds"] <= 5
    assert by_id[empty_sid]["ntp_in_sync"] is None


# ---- SLA and tenant isolation -----------------------------------------------------------------------

def test_an_open_critical_alert_past_its_fifteen_minutes_is_breached(world, monkeypatch):
    monkeypatch.setenv("MEDICAL_NET_CIDRS", "10.20.0.0/16")
    sid = random.randint(2_000_000, 2_999_999)
    _, headers = _source(world, "suricata_ids")
    world.client.post("/api/ingest/suricata", json=_suricata_alert("10.20.7.7", "93.184.216.50", sid=sid),
                      headers=headers)
    alert = _alert_for_sid(world, sid)
    with psycopg.connect(world.owner_url) as owner:
        old = (_now() - timedelta(minutes=30)).strftime("%Y-%m-%dT%H:%M:%S")
        owner.execute("UPDATE alerts SET created = %s WHERE id = %s", (old, alert["id"]))
        owner.commit()
    detail = Api(world, CITY, "viewer").get(f"/api/alerts/{alert['id']}").get_json()
    assert detail["sla_target_minutes"] == 15 and detail["sla_breached"] is True


def test_threat_category_and_sla_are_hidden_from_another_hospital(world):
    Api(world, CITY).post("/api/events", json=failed_logins(CITY, ip="10.66.0.1"))
    own = Api(world, CITY, "viewer").get(f"/api/alerts?tenant={CITY}").get_json()
    mine = next(a for a in own if a["rule"] == "FAILED_LOGIN_BURST")  # newest first: the burst this test just raised
    assert mine["threat_category"] == "credential_abuse_impossible_travel"
    assert mine["sla_target_minutes"] == 240
    theirs = Api(world, ORTHO, "viewer").get(f"/api/alerts?tenant={ORTHO}").get_json()
    assert all(a["id"] != mine["id"] for a in theirs)
