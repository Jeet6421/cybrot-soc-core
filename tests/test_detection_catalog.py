import os

import psycopg
import pytest

from support import Api, CITY

c = None


@pytest.fixture(autouse=True)
def _api(world):
    global c
    c = Api(world)


def event(type_, **kwargs):
    return {
        "ts": "2026-11-20T10:00:00",
        "tenant": CITY,
        "source": "synthetic",
        "type": type_,
        **kwargs,
    }


def reset():
    c.post("/api/reset")


def alerts():
    return c.get(f"/api/alerts?tenant={CITY}").get_json()


def test_hc_end_001_detects_50_distinct_file_changes_in_five_minutes():
    reset()
    events = [
        event("file_rename", host="ehr-ws-01", detail=f"C:/data/file-{i}.dat",
              ts=f"2026-11-20T10:00:{i:02d}")
        for i in range(50)
    ]

    response = c.post("/api/events", json=events)

    assert response.status_code == 200
    assert {a["rule"] for a in alerts()} == {"HC-END-001"}
    assert alerts()[0]["severity"] == "critical"
    assert alerts()[0]["rule_version"] == "0.1.0"


def test_hc_end_001_does_not_alert_below_file_activity_threshold():
    reset()
    events = [
        event("file_modify", host="ehr-ws-01", detail=f"C:/data/file-{i}.dat",
              ts=f"2026-11-20T10:00:{i:02d}")
        for i in range(49)
    ]

    c.post("/api/events", json=events)

    assert alerts() == []


def test_hc_end_004_alerts_on_endpoint_security_tampering_but_not_approved_change():
    reset()
    c.post("/api/events", json=event("security_agent_disabled", host="ehr-ws-01", approved_change=True))
    assert alerts() == []

    c.post("/api/events", json=event("security_agent_disabled", host="ehr-ws-01", approved_change=False))

    assert [a["rule"] for a in alerts()] == ["HC-END-004"]


def test_hc_dlp_002_requires_sensitive_classification_and_unapproved_destination():
    reset()
    c.post("/api/events", json=event("data_transfer", host="ehr-01", data_classification="phi",
                                     destination="partner.example", destination_approved=True))
    assert alerts() == []

    c.post("/api/events", json=event("data_transfer", host="ehr-01", data_classification="phi",
                                     destination="unknown.example", destination_approved=False))

    assert [a["rule"] for a in alerts()] == ["HC-DLP-002"]


def test_hc_ops_002_alerts_on_unapproved_destructive_change_and_repeated_failures():
    reset()
    c.post("/api/events", json=event("backup_retention_changed", host="backup-01", approved_change=True))
    assert alerts() == []
    c.post("/api/events", json=event("backup_repository_deleted", host="backup-01", approved_change=False))
    assert [a["rule"] for a in alerts()] == ["HC-OPS-002"]

    reset()
    failures = [
        event("backup_job_failed", host="backup-01", ts=f"2026-11-20T{hour:02d}:00:00")
        for hour in (0, 8, 12)
    ]
    c.post("/api/events", json=failures)
    assert [a["rule"] for a in alerts()] == ["HC-OPS-002"]


def test_hc_med_004_requires_an_explicit_boundary_violation_with_both_zones():
    reset()
    c.post("/api/events", json=event("network_flow", src_zone="clinical", dst_zone="corporate",
                                     boundary_violation=False))
    assert alerts() == []

    c.post("/api/events", json=event("network_flow", src_zone="clinical", dst_zone="corporate",
                                     boundary_violation=True))

    assert [a["rule"] for a in alerts()] == ["HC-MED-004"]


def test_hc_aud_001_alerts_on_unapproved_audit_log_tampering():
    reset()
    c.post("/api/events", json=event("audit_log_cleared", host="ehr-01", approved_change=True))
    assert alerts() == []
    c.post("/api/events", json=event("log_forwarding_disabled", host="ehr-01", approved_change=False))

    assert [a["rule"] for a in alerts()] == ["HC-AUD-001"]


def test_rule_events_persist_normalized_clinical_context():
    reset()
    payload = event("data_transfer", host="ehr-01", data_classification="patient_data",
                    destination="unknown.example", destination_approved=False)
    c.post("/api/events", json=payload)

    # Read as the owner: the runtime role only sees rows of the hospital its identity names.
    with psycopg.connect(os.environ["MIGRATE_DATABASE_URL"]) as owner:
        row = owner.execute(
            "SELECT destination, data_classification, destination_approved FROM events WHERE type='data_transfer' "
            "ORDER BY id DESC LIMIT 1"
        ).fetchone()

    assert row[0] == "unknown.example"
    assert row[1] == "patient_data"
    assert row[2] is False
