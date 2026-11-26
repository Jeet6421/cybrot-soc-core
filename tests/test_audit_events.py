"""Append-only audit storage and authenticated acknowledgement/verdict attribution."""
import os

import psycopg
import pytest
from psycopg import errors

import app as soc
from support import Api, CITY, failed_logins


def _owner_rows(world, sql, params=()):
    with psycopg.connect(world.owner_url) as owner:
        return owner.execute(sql, params).fetchall()


def _make_alert(world):
    response = world.client.post(
        "/api/events", json=failed_logins(CITY), headers=world.ingest(CITY))
    assert response.status_code in (200, 201)
    alerts = Api(world, CITY, "viewer").get("/api/alerts")
    assert alerts.status_code == 200
    return alerts.get_json()[0]["id"]


def test_soc_app_can_read_insert_but_cannot_mutate_audit_events(world):
    conn = psycopg.connect(os.environ["DATABASE_URL"])
    try:
        assert conn.execute("SELECT current_user").fetchone()[0] == "soc_app"
        privileges = conn.execute(
            "SELECT has_table_privilege(current_user, 'public.audit_events', 'SELECT'), "
            "has_table_privilege(current_user, 'public.audit_events', 'INSERT'), "
            "has_table_privilege(current_user, 'public.audit_events', 'UPDATE'), "
            "has_table_privilege(current_user, 'public.audit_events', 'DELETE'), "
            "has_table_privilege(current_user, 'public.audit_events', 'TRUNCATE')").fetchone()
        assert privileges == (True, True, False, False, False)
        assert conn.execute("SELECT count(*) FROM audit_events").fetchone()[0] == 0

        for sql in (
            "UPDATE audit_events SET action = action",
            "DELETE FROM audit_events",
            "TRUNCATE audit_events",
        ):
            with pytest.raises(errors.InsufficientPrivilege):
                with conn.transaction():
                    conn.execute(sql)

        triggers = {
            row[0] for row in conn.execute(
                "SELECT tgname FROM pg_trigger WHERE tgrelid='audit_events'::regclass AND NOT tgisinternal"
            ).fetchall()
        }
        assert {"audit_events_no_update_delete", "audit_events_no_truncate"} <= triggers
    finally:
        conn.close()


def test_ack_and_verdict_require_sessions_and_record_the_authenticated_actors(world):
    alert_id = _make_alert(world)
    unauthenticated = world.client
    assert unauthenticated.post(f"/api/alerts/{alert_id}/ack").status_code == 401
    assert unauthenticated.post(
        f"/api/alerts/{alert_id}/verdict", json={"verdict": "tp"}).status_code == 401
    # The ingest/alert flow and denied unauthenticated attempts are audited, but
    # neither rejected request may create a triage mutation audit record.
    assert _owner_rows(
        world,
        "SELECT count(*) FROM audit_events WHERE resource_id=%s AND action IN ('alert.ack', 'alert.verdict')",
        (str(alert_id),),
    )[0][0] == 0

    l1 = Api(world, CITY, "l1")
    l2 = Api(world, CITY, "l2")
    assert l1.post(f"/api/alerts/{alert_id}/ack").status_code == 200
    assert l2.post(
        f"/api/alerts/{alert_id}/verdict", json={"verdict": "tp", "note": "reviewed"}).status_code == 200

    l1_actor = _owner_rows(
        world, "SELECT id FROM users WHERE tenant=%s AND username='analyst-l1'", (CITY,))[0][0]
    l2_actor = _owner_rows(
        world, "SELECT id FROM users WHERE tenant=%s AND username='analyst-l2'", (CITY,))[0][0]
    alert = _owner_rows(
        world,
        "SELECT acknowledged_by, acknowledged_at, verdict_by, verdict_at, verdict "
        "FROM alerts WHERE id=%s AND tenant=%s",
        (alert_id, CITY))[0]
    assert alert[0] == l1_actor and alert[1] is not None
    assert alert[2] == l2_actor and alert[3] is not None and alert[4] == "tp"

    events = _owner_rows(
        world,
        "SELECT actor_id, actor_role, auth_context, break_glass_grant_id, action, resource_type, "
        "resource_id, resource_classification, outcome, metadata, request_id, occurred_at "
        "FROM audit_events WHERE tenant_id=%s AND resource_id=%s ORDER BY action",
        (CITY, str(alert_id)))
    assert len(events) == 2
    by_action = {row[4]: row for row in events}
    ack = by_action["alert.ack"]
    verdict = by_action["alert.verdict"]
    assert ack[0:4] == (l1_actor, "l1", "session", None)
    assert verdict[0:4] == (l2_actor, "l2", "session", None)
    assert ack[5:10] == ("alert", str(alert_id), "telemetry", "allow", {"status": "ack"})
    assert verdict[5:10] == ("alert", str(alert_id), "telemetry", "allow", {"verdict": "tp"})
    assert ack[10] and verdict[10] and ack[10] != verdict[10]
    assert ack[11] is not None and verdict[11] is not None
    assert all("reviewed" not in str(row[9]) for row in events)


def test_audit_metadata_strictly_drops_unapproved_secrets_and_phi():
    assert soc.redact_audit_metadata({
        "verdict": "fp",
        "status": "closed",
        "password": "secret",
        "authorization": "Bearer token",
        "patient_name": "Example Patient",
        "mrn": "12345",
        "note": "clinical notes",
        "custom": "arbitrary free text",
    }) == {"status": "closed", "verdict": "fp"}
