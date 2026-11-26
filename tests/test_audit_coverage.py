"""Integration coverage for PR 7 audit emission and transaction boundaries."""
import os
import uuid

import psycopg

import app as soc
from support import Api, CITY, PASSWORD, failed_logins


def _owner_rows(world, sql, params=()):
    with psycopg.connect(world.owner_url) as owner:
        return owner.execute(sql, params).fetchall()


def _seed_alert(world):
    result = Api(world, CITY, "l1").post("/api/events", json=failed_logins(CITY))
    assert result.status_code == 200
    alert = Api(world, CITY, "l1").get("/api/alerts").get_json()[0]
    return alert["id"]


def _audit(world, action, resource_id=None):
    if resource_id is None:
        return _owner_rows(
            world, "SELECT audit_id, tenant_id, actor_id, actor_role, auth_context, action, "
            "resource_type, resource_id, resource_classification, outcome, metadata, request_id "
            "FROM audit_events WHERE action=%s ORDER BY audit_id", (action,))
    return _owner_rows(
        world, "SELECT audit_id, tenant_id, actor_id, actor_role, auth_context, action, "
        "resource_type, resource_id, resource_classification, outcome, metadata, request_id "
        "FROM audit_events WHERE action=%s AND resource_id=%s ORDER BY audit_id",
        (action, str(resource_id)))


def test_auth_fail_ingest_and_sensitive_reads_are_audited(world):
    alert_id = _seed_alert(world)
    l1 = Api(world, CITY, "l1")
    admin = Api(world, CITY, "hospital_admin")

    assert l1.get("/api/events").status_code == 200
    assert l1.get(f"/api/alerts/{alert_id}").status_code == 200
    assert admin.get("/api/credentials").status_code == 200

    ingest = _audit(world, "event.ingest")
    alert_created = _audit(world, "alert.create", alert_id)
    event_read = _audit(world, "event.read")
    detail_read = _audit(world, "alert.detail.read", alert_id)
    credential_read = _audit(world, "credential.list")
    assert ingest and alert_created and event_read and detail_read and credential_read

    assert ingest[-1][1:6] == (CITY, None, "ingest", "ingest_key", "event.ingest")
    assert ingest[-1][9] == "allow"
    assert ingest[-1][10]["record_count"] == 5
    assert alert_created[-1][2:5] == (None, "ingest", "ingest_key")
    assert event_read[-1][2:5] == (
        _owner_rows(world, "SELECT id FROM users WHERE tenant=%s AND username='analyst-l1'", (CITY,))[0][0],
        "l1", "session")
    assert detail_read[-1][8:10] == ("telemetry", "allow")
    assert credential_read[-1][8:10] == ("credential_metadata", "allow")
    assert all(row[-1] for rows in (ingest, alert_created, event_read, detail_read, credential_read) for row in rows)
    for rows in (ingest, alert_created, event_read, detail_read, credential_read):
        for row in rows:
            assert not ({"password", "token", "key", "patient", "mrn", "clinical"} & set(row[10]))


def test_user_creation_role_change_disable_and_denial_are_audited(world):
    admin = Api(world, CITY, "hospital_admin")
    username = f"audit-{uuid.uuid4().hex[:8]}"
    email = f"{username}@example.invalid"
    created = admin.post("/api/users", json={
        "username": username, "email": email, "role": "l1", "password": PASSWORD})
    assert created.status_code == 201
    user_id = created.get_json()["id"]

    changed = admin.patch(f"/api/users/{user_id}", json={"role": "l2"})
    assert changed.status_code == 200 and changed.get_json()["token_version_advanced"] is True
    disabled = admin.post(f"/api/users/{user_id}/disable")
    assert disabled.status_code == 200
    row = _owner_rows(
        world, "SELECT role, status, is_active, token_version FROM users WHERE id=%s", (user_id,))[0]
    assert row == ("l2", "disabled", False, 2)

    l1_actor = _owner_rows(
        world, "SELECT id FROM users WHERE tenant=%s AND username='admin'", (CITY,))[0][0]
    assert _audit(world, "user.create", user_id)[-1][3:5] == ("hospital_admin", "session")
    role_event = _audit(world, "user.role.change", user_id)[-1]
    assert role_event[2] == l1_actor and role_event[10] == {"previous_role": "l1", "new_role": "l2"}
    disable_event = _audit(world, "user.disable", user_id)[-1]
    assert disable_event[10] == {"status": "disabled", "token_version_advanced": True}

    assert Api(world, CITY, "hospital_admin").get("/api/users").status_code == 200
    assert _audit(world, "user.list")
    denied = Api(world, CITY, "viewer").get("/api/users")
    assert denied.status_code == 403
    deny_event = _audit(world, "authorization.denied")[-1]
    viewer_actor = _owner_rows(
        world, "SELECT id FROM users WHERE tenant=%s AND username='analyst-viewer'", (CITY,))[0][0]
    assert deny_event[1:5] == (CITY, viewer_actor, "viewer", "session")
    assert deny_event[9] == "deny"


def test_credential_create_rotate_and_revoke_are_audited_without_recording_keys(world):
    admin = Api(world, CITY, "hospital_admin")
    source_id = admin.get("/api/log-sources").get_json()[0]["id"]
    created = admin.post("/api/credentials", json={"log_source_id": source_id, "label": "audit-test"})
    assert created.status_code == 201
    first = created.get_json()

    rotated = admin.post(f"/api/credentials/{first['id']}/rotate")
    assert rotated.status_code == 201
    second = rotated.get_json()
    assert second["id"] != first["id"] and second["key"] != first["key"]
    assert admin.post(f"/api/credentials/{second['id']}/revoke").status_code == 200

    old = _owner_rows(world, "SELECT revoked_at FROM ingest_keys WHERE id=%s", (first["id"],))[0][0]
    new = _owner_rows(world, "SELECT revoked_at FROM ingest_keys WHERE id=%s", (second["id"],))[0][0]
    assert old is not None and new is not None

    created_event = _audit(world, "credential.create", first["id"])[-1]
    rotation_event = _audit(world, "credential.rotate", second["id"])[-1]
    revoked_event = _audit(world, "credential.revoke", second["id"])[-1]
    assert created_event[9] == rotation_event[9] == revoked_event[9] == "allow"
    assert rotation_event[10] == {
        "previous_credential_id": first["id"],
        "new_credential_id": second["id"],
        "log_source_id": source_id,
    }
    for event in (created_event, rotation_event, revoked_event):
        encoded = str(event[10])
        assert first["key"] not in encoded and second["key"] not in encoded


def test_triage_handoff_verdict_and_approval_decision_are_audited(world):
    alert_id = _seed_alert(world)
    l1 = Api(world, CITY, "l1")
    l2 = Api(world, CITY, "l2")
    admin = Api(world, CITY, "hospital_admin")

    alert = l1.get(f"/api/alerts/{alert_id}").get_json()
    new_owner = next(name for name in ("analyst1", "analyst2", "analyst3") if name != alert["owner"])
    assert l1.post(f"/api/alerts/{alert_id}/ack").status_code == 200
    assert l1.post(f"/api/alerts/{alert_id}/handoff", json={"to_owner": new_owner}).status_code == 200
    request = l1.post(f"/api/alerts/{alert_id}/response-approvals", json={
        "action": "isolate_host", "target": "test-host", "reason": "Audit coverage test"})
    assert request.status_code == 201
    approval_id = request.get_json()["id"]
    assert l2.post(f"/api/response-approvals/{approval_id}/decision",
                   json={"decision": "approved"}).status_code == 200
    assert l2.post(f"/api/alerts/{alert_id}/verdict",
                   json={"verdict": "tp", "note": "do not copy into audit metadata"}).status_code == 200

    ack = _audit(world, "alert.ack", alert_id)[-1]
    handoff = _audit(world, "alert.handoff", alert_id)[-1]
    verdict = _audit(world, "alert.verdict", alert_id)[-1]
    requested = _audit(world, "response_approval.request", approval_id)[-1]
    decided = _audit(world, "response_approval.decision", approval_id)[-1]

    assert ack[9] == handoff[9] == verdict[9] == requested[9] == decided[9] == "allow"
    assert ack[10] == {"previous_status": "new", "status": "ack"}
    assert handoff[10] == {"owner_from": alert["owner"], "owner_to": new_owner}
    assert verdict[10] == {"previous_verdict": None, "new_verdict": "tp"}
    assert requested[10] == {"response_action": "isolate_host", "status": "pending"}
    assert decided[10] == {"response_action": "isolate_host", "decision": "approved"}
    assert "do not copy" not in str(verdict[10])


def test_cross_tenant_denial_is_audited_and_missing_mutation_has_no_allow_event(world):
    alert_id = _seed_alert(world)
    other_alert = _owner_rows(
        world, "SELECT id FROM alerts WHERE tenant='ortho-clinic' ORDER BY id DESC LIMIT 1")
    if not other_alert:
        # Seed the second tenant through its own ingest key.
        Api(world, "ortho-clinic", "l1").post(
            "/api/events", json=failed_logins("ortho-clinic"))
        other_alert = _owner_rows(
            world, "SELECT id FROM alerts WHERE tenant='ortho-clinic' ORDER BY id DESC LIMIT 1")
    other_alert_id = other_alert[0][0]
    assert Api(world, CITY, "hospital_admin").post(f"/api/alerts/{other_alert_id}/ack").status_code == 404
    denied = _audit(world, "authorization.denied", other_alert_id)[-1]
    assert denied[1] == CITY and denied[9] == "deny"

    missing_id = _owner_rows(world, "SELECT COALESCE(MAX(id), 0) + 100000 FROM ingest_keys")[0][0]
    response = Api(world, CITY, "hospital_admin").post(f"/api/credentials/{missing_id}/revoke")
    assert response.status_code == 404
    assert not _audit(world, "credential.revoke", missing_id)


def test_audit_insert_failure_rolls_back_credential_mutation(monkeypatch, world):
    admin = Api(world, CITY, "hospital_admin")
    source_id = admin.get("/api/log-sources").get_json()[0]["id"]
    created = admin.post("/api/credentials", json={"log_source_id": source_id, "label": "rollback-test"})
    assert created.status_code == 201
    key_id = created.get_json()["id"]

    def fail_audit_insert(db_session, **kwargs):
        db_session.execute(
            "INSERT INTO audit_events(tenant_id, actor_id, actor_role, auth_context, action, resource_type, "
            "resource_classification, outcome, request_id) "
            "VALUES (%s, %s, %s, %s, 'credential.revoke', 'ingest_key', 'credential_metadata', "
            "'invalid-outcome', 'forced-audit-failure')",
            (kwargs["tenant_id"], kwargs["actor_id"], kwargs["actor_role"], kwargs["auth_context"]))
    monkeypatch.setattr(soc, "record_audit_event", fail_audit_insert)

    try:
        response = admin.post(f"/api/credentials/{key_id}/revoke")
    except psycopg.Error:
        pass
    else:
        assert response.status_code >= 500

    assert _owner_rows(world, "SELECT revoked_at FROM ingest_keys WHERE id=%s", (key_id,))[0][0] is None
    assert not _audit(world, "credential.revoke", key_id)
