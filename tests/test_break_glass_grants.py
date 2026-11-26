"""Hospital-approved, time-limited vendor break-glass integration tests."""
import psycopg

from support import Api, CITY, ORTHO


def _owner_rows(world, sql, params=()):
    with psycopg.connect(world.owner_url) as owner:
        return owner.execute(sql, params).fetchall()


def _request(world, tenant=CITY, scope="events:read", ttl=30):
    vendor = Api(world, "platform", "vendor_admin")
    return vendor.post("/api/break-glass/grants", json={
        "tenant_id": tenant,
        "ticket_id": "INC-2026-1234",
        "reason": "Investigate a reported telemetry delivery failure.",
        "scope": scope,
        "ttl_minutes": ttl,
    })


def test_vendor_break_glass_approval_scope_audit_revoke_and_review(world):
    vendor = Api(world, "platform", "vendor_admin")
    assert vendor.get(f"/api/events?tenant_id={CITY}").status_code == 403

    requested = _request(world, scope="events:read", ttl=60)
    assert requested.status_code == 201, requested.get_json()
    grant = requested.get_json()
    grant_id = grant["grant_id"]
    assert grant["state"] == "pending"
    assert grant["ticket_id"] == "INC-2026-1234"
    assert grant["scope"] == "events:read"

    admin = Api(world, CITY, "hospital_admin")
    listed = admin.get("/api/break-glass/grants")
    assert listed.status_code == 200
    assert any(item["grant_id"] == grant_id for item in listed.get_json()["grants"])

    approved = admin.post(f"/api/break-glass/grants/{grant_id}/approve")
    assert approved.status_code == 200, approved.get_json()
    alert = _owner_rows(
        world,
        "SELECT severity, rule, source FROM alerts WHERE id=%s AND tenant=%s",
        (approved.get_json()["alert_id"], CITY),
    )[0]
    assert alert == ("critical", "VENDOR_BREAK_GLASS_ACTIVATED", "security")

    events = vendor.get(f"/api/events?tenant_id={CITY}")
    assert events.status_code == 200, events.get_json()
    # An events-only grant cannot be used for alert or handoff reads.
    assert vendor.get(f"/api/alerts?tenant_id={CITY}").status_code == 403

    audit_rows = _owner_rows(
        world,
        "SELECT action, actor_id, tenant_id, auth_context, break_glass_grant_id, outcome, metadata "
        "FROM audit_events WHERE break_glass_grant_id=%s ORDER BY audit_id",
        (grant_id,),
    )
    assert any(row[0] == "break_glass.activate" and row[2] == CITY and row[5] == "allow"
               and row[6] == {"scope": "events:read", "priority": "high"} for row in audit_rows)
    access_rows = [row for row in audit_rows if row[0] in ("break_glass.access", "event.read")]
    assert len(access_rows) == 2
    assert all(row[2] == CITY and row[3] == "break_glass" and row[4] is not None
               and row[5] == "allow" for row in access_rows)
    vendor_actor = _owner_rows(
        world, "SELECT id FROM users WHERE tenant IS NULL AND username='vendor'")[0][0]
    assert any(row[0] == "break_glass.access" and row[1] == vendor_actor for row in access_rows)

    revoked = admin.post(f"/api/break-glass/grants/{grant_id}/revoke")
    assert revoked.status_code == 200
    assert vendor.get(f"/api/events?tenant_id={CITY}").status_code == 403

    reviewed = admin.post(f"/api/break-glass/grants/{grant_id}/review")
    assert reviewed.status_code == 200
    assert reviewed.get_json()["grant"]["state"] == "revoked"
    review_row = _owner_rows(
        world, "SELECT reviewed_by, reviewed_at FROM break_glass_grants WHERE grant_id=%s",
        (grant_id,),
    )[0]
    admin_actor = _owner_rows(
        world, "SELECT id FROM users WHERE tenant=%s AND username='admin'", (CITY,))[0][0]
    assert review_row[0] == admin_actor and review_row[1] is not None


def test_vendor_grant_ttl_and_scope_validation_and_expiry_are_enforced(world):
    vendor = Api(world, "platform", "vendor_admin")
    too_long = _request(world, scope="events:read", ttl=61)
    assert too_long.status_code == 400
    bad_scope = _request(world, scope="credentials:read", ttl=30)
    assert bad_scope.status_code == 400

    requested = _request(world, tenant=ORTHO, scope="metrics:read", ttl=30)
    assert requested.status_code == 201
    grant_id = requested.get_json()["grant_id"]

    city_admin = Api(world, CITY, "hospital_admin")
    assert city_admin.post(f"/api/break-glass/grants/{grant_id}/approve").status_code == 404
    assert city_admin.post(f"/api/break-glass/grants/{grant_id}/revoke").status_code == 404

    ortho_admin = Api(world, ORTHO, "hospital_admin")
    assert ortho_admin.post(f"/api/break-glass/grants/{grant_id}/approve").status_code == 200
    with psycopg.connect(world.owner_url) as owner:
        owner.execute(
            "UPDATE break_glass_grants SET expires_at=now()-interval '1 second' WHERE grant_id=%s",
            (grant_id,),
        )
    assert vendor.get(f"/api/metrics?tenant_id={ORTHO}").status_code == 403
