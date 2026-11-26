"""Tenant isolation enforced by PostgreSQL itself, with the connection as the runtime role soc_app.

These tests never connect as the owner (soc) for an access check. The owner is used only to seed data
and to read the result of a write. Every check runs in its own transaction and is rolled back.
"""
import os

import psycopg
import pytest
from psycopg import errors

import manage
from support import Api, CITY, ORTHO, failed_logins

HOSPITAL_TABLES = ("events", "alerts", "handoffs", "response_approvals")
ADMIN_TABLES = ("users", "ingest_keys", "log_sources")


@pytest.fixture
def runtime(world):
    """A connection as soc_app with no identity set yet. Refuses to run as anything else."""
    conn = psycopg.connect(os.environ["DATABASE_URL"])
    role = conn.execute("SELECT current_user").fetchone()[0]
    assert role == "soc_app", f"tests must connect as soc_app, not {role}"
    yield conn
    conn.rollback()
    conn.close()


def as_identity(conn, tenant, role, actor=None):
    conn.execute("SELECT set_config('app.tenant_id', %s, true), set_config('app.role', %s, true), "
                 "set_config('app.actor_id', %s, true)",
                 (tenant or "", role or "", "" if actor is None else str(actor)))


def count(conn, table, tenant):
    return conn.execute(f"SELECT count(*) FROM {table} WHERE tenant = %s", (tenant,)).fetchone()[0]


def actor_id(world, tenant, username):
    with psycopg.connect(world.owner_url) as owner:
        return owner.execute("SELECT id FROM users WHERE tenant=%s AND username=%s", (tenant, username)).fetchone()[0]


@pytest.fixture(scope="module")
def data(world):
    """One alert, one event and one handoff for each hospital, written through the API as the ingest keys."""
    world.client.post("/api/reset", headers=world.vendor())
    for tenant in (CITY, ORTHO):
        world.client.post("/api/events", json=failed_logins(tenant), headers=world.ingest(tenant))
    alert = Api(world, ORTHO, "viewer").get(f"/api/alerts?tenant={ORTHO}").get_json()[0]
    Api(world, ORTHO, "l1").post(f"/api/alerts/{alert['id']}/handoff", json={"to_owner": "analyst2"})
    approval = Api(world, ORTHO, "l1").post(f"/api/alerts/{alert['id']}/response-approvals", json={
        "action": "isolate_host", "target": "ehr-01", "reason": "Test RLS visibility"})
    assert approval.status_code == 201
    return True


# ---- The runtime connection ------------------------------------------------------------------------

def test_runtime_role_cannot_bypass_rls_or_administer(runtime):
    row = runtime.execute("SELECT rolsuper, rolbypassrls, rolcreaterole, rolcreatedb, rolinherit "
                          "FROM pg_roles WHERE rolname = current_user").fetchone()
    assert row == (False, False, False, False, False)


def test_runtime_role_cannot_change_the_schema_or_truncate(runtime):
    for sql in ("CREATE TABLE evil(id int)", "TRUNCATE events", "DROP POLICY events_read ON events",
                "ALTER TABLE events DISABLE ROW LEVEL SECURITY"):
        with pytest.raises(errors.InsufficientPrivilege):
            with runtime.transaction():
                runtime.execute(sql)


def test_runtime_role_cannot_rewrite_audit_or_revoke_grants(runtime):
    as_identity(runtime, CITY, "hospital_admin", 1)
    for sql in ("UPDATE audit_log SET action = 'x'", "DELETE FROM audit_log",
                "DELETE FROM break_glass_grants", "INSERT INTO break_glass_grants(actor_id, tenant, reason, granted_by, expires_at) "
                "VALUES (1, 'city-hospital', 'x', 'x', now())"):
        with pytest.raises(errors.InsufficientPrivilege):
            with runtime.transaction():
                runtime.execute(sql)


# ---- No identity set: fail closed ------------------------------------------------------------------

def test_unset_context_sees_no_rows(runtime, data):
    for table in HOSPITAL_TABLES + ADMIN_TABLES + ("tenants", "sessions"):
        assert runtime.execute(f"SELECT count(*) FROM {table}").fetchone()[0] == 0, table


def test_unset_context_cannot_write(runtime, data, world):
    with pytest.raises(errors.InsufficientPrivilege):
        with runtime.transaction():
            runtime.execute("INSERT INTO events(ts, tenant, type) VALUES ('2026-11-25T10:00:00', %s, 'x')", (CITY,))
    with pytest.raises(errors.InsufficientPrivilege):
        with runtime.transaction():
            runtime.execute("INSERT INTO alerts(tenant, rule) VALUES (%s, 'R')", (CITY,))
    alert_id = Api(world, CITY, "viewer").get("/api/alerts").get_json()[0]["id"]
    requester = actor_id(world, CITY, "analyst-l1")
    with pytest.raises(errors.InsufficientPrivilege):
        with runtime.transaction():
            runtime.execute("INSERT INTO response_approvals(tenant, alert_id, action, target, reason, requested_by) "
                            "VALUES (%s, %s, 'isolate_host', 'ehr-01', 'no context', %s)",
                            (CITY, alert_id, requester))
    assert runtime.execute("UPDATE alerts SET status = 'closed'").rowcount == 0


def test_empty_context_is_the_same_as_unset(runtime, data):
    as_identity(runtime, "", "", None)
    assert runtime.execute("SELECT count(*) FROM alerts").fetchone()[0] == 0


# ---- Hospital A's roles, looking at hospital B -----------------------------------------------------

@pytest.mark.parametrize("role", ["hospital_admin", "l1", "l2", "viewer"])
def test_hospital_role_sees_none_of_another_hospitals_rows(runtime, data, role):
    as_identity(runtime, CITY, role, 1)
    for table in HOSPITAL_TABLES:
        assert count(runtime, table, ORTHO) == 0, table
    assert count(runtime, "alerts", CITY) >= 1


@pytest.mark.parametrize("role", ["hospital_admin", "l1"])
def test_hospital_role_cannot_change_another_hospitals_alerts(runtime, data, role):
    as_identity(runtime, CITY, role, 1)
    assert runtime.execute("UPDATE alerts SET status = 'ack' WHERE tenant = %s", (ORTHO,)).rowcount == 0
    assert runtime.execute("UPDATE alerts SET status = 'closed' WHERE tenant = %s", (ORTHO,)).rowcount == 0
    assert runtime.execute("DELETE FROM alerts WHERE tenant = %s", (ORTHO,)).rowcount == 0


def test_hospital_role_cannot_write_into_another_hospital(runtime, data):
    as_identity(runtime, CITY, "l1", 1)
    with pytest.raises(errors.InsufficientPrivilege):
        with runtime.transaction():
            runtime.execute("INSERT INTO handoffs(alert_id, at, from_owner, to_owner, note, tenant) "
                            "VALUES (1, '2026-11-25T10:00:00', 'a', 'b', '', %s)", (ORTHO,))
    with pytest.raises(errors.InsufficientPrivilege):
        with runtime.transaction():
            runtime.execute("INSERT INTO alerts(tenant, rule) VALUES (%s, 'R')", (ORTHO,))


def test_hospital_role_cannot_move_its_own_alert_to_another_hospital(runtime, data):
    as_identity(runtime, CITY, "hospital_admin", 1)
    with pytest.raises(errors.InsufficientPrivilege):
        with runtime.transaction():
            runtime.execute("UPDATE alerts SET tenant = %s WHERE tenant = %s", (ORTHO, CITY))


@pytest.mark.parametrize("role", ["hospital_admin", "l1", "viewer"])
def test_only_the_hospital_admin_sees_credentials_and_users(runtime, data, role):
    as_identity(runtime, CITY, role, 1)
    if role == "hospital_admin":
        assert count(runtime, "ingest_keys", CITY) >= 1
        assert count(runtime, "users", CITY) >= 1
    else:
        assert runtime.execute("SELECT count(*) FROM users").fetchone()[0] == 0
        assert runtime.execute("SELECT count(*) FROM ingest_keys").fetchone()[0] == 0


def test_hospital_admin_cannot_read_or_change_another_hospitals_users_or_keys(runtime, data):
    as_identity(runtime, CITY, "hospital_admin", 1)
    assert count(runtime, "users", ORTHO) == 0
    assert count(runtime, "ingest_keys", ORTHO) == 0
    assert count(runtime, "log_sources", ORTHO) == 0
    assert runtime.execute("UPDATE users SET status = 'disabled' WHERE tenant = %s", (ORTHO,)).rowcount == 0
    assert runtime.execute("UPDATE ingest_keys SET revoked_at = now() WHERE tenant = %s", (ORTHO,)).rowcount == 0
    with pytest.raises(errors.InsufficientPrivilege):
        with runtime.transaction():
            runtime.execute("INSERT INTO users(tenant, username, role, password_hash) VALUES (%s, 'x', 'l1', 'x')", (ORTHO,))


def test_hospital_admin_cannot_read_another_hospitals_tenant_row(runtime, data):
    as_identity(runtime, CITY, "hospital_admin", 1)
    names = {r[0] for r in runtime.execute("SELECT id FROM tenants").fetchall()}
    assert names == {CITY}


# ---- Ingest key role ------------------------------------------------------------------------------

def test_ingest_role_writes_its_own_hospital_only(runtime, data):
    as_identity(runtime, CITY, "ingest", None)
    runtime.execute("INSERT INTO events(ts, tenant, type) VALUES ('2026-11-25T10:00:00', %s, 'auth_fail')", (CITY,))
    with pytest.raises(errors.InsufficientPrivilege):
        with runtime.transaction():
            runtime.execute("INSERT INTO events(ts, tenant, type) VALUES ('2026-11-25T10:00:00', %s, 'auth_fail')", (ORTHO,))


def test_l2_cannot_approve_own_response_request_inside_postgres(runtime, world, data):
    requester = actor_id(world, CITY, "analyst-l2")
    alert_id = Api(world, CITY, "viewer").get("/api/alerts").get_json()[0]["id"]
    as_identity(runtime, CITY, "l2", requester)
    approval_id = runtime.execute(
        "INSERT INTO response_approvals(tenant, alert_id, action, target, reason, requested_by) "
        "VALUES (%s, %s, 'block_ip', '203.0.113.77', 'test self approval policy', %s) RETURNING id",
        (CITY, alert_id, requester)).fetchone()[0]
    changed = runtime.execute(
        "UPDATE response_approvals SET status='approved', approved_by=%s, decided_at=now() WHERE id=%s",
        (requester, approval_id)).rowcount
    assert changed == 0


def test_ingest_role_cannot_read_users_credentials_or_change_history(runtime, data):
    as_identity(runtime, CITY, "ingest", None)
    assert runtime.execute("SELECT count(*) FROM users").fetchone()[0] == 0
    assert runtime.execute("SELECT count(*) FROM ingest_keys").fetchone()[0] == 0
    assert runtime.execute("UPDATE events SET type = 'x'").rowcount == 0
    assert runtime.execute("DELETE FROM events").rowcount == 0


# ---- Vendor admin --------------------------------------------------------------------------------

def test_vendor_without_a_grant_reads_no_hospital_rows(runtime, world, data):
    vendor = vendor_actor()
    # Other break-glass tests use this same fixture database. Revoke any leftover grants
    # so this test checks the no-grant policy regardless of test execution order.
    with psycopg.connect(world.owner_url) as owner:
        owner.execute("UPDATE break_glass_grants SET revoked_at = now() WHERE actor_id = %s AND revoked_at IS NULL",
                      (vendor,))
    for tenant in (CITY, ORTHO):
        as_identity(runtime, tenant, "vendor_admin", vendor)
        for table in HOSPITAL_TABLES + ADMIN_TABLES:
            assert count(runtime, table, tenant) == 0, (tenant, table)


def test_vendor_sees_the_tenant_list_but_no_hospital_data(runtime, data):
    as_identity(runtime, "platform", "vendor_admin", vendor_actor())
    assert runtime.execute("SELECT count(*) FROM tenants").fetchone()[0] >= 3


def test_break_glass_lets_the_vendor_read_one_hospital_and_only_while_valid(runtime, world, data):
    vendor = vendor_actor()
    with psycopg.connect(world.owner_url) as owner:
        grant = manage.grant_break_glass(owner, "vendor", CITY, 1, "INC-RLS-1", "test")
        owner.commit()
    try:
        as_identity(runtime, CITY, "vendor_admin", vendor)
        assert count(runtime, "alerts", CITY) >= 1
        assert count(runtime, "events", CITY) >= 1
        assert runtime.execute("UPDATE alerts SET status = 'closed'").rowcount == 0  # read-only
        assert runtime.execute("SELECT count(*) FROM ingest_keys").fetchone()[0] == 0  # never credentials
        assert runtime.execute("SELECT count(*) FROM response_approvals").fetchone()[0] == 0
        as_identity(runtime, ORTHO, "vendor_admin", vendor)
        assert count(runtime, "alerts", ORTHO) == 0  # the grant is for City only
    finally:
        with psycopg.connect(world.owner_url) as owner:
            owner.execute("UPDATE break_glass_grants SET revoked_at = now() WHERE id = %s", (grant,))
            owner.commit()


def test_expired_break_glass_grant_reads_nothing(runtime, world, data):
    vendor = vendor_actor()
    with psycopg.connect(world.owner_url) as owner:
        grant = manage.grant_break_glass(owner, "vendor", ORTHO, 1, "INC-RLS-2", "test")
        owner.execute("UPDATE break_glass_grants SET expires_at = now() - interval '1 second' WHERE id = %s", (grant,))
        owner.commit()
    as_identity(runtime, ORTHO, "vendor_admin", vendor)
    assert count(runtime, "alerts", ORTHO) == 0


_VENDOR = {}


def vendor_actor():
    """The vendor admin's user id, read once through the owner (seeding only, not an access check)."""
    if "id" not in _VENDOR:
        with psycopg.connect(os.environ["MIGRATE_DATABASE_URL"]) as owner:
            _VENDOR["id"] = owner.execute("SELECT id FROM users WHERE role='vendor_admin'").fetchone()[0]
    return _VENDOR["id"]


# ---- Context does not leak between requests -------------------------------------------------------

def test_identity_ends_with_the_transaction(runtime, data):
    as_identity(runtime, CITY, "hospital_admin", 1)
    assert count(runtime, "alerts", CITY) >= 1
    runtime.commit()
    assert runtime.execute("SELECT app_tenant()").fetchone()[0] is None
    assert runtime.execute("SELECT count(*) FROM alerts").fetchone()[0] == 0


def test_identity_is_dropped_on_rollback(runtime, data):
    as_identity(runtime, ORTHO, "hospital_admin", 1)
    runtime.rollback()
    assert runtime.execute("SELECT app_role()").fetchone()[0] is None


# ---- Break-glass and sessions are per user --------------------------------------------------------

def test_a_user_sees_only_their_own_sessions(runtime, world, data):
    me = actor_id(world, CITY, "admin")
    as_identity(runtime, CITY, "hospital_admin", me)
    mine = runtime.execute("SELECT count(*) FROM sessions").fetchone()[0]
    assert mine >= 1
    as_identity(runtime, CITY, "hospital_admin", me + 1000)  # some other user's id
    assert runtime.execute("SELECT count(*) FROM sessions").fetchone()[0] == 0


# ---- The app's SECURITY DEFINER lookups -----------------------------------------------------------

def test_lookups_work_before_any_identity_is_set(runtime, world, data):
    assert runtime.execute("SELECT count(*) FROM auth_ingest_key(%s)", ("not-a-key-hash",)).fetchone()[0] == 0
    row = runtime.execute("SELECT count(*) FROM auth_user_for_login(%s, %s)", (CITY, "admin")).fetchone()[0]
    assert row == 1

