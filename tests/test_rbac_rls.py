"""Tenant isolation enforced by PostgreSQL itself, with the connection as the runtime role soc_app.

These tests never connect as the owner (soc) for an access check. The owner is used only to seed data
and to read the result of a write. Every check runs in its own transaction and is rolled back.
"""
import os

import psycopg
import pytest
from psycopg import errors

import app as soc
from support import (Api, CITY, ORTHO, active_break_glass, failed_logins, request_break_glass,
                     revoke_break_glass)

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
    tenant_value = tenant or ""
    role_value = role or ""
    actor_value = "" if actor is None else str(actor)
    conn.execute("SELECT set_config('app.current_tenant_id', %s, true), "
                 "set_config('app.current_actor_role', %s, true), "
                 "set_config('app.current_actor_id', %s, true), "
                 "set_config('app.tenant_id', %s, true), set_config('app.role', %s, true), "
                 "set_config('app.actor_id', %s, true)",
                 (tenant_value, role_value, actor_value, tenant_value, role_value, actor_value))
def count(conn, table, tenant):
    return conn.execute(f"SELECT count(*) FROM {table} WHERE {TENANT_COLUMN.get(table, 'tenant')} = %s",
                        (tenant,)).fetchone()[0]


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
    Api(world, ORTHO, "l1").post(f"/api/alerts/{alert['id']}/handoff",
                                 json={"to_actor_id": actor_id(world, ORTHO, "analyst-l2")})
    approval = Api(world, ORTHO, "l1").post(f"/api/alerts/{alert['id']}/response-approvals", json={
        "action": "isolate_host", "target": "ehr-01", "reason": "Test RLS visibility"})
    assert approval.status_code == 201
    return True


# ---- The runtime connection ------------------------------------------------------------------------

def test_runtime_role_cannot_bypass_rls_or_administer(runtime):
    row = runtime.execute("SELECT rolsuper, rolbypassrls, rolcreaterole, rolcreatedb, rolinherit, rolreplication "
                          "FROM pg_roles WHERE rolname = current_user").fetchone()
    assert row == (False, False, False, False, False, False)


TENANT_TABLES = ("users", "ingest_keys", "log_sources", "events", "alerts", "handoffs", "response_approvals",
                 "response_jobs")
TENANT_COLUMN = {"response_jobs": "tenant_id"}  # the queue table names its tenant column tenant_id


def test_every_tenant_table_has_rls_enabled_and_forced(runtime):
    rows = runtime.execute(
        "SELECT relname, relrowsecurity, relforcerowsecurity FROM pg_class "
        "WHERE relnamespace = 'public'::regnamespace AND relname = ANY(%s)",
        (list(TENANT_TABLES),)).fetchall()
    assert {row[0] for row in rows} == set(TENANT_TABLES)
    assert all(enabled and forced for _, enabled, forced in rows)


def test_canonical_unset_context_fails_closed_for_all_tenant_tables(runtime, data):
    for table in TENANT_TABLES:
        assert runtime.execute(f"SELECT count(*) FROM {table}").fetchone()[0] == 0, table


def test_spoofed_tenant_inserts_are_rejected(runtime, world, data):
    # Valid payloads and existing foreign keys ensure each failure comes from the tenant policy.
    with psycopg.connect(world.owner_url) as owner:
        ortho_actor = owner.execute(
            "SELECT id FROM users WHERE tenant=%s AND username='admin'", (ORTHO,)).fetchone()[0]
        ortho_alert = owner.execute(
            "SELECT id FROM alerts WHERE tenant=%s ORDER BY id LIMIT 1", (ORTHO,)).fetchone()[0]
    statements = (
        ("INSERT INTO users(tenant, username, email, role, password_hash) "
         "VALUES (%s, 'rls-spoof', 'rls-spoof@example.invalid', 'l1', 'hash')", (ORTHO,)),
        ("INSERT INTO ingest_keys(tenant, label, key_hash) VALUES (%s, 'spoof', 'rls-spoof-key')", (ORTHO,)),
        ("INSERT INTO log_sources(tenant, name, kind) VALUES (%s, 'rls-spoof', 'test')", (ORTHO,)),
        ("INSERT INTO events(ts, tenant, type) VALUES ('2026-11-25T10:00:00', %s, 'auth_fail')", (ORTHO,)),
        ("INSERT INTO alerts(tenant, rule) VALUES (%s, 'RLS_SPOOF')", (ORTHO,)),
        ("INSERT INTO handoffs(alert_id, at, from_owner, to_owner, note, tenant) "
         "VALUES (%s, '2026-11-25T10:00:00', 'a', 'b', '', %s)", (ortho_alert, ORTHO)),
        ("INSERT INTO response_approvals(tenant, alert_id, action, target, reason, requested_by) "
         "VALUES (%s, %s, 'isolate_host', 'ehr-01', 'spoofed tenant test', %s)",
         (ORTHO, ortho_alert, ortho_actor)),
        ("INSERT INTO response_jobs(tenant_id, alert_id, action_type, target_host, idempotency_key, requested_by, "
         "approved_by, approved_at) VALUES (%s, %s, 'isolate_host', 'ehr-01', 'rls-spoof', %s, %s, now())",
         (ORTHO, ortho_alert, ortho_actor, ortho_actor)),
    )
    for sql, params in statements:
        with pytest.raises(errors.InsufficientPrivilege):
            with runtime.transaction():
                runtime.execute(sql, params)
    as_identity(runtime, CITY, "hospital_admin", actor_id(world, CITY, "admin"))
    for sql, params in statements:
        with pytest.raises(errors.InsufficientPrivilege):
            with runtime.transaction():
                runtime.execute(sql, params)


@pytest.mark.parametrize("table", TENANT_TABLES)
def test_hospital_cannot_select_update_or_delete_another_tenant(runtime, world, data, table):
    as_identity(runtime, CITY, "hospital_admin", actor_id(world, CITY, "admin"))
    column = TENANT_COLUMN.get(table, "tenant")
    assert runtime.execute(f"SELECT count(*) FROM {table} WHERE {column} = %s", (ORTHO,)).fetchone()[0] == 0
    if table == "response_jobs":
        # The runtime role cannot change or delete queue rows at all: only the worker's functions do.
        with pytest.raises(errors.InsufficientPrivilege):
            runtime.execute(f"UPDATE {table} SET {column} = {column} WHERE {column} = %s", (ORTHO,))
        with pytest.raises(errors.InsufficientPrivilege):
            runtime.execute(f"DELETE FROM {table} WHERE {column} = %s", (ORTHO,))
        return
    update_column = "status" if table == "response_approvals" else "tenant"
    assert runtime.execute(
        f"UPDATE {table} SET {update_column} = {update_column} WHERE {column} = %s", (ORTHO,)).rowcount == 0
    if table == "response_approvals":
        # soc_app deliberately has no DELETE grant for approval records.
        with pytest.raises(errors.InsufficientPrivilege):
            runtime.execute(f"DELETE FROM {table} WHERE {column} = %s", (ORTHO,))
    else:
        assert runtime.execute(f"DELETE FROM {table} WHERE {column} = %s", (ORTHO,)).rowcount == 0


def test_tenant_leading_indexes_exist(runtime):
    expected = {
        "users": "users_tenant_id_idx",
        "ingest_keys": "ingest_keys_tenant_id_idx",
        "log_sources": "log_sources_tenant_id_idx",
        "events": "ev_idx",
        "alerts": "alerts_tenant_id_idx",
        "handoffs": "handoffs_tenant_alert_id_idx",
        "response_approvals": "response_approvals_tenant_alert_idx",
    }
    rows = runtime.execute(
        "SELECT tablename, indexname, indexdef FROM pg_indexes "
        "WHERE schemaname = 'public' AND indexname = ANY(%s)",
        (list(expected.values()),)).fetchall()
    found = {row[0]: row[2] for row in rows}
    assert set(found) == set(expected)
    for table, index_name in expected.items():
        assert index_name in found[table]
        assert f"ON public.{table} USING btree (tenant" in found[table], found[table]




def test_app_queries_connect_as_soc_app(world):
    with soc.app.test_request_context("/api/me"):
        current_user = soc.db().execute("SELECT current_user").fetchone()[0]
        assert current_user == "soc_app"


def test_app_context_settings_are_transaction_local(world):
    with soc.app.test_request_context("/api/me"):
        conn = soc.db()
        soc.set_context(CITY, "l1", 42)
        settings = conn.execute(
            "SELECT current_setting('app.current_tenant_id', true) AS tenant_id, "
            "current_setting('app.current_actor_id', true) AS actor_id, "
            "current_setting('app.current_actor_role', true) AS actor_role, "
            "current_setting('app.tenant_id', true) AS legacy_tenant_id, "
            "current_setting('app.actor_id', true) AS legacy_actor_id, "
            "current_setting('app.role', true) AS legacy_role").fetchone()
        assert tuple(settings[i] for i in range(6)) == (CITY, "42", "l1", CITY, "42", "l1")
        conn.commit()
        cleared = conn.execute(
            "SELECT current_setting('app.current_tenant_id', true) AS tenant_id, "
            "current_setting('app.current_actor_id', true) AS actor_id, "
            "current_setting('app.current_actor_role', true) AS actor_role, "
            "current_setting('app.tenant_id', true) AS legacy_tenant_id, "
            "current_setting('app.actor_id', true) AS legacy_actor_id, "
            "current_setting('app.role', true) AS legacy_role").fetchone()
        assert all(cleared[i] in (None, "") for i in range(6))


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


def test_pending_grant_reads_nothing(runtime, world, data):
    vendor = vendor_actor()
    request_break_glass(world, CITY, "alerts:read")  # requested, never approved
    try:
        as_identity(runtime, CITY, "vendor_admin", vendor)
        assert count(runtime, "alerts", CITY) == 0
    finally:
        revoke_break_glass(world, CITY)


def test_approved_grant_reads_only_its_scope_and_only_while_valid(runtime, world, data):
    vendor = vendor_actor()
    active_break_glass(world, CITY, "alerts:read")
    try:
        as_identity(runtime, CITY, "vendor_admin", vendor)
        assert count(runtime, "alerts", CITY) >= 1
        assert count(runtime, "events", CITY) == 0  # events:read was not granted
        assert runtime.execute("UPDATE alerts SET status = 'closed'").rowcount == 0  # read-only
        assert runtime.execute("SELECT count(*) FROM ingest_keys").fetchone()[0] == 0  # never credentials
        assert runtime.execute("SELECT count(*) FROM response_approvals").fetchone()[0] == 0
        as_identity(runtime, ORTHO, "vendor_admin", vendor)
        assert count(runtime, "alerts", ORTHO) == 0  # the grant is for City only
    finally:
        revoke_break_glass(world, CITY)


def test_expired_grant_reads_nothing(runtime, world, data):
    vendor = vendor_actor()
    gid = active_break_glass(world, ORTHO, "alerts:read")
    try:
        with psycopg.connect(world.owner_url) as owner:
            owner.execute("UPDATE break_glass_grants SET expires_at = now() - interval '1 second' WHERE grant_id = %s",
                          (gid,))
            owner.commit()
        as_identity(runtime, ORTHO, "vendor_admin", vendor)
        assert count(runtime, "alerts", ORTHO) == 0
    finally:
        revoke_break_glass(world, ORTHO)


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

