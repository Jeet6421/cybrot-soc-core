-- SOC Core schema, row-level security and grants.
-- Run by migrate.py as the OWNER role (the schema owner). The app connects as soc_app, which cannot
-- change the schema and cannot bypass RLS. Idempotent: safe to run on every deploy.

-- 1. Runtime role. NOBYPASSRLS is what makes the policies below apply to the app.
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'soc_app') THEN
    CREATE ROLE soc_app LOGIN;
  END IF;
END $$;
ALTER ROLE soc_app LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;

-- 2. Tables. Earlier PRs' tables are kept; new columns are added in place.
CREATE TABLE IF NOT EXISTS tenants(id TEXT PRIMARY KEY, name TEXT NOT NULL,
  created TEXT NOT NULL DEFAULT to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS'));
INSERT INTO tenants(id, name) VALUES ('default', 'Default (lab)') ON CONFLICT DO NOTHING;
-- 'platform' is the vendor's own tenant. Vendor admins log in there. It holds no hospital data.
INSERT INTO tenants(id, name) VALUES ('platform', 'Vendor platform') ON CONFLICT DO NOTHING;

CREATE TABLE IF NOT EXISTS log_sources(id BIGSERIAL PRIMARY KEY, tenant TEXT NOT NULL REFERENCES tenants(id),
  name TEXT NOT NULL, kind TEXT NOT NULL DEFAULT '',
  created TEXT NOT NULL DEFAULT to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS'),
  disabled_at TEXT, UNIQUE (tenant, name));

CREATE TABLE IF NOT EXISTS users(id BIGSERIAL PRIMARY KEY, tenant TEXT NOT NULL REFERENCES tenants(id),
  username TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('hospital_admin', 'l1', 'l2', 'viewer', 'vendor_admin')),
  password_hash TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
  created TEXT NOT NULL DEFAULT to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS'),
  UNIQUE (tenant, username));

-- Ingest keys are the "credentials" of the design doc. Each key is bound to one log source.
CREATE TABLE IF NOT EXISTS ingest_keys(id BIGSERIAL PRIMARY KEY, tenant TEXT NOT NULL REFERENCES tenants(id),
  label TEXT NOT NULL DEFAULT '', key_hash TEXT NOT NULL UNIQUE,
  created TEXT NOT NULL DEFAULT to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS'), revoked_at TEXT);
ALTER TABLE ingest_keys ADD COLUMN IF NOT EXISTS log_source_id BIGINT REFERENCES log_sources(id);

CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY,
  user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created TIMESTAMPTZ NOT NULL DEFAULT now(), expires_at TIMESTAMPTZ NOT NULL);

CREATE TABLE IF NOT EXISTS audit_log(id BIGSERIAL PRIMARY KEY, at TIMESTAMPTZ NOT NULL DEFAULT now(),
  tenant TEXT NOT NULL, actor_id BIGINT, action TEXT NOT NULL, detail TEXT NOT NULL DEFAULT '');

-- Break-glass: a time-limited grant that lets one vendor admin read one hospital's data. Created by a
-- database administrator (manage.py grant-break-glass), never through the API.
CREATE TABLE IF NOT EXISTS break_glass_grants(id BIGSERIAL PRIMARY KEY, actor_id BIGINT NOT NULL REFERENCES users(id),
  tenant TEXT NOT NULL REFERENCES tenants(id), reason TEXT NOT NULL, granted_by TEXT NOT NULL,
  created TIMESTAMPTZ NOT NULL DEFAULT now(), expires_at TIMESTAMPTZ NOT NULL, revoked_at TIMESTAMPTZ);

CREATE TABLE IF NOT EXISTS events(id BIGSERIAL PRIMARY KEY, ts TEXT, tenant TEXT, source TEXT, type TEXT,
  "user" TEXT, host TEXT, ip TEXT, patient TEXT, detail TEXT, attack_id TEXT,
  destination TEXT, data_classification TEXT, destination_approved BOOLEAN,
  src_zone TEXT, dst_zone TEXT, boundary_violation BOOLEAN, approved_change BOOLEAN);
CREATE INDEX IF NOT EXISTS ev_idx ON events(tenant, type, ts);
CREATE INDEX IF NOT EXISTS ev_host_type_idx ON events(tenant, host, type, ts);
ALTER TABLE events ADD COLUMN IF NOT EXISTS destination TEXT;
ALTER TABLE events ADD COLUMN IF NOT EXISTS data_classification TEXT;
ALTER TABLE events ADD COLUMN IF NOT EXISTS destination_approved BOOLEAN;
ALTER TABLE events ADD COLUMN IF NOT EXISTS src_zone TEXT;
ALTER TABLE events ADD COLUMN IF NOT EXISTS dst_zone TEXT;
ALTER TABLE events ADD COLUMN IF NOT EXISTS boundary_violation BOOLEAN;
ALTER TABLE events ADD COLUMN IF NOT EXISTS approved_change BOOLEAN;
ALTER TABLE events ADD COLUMN IF NOT EXISTS log_source_id BIGINT;

CREATE TABLE IF NOT EXISTS alerts(id BIGSERIAL PRIMARY KEY, created TEXT, event_ts TEXT, tenant TEXT, rule TEXT,
  rule_version TEXT, severity TEXT, summary TEXT, dkey TEXT, owner TEXT, step TEXT, status TEXT DEFAULT 'new',
  ack_at TEXT, verdict TEXT, attack_id TEXT, source TEXT DEFAULT 'builtin', detail TEXT);
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS detail TEXT;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS resolution TEXT;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS rule_version TEXT;
CREATE UNIQUE INDEX IF NOT EXISTS users_id_tenant_uidx ON users(id, tenant);
CREATE UNIQUE INDEX IF NOT EXISTS alerts_id_tenant_uidx ON alerts(id, tenant);

CREATE TABLE IF NOT EXISTS handoffs(id BIGSERIAL PRIMARY KEY, alert_id BIGINT, at TEXT, from_owner TEXT,
  to_owner TEXT, note TEXT);
ALTER TABLE handoffs ADD COLUMN IF NOT EXISTS tenant TEXT;
CREATE INDEX IF NOT EXISTS ho_idx ON handoffs(alert_id);

-- Response approvals record a human approval decision. They never execute an action themselves.
CREATE TABLE IF NOT EXISTS response_approvals(
  id BIGSERIAL PRIMARY KEY,
  tenant TEXT NOT NULL REFERENCES tenants(id),
  alert_id BIGINT NOT NULL,
  action TEXT NOT NULL CHECK (action IN ('isolate_host', 'disable_account', 'block_ip')),
  target TEXT NOT NULL,
  reason TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected')),
  requested_by BIGINT NOT NULL,
  requested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  approved_by BIGINT,
  decided_at TIMESTAMPTZ,
  decision_note TEXT NOT NULL DEFAULT '',
  FOREIGN KEY (alert_id, tenant) REFERENCES alerts(id, tenant),
  FOREIGN KEY (requested_by, tenant) REFERENCES users(id, tenant),
  FOREIGN KEY (approved_by, tenant) REFERENCES users(id, tenant),
  CHECK (length(btrim(target)) BETWEEN 1 AND 200),
  CHECK (length(btrim(reason)) BETWEEN 1 AND 500),
  CHECK ((status = 'pending' AND approved_by IS NULL AND decided_at IS NULL)
      OR (status IN ('approved', 'rejected') AND approved_by IS NOT NULL AND decided_at IS NOT NULL))
);
CREATE INDEX IF NOT EXISTS response_approvals_tenant_alert_idx ON response_approvals(tenant, alert_id, id DESC);
CREATE UNIQUE INDEX IF NOT EXISTS response_approvals_one_pending_idx
  ON response_approvals(alert_id, action, target) WHERE status = 'pending';

-- 3. Request context helpers. The app sets these with set_config(..., true), which is transaction-local:
--    they vanish at COMMIT or ROLLBACK, so a pooled connection never carries one request's context into
--    the next. An unset or empty value makes app_tenant() NULL, and NULL matches no row (fail closed).
CREATE OR REPLACE FUNCTION app_tenant() RETURNS text LANGUAGE sql STABLE
  AS $$ SELECT NULLIF(current_setting('app.tenant_id', true), '') $$;
CREATE OR REPLACE FUNCTION app_role() RETURNS text LANGUAGE sql STABLE
  AS $$ SELECT NULLIF(current_setting('app.role', true), '') $$;
CREATE OR REPLACE FUNCTION app_actor_id() RETURNS bigint LANGUAGE sql STABLE
  AS $$ SELECT NULLIF(current_setting('app.actor_id', true), '')::bigint $$;

-- Is there an unrevoked, unexpired break-glass grant for this actor and this hospital? SECURITY DEFINER so
-- that the check does not depend on the caller's row access to break_glass_grants.
CREATE OR REPLACE FUNCTION break_glass_active(p_tenant text) RETURNS boolean
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
  SELECT p_tenant IS NOT NULL AND EXISTS (
    SELECT 1 FROM break_glass_grants g
    WHERE g.tenant = p_tenant AND g.actor_id = app_actor_id()
      AND g.revoked_at IS NULL AND g.expires_at > now())
$$;

-- Lookups that must run before any tenant is known (login, session check, ingest key check).
-- They return one narrow row and run as the owner, so they are the only reads that cross tenants.
CREATE OR REPLACE FUNCTION auth_user_for_login(p_tenant text, p_username text)
  RETURNS TABLE(user_id bigint, user_tenant text, user_role text, user_password_hash text, user_status text)
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
  SELECT u.id, u.tenant, u.role, u.password_hash, u.status
  FROM users u WHERE u.tenant = p_tenant AND u.username = p_username
$$;

CREATE OR REPLACE FUNCTION auth_session(p_token_hash text)
  RETURNS TABLE(user_id bigint, user_tenant text, user_role text, user_name text, user_status text)
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
  SELECT u.id, u.tenant, u.role, u.username, u.status
  FROM sessions s JOIN users u ON u.id = s.user_id
  WHERE s.token_hash = p_token_hash AND s.expires_at > now()
$$;

CREATE OR REPLACE FUNCTION auth_ingest_key(p_key_hash text)
  RETURNS TABLE(key_id bigint, key_tenant text, key_log_source_id bigint)
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
  SELECT k.id, k.tenant, k.log_source_id
  FROM ingest_keys k JOIN log_sources ls ON ls.id = k.log_source_id
  WHERE k.key_hash = p_key_hash AND k.revoked_at IS NULL
    AND ls.disabled_at IS NULL AND ls.tenant = k.tenant
$$;

REVOKE ALL ON FUNCTION auth_user_for_login(text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION auth_session(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION auth_ingest_key(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION break_glass_active(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION auth_user_for_login(text, text) TO soc_app;
GRANT EXECUTE ON FUNCTION auth_session(text) TO soc_app;
GRANT EXECUTE ON FUNCTION auth_ingest_key(text) TO soc_app;
GRANT EXECUTE ON FUNCTION break_glass_active(text) TO soc_app;

-- 4. Row-level security. ENABLE turns RLS on, FORCE makes it apply to the table owner too.
--    Each policy is dropped and created again, so a changed policy takes effect on the next deploy.
ALTER TABLE tenants ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenants FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenants_read ON tenants;
CREATE POLICY tenants_read ON tenants FOR SELECT
  USING (id = app_tenant() OR app_role() = 'vendor_admin');
DROP POLICY IF EXISTS tenants_create ON tenants;
CREATE POLICY tenants_create ON tenants FOR INSERT
  WITH CHECK (app_role() = 'vendor_admin');
DROP POLICY IF EXISTS tenants_update ON tenants;
CREATE POLICY tenants_update ON tenants FOR UPDATE
  USING (id = app_tenant() AND app_role() = 'hospital_admin')
  WITH CHECK (id = app_tenant() AND app_role() = 'hospital_admin');

ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE users FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS users_read ON users;
CREATE POLICY users_read ON users FOR SELECT
  USING (tenant = app_tenant() AND app_role() = 'hospital_admin');
DROP POLICY IF EXISTS users_write ON users;
CREATE POLICY users_write ON users FOR ALL
  USING (tenant = app_tenant() AND app_role() = 'hospital_admin')
  WITH CHECK (tenant = app_tenant() AND app_role() = 'hospital_admin');

ALTER TABLE log_sources ENABLE ROW LEVEL SECURITY;
ALTER TABLE log_sources FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS log_sources_read ON log_sources;
CREATE POLICY log_sources_read ON log_sources FOR SELECT
  USING (tenant = app_tenant() AND app_role() IN ('hospital_admin', 'l1', 'l2', 'viewer'));
DROP POLICY IF EXISTS log_sources_write ON log_sources;
CREATE POLICY log_sources_write ON log_sources FOR ALL
  USING (tenant = app_tenant() AND app_role() = 'hospital_admin')
  WITH CHECK (tenant = app_tenant() AND app_role() = 'hospital_admin');

ALTER TABLE ingest_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE ingest_keys FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS ingest_keys_admin ON ingest_keys;
CREATE POLICY ingest_keys_admin ON ingest_keys FOR ALL
  USING (tenant = app_tenant() AND app_role() = 'hospital_admin')
  WITH CHECK (tenant = app_tenant() AND app_role() = 'hospital_admin');

-- Hospital data. Reads: hospital roles and the ingest key (which needs its own tenant's history for
-- detection). A vendor admin reads only with an active break-glass grant. Nobody updates or deletes events.
ALTER TABLE events ENABLE ROW LEVEL SECURITY;
ALTER TABLE events FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS events_read ON events;
CREATE POLICY events_read ON events FOR SELECT
  USING (tenant = app_tenant() AND (
    app_role() IN ('hospital_admin', 'l1', 'l2', 'viewer', 'ingest')
    OR (app_role() = 'vendor_admin' AND break_glass_active(app_tenant()))));
DROP POLICY IF EXISTS events_ingest ON events;
CREATE POLICY events_ingest ON events FOR INSERT
  WITH CHECK (tenant = app_tenant() AND app_role() = 'ingest');

ALTER TABLE alerts ENABLE ROW LEVEL SECURITY;
ALTER TABLE alerts FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS alerts_read ON alerts;
CREATE POLICY alerts_read ON alerts FOR SELECT
  USING (tenant = app_tenant() AND (
    app_role() IN ('hospital_admin', 'l1', 'l2', 'viewer', 'ingest')
    OR (app_role() = 'vendor_admin' AND break_glass_active(app_tenant()))));
DROP POLICY IF EXISTS alerts_ingest ON alerts;
CREATE POLICY alerts_ingest ON alerts FOR INSERT
  WITH CHECK (tenant = app_tenant() AND app_role() = 'ingest');
DROP POLICY IF EXISTS alerts_triage ON alerts;
CREATE POLICY alerts_triage ON alerts FOR UPDATE
  USING (tenant = app_tenant() AND app_role() IN ('hospital_admin', 'l1', 'l2'))
  WITH CHECK (tenant = app_tenant() AND app_role() IN ('hospital_admin', 'l1', 'l2'));

ALTER TABLE handoffs ENABLE ROW LEVEL SECURITY;
ALTER TABLE handoffs FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS handoffs_read ON handoffs;
CREATE POLICY handoffs_read ON handoffs FOR SELECT
  USING (tenant = app_tenant() AND (
    app_role() IN ('hospital_admin', 'l1', 'l2', 'viewer')
    OR (app_role() = 'vendor_admin' AND break_glass_active(app_tenant()))));
DROP POLICY IF EXISTS handoffs_write ON handoffs;
CREATE POLICY handoffs_write ON handoffs FOR INSERT
  WITH CHECK (tenant = app_tenant() AND app_role() IN ('hospital_admin', 'l1', 'l2'));

ALTER TABLE response_approvals ENABLE ROW LEVEL SECURITY;
ALTER TABLE response_approvals FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS response_approvals_read ON response_approvals;
CREATE POLICY response_approvals_read ON response_approvals FOR SELECT
  USING (tenant = app_tenant() AND app_role() IN ('hospital_admin', 'l1', 'l2'));
DROP POLICY IF EXISTS response_approvals_request ON response_approvals;
CREATE POLICY response_approvals_request ON response_approvals FOR INSERT
  WITH CHECK (tenant = app_tenant()
    AND app_role() IN ('hospital_admin', 'l1', 'l2')
    AND requested_by = app_actor_id()
    AND status = 'pending'
    AND approved_by IS NULL AND decided_at IS NULL);
DROP POLICY IF EXISTS response_approvals_decide ON response_approvals;
CREATE POLICY response_approvals_decide ON response_approvals FOR UPDATE
  USING (tenant = app_tenant()
    AND app_role() IN ('hospital_admin', 'l2')
    AND status = 'pending'
    AND requested_by <> app_actor_id())
  WITH CHECK (tenant = app_tenant()
    AND app_role() IN ('hospital_admin', 'l2')
    AND status IN ('approved', 'rejected')
    AND approved_by = app_actor_id()
    AND decided_at IS NOT NULL);

-- A session belongs to one user. The app only sees and changes its own sessions.
ALTER TABLE sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE sessions FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS sessions_own ON sessions;
CREATE POLICY sessions_own ON sessions FOR ALL
  USING (user_id = app_actor_id())
  WITH CHECK (user_id = app_actor_id());

-- Audit rows are written by the app and read by hospital admins. The app cannot change or delete them.
ALTER TABLE audit_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_log FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS audit_read ON audit_log;
CREATE POLICY audit_read ON audit_log FOR SELECT
  USING (tenant = app_tenant() AND app_role() = 'hospital_admin');
DROP POLICY IF EXISTS audit_write ON audit_log;
CREATE POLICY audit_write ON audit_log FOR INSERT
  WITH CHECK (tenant = app_tenant());

ALTER TABLE break_glass_grants ENABLE ROW LEVEL SECURITY;
ALTER TABLE break_glass_grants FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS break_glass_read ON break_glass_grants;
CREATE POLICY break_glass_read ON break_glass_grants FOR SELECT
  USING (actor_id = app_actor_id() OR (tenant = app_tenant() AND app_role() = 'hospital_admin'));

-- 5. Grants. soc_app gets only what the app uses. No CREATE, no TRUNCATE, no DDL.
GRANT USAGE ON SCHEMA public TO soc_app;
GRANT SELECT, INSERT ON tenants TO soc_app;
GRANT UPDATE (name) ON tenants TO soc_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON users, log_sources, ingest_keys, events, alerts, handoffs, sessions TO soc_app;
GRANT SELECT, INSERT ON audit_log TO soc_app;
GRANT SELECT ON break_glass_grants TO soc_app;
GRANT SELECT, INSERT ON response_approvals TO soc_app;
GRANT UPDATE (status, approved_by, decided_at, decision_note) ON response_approvals TO soc_app;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO soc_app;

