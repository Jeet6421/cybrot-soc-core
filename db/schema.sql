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
ALTER ROLE soc_app LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;

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
CREATE INDEX IF NOT EXISTS log_sources_tenant_id_idx ON log_sources(tenant, id);

CREATE TABLE IF NOT EXISTS users(id BIGSERIAL PRIMARY KEY, tenant TEXT NOT NULL REFERENCES tenants(id),
  username TEXT NOT NULL,
  email TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('hospital_admin', 'l1', 'l2', 'viewer', 'vendor_admin')),
  account_type TEXT NOT NULL DEFAULT 'hospital_staff'
    CHECK (account_type IN ('hospital_staff', 'vendor_support', 'external_auditor', 'service_principal')),
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  token_version INTEGER NOT NULL DEFAULT 0 CHECK (token_version >= 0),
  password_hash TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
  created TEXT NOT NULL DEFAULT to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS'),
  UNIQUE (tenant, username));
ALTER TABLE users ADD COLUMN IF NOT EXISTS email TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS account_type TEXT NOT NULL DEFAULT 'hospital_staff';
ALTER TABLE users ADD COLUMN IF NOT EXISTS is_active BOOLEAN NOT NULL DEFAULT TRUE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS token_version INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ALTER COLUMN tenant DROP NOT NULL;
UPDATE users SET email = 'legacy+' || id::text || '@invalid.local' WHERE email IS NULL;
UPDATE users SET account_type = CASE WHEN role = 'vendor_admin' THEN 'vendor_support' ELSE 'hospital_staff' END;
UPDATE users SET is_active = (status = 'active');
UPDATE users SET tenant = NULL WHERE role = 'vendor_admin';
ALTER TABLE users ALTER COLUMN email SET NOT NULL;
CREATE INDEX IF NOT EXISTS users_tenant_id_idx ON users(tenant, id);
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_account_classification_check;
ALTER TABLE users ADD CONSTRAINT users_account_classification_check CHECK (
  (role = 'vendor_admin' AND account_type = 'vendor_support' AND tenant IS NULL)
  OR (role IN ('hospital_admin', 'l1', 'l2', 'viewer')
      AND account_type IN ('hospital_staff', 'external_auditor', 'service_principal') AND tenant IS NOT NULL));
CREATE UNIQUE INDEX IF NOT EXISTS users_email_uidx ON users(lower(email));

-- Ingest keys are the "credentials" of the design doc. Each key is bound to one log source.
CREATE TABLE IF NOT EXISTS ingest_keys(id BIGSERIAL PRIMARY KEY, tenant TEXT NOT NULL REFERENCES tenants(id),
  label TEXT NOT NULL DEFAULT '', key_hash TEXT NOT NULL UNIQUE,
  created TEXT NOT NULL DEFAULT to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS'), revoked_at TEXT);
ALTER TABLE ingest_keys ADD COLUMN IF NOT EXISTS log_source_id BIGINT REFERENCES log_sources(id);
CREATE INDEX IF NOT EXISTS ingest_keys_tenant_id_idx ON ingest_keys(tenant, id);

CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY,
  user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_version INTEGER NOT NULL,
  created TIMESTAMPTZ NOT NULL DEFAULT now(), expires_at TIMESTAMPTZ NOT NULL);
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS token_version INTEGER;
UPDATE sessions s SET token_version = u.token_version FROM users u
  WHERE s.user_id = u.id AND s.token_version IS NULL;
ALTER TABLE sessions ALTER COLUMN token_version SET NOT NULL;

CREATE TABLE IF NOT EXISTS audit_log(id BIGSERIAL PRIMARY KEY, at TIMESTAMPTZ NOT NULL DEFAULT now(),
  tenant TEXT NOT NULL, actor_id BIGINT, action TEXT NOT NULL, detail TEXT NOT NULL DEFAULT '');

-- Append-only, tenant-scoped evidence for authenticated actions. Free-form clinical or credential
-- content must never be placed in metadata; app.py applies a strict metadata allowlist before insert.
CREATE TABLE IF NOT EXISTS audit_events(
  audit_id BIGSERIAL PRIMARY KEY,
  occurred_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  actor_id BIGINT,
  actor_role TEXT NOT NULL,
  auth_context TEXT NOT NULL CHECK (auth_context IN ('session', 'break_glass', 'ingest_key', 'system')),
  break_glass_grant_id UUID,
  action TEXT NOT NULL,
  resource_type TEXT NOT NULL,
  resource_id TEXT,
  resource_classification TEXT NOT NULL,
  outcome TEXT NOT NULL CHECK (outcome IN ('allow', 'deny', 'error')),
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(metadata) = 'object'),
  request_id TEXT NOT NULL,
  source_ip TEXT,
  device_id TEXT
);
CREATE INDEX IF NOT EXISTS audit_events_tenant_time_idx ON audit_events(tenant_id, occurred_at DESC, audit_id DESC);
CREATE INDEX IF NOT EXISTS audit_events_request_id_idx ON audit_events(request_id);

-- Break-glass grants are requested by an individual vendor actor and activated only by the
-- target hospital's administrator. Legacy columns remain for migration compatibility.
CREATE TABLE IF NOT EXISTS break_glass_grants(
  id BIGSERIAL PRIMARY KEY,
  actor_id BIGINT NOT NULL REFERENCES users(id),
  tenant TEXT NOT NULL REFERENCES tenants(id),
  reason TEXT NOT NULL,
  granted_by TEXT NOT NULL,
  created TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at TIMESTAMPTZ NOT NULL,
  revoked_at TIMESTAMPTZ,
  grant_id UUID NOT NULL DEFAULT gen_random_uuid(),
  vendor_actor_id BIGINT REFERENCES users(id),
  tenant_id TEXT REFERENCES tenants(id),
  ticket_id TEXT,
  scope TEXT,
  requested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  approved_by BIGINT REFERENCES users(id),
  approved_at TIMESTAMPTZ,
  reviewed_by BIGINT REFERENCES users(id),
  reviewed_at TIMESTAMPTZ,
  requested_ttl_minutes INTEGER NOT NULL DEFAULT 30
);
ALTER TABLE break_glass_grants ADD COLUMN IF NOT EXISTS grant_id UUID DEFAULT gen_random_uuid();
ALTER TABLE break_glass_grants ADD COLUMN IF NOT EXISTS vendor_actor_id BIGINT REFERENCES users(id);
ALTER TABLE break_glass_grants ADD COLUMN IF NOT EXISTS tenant_id TEXT REFERENCES tenants(id);
ALTER TABLE break_glass_grants ADD COLUMN IF NOT EXISTS ticket_id TEXT;
ALTER TABLE break_glass_grants ADD COLUMN IF NOT EXISTS scope TEXT;
ALTER TABLE break_glass_grants ADD COLUMN IF NOT EXISTS requested_at TIMESTAMPTZ NOT NULL DEFAULT now();
ALTER TABLE break_glass_grants ADD COLUMN IF NOT EXISTS approved_by BIGINT REFERENCES users(id);
ALTER TABLE break_glass_grants ADD COLUMN IF NOT EXISTS approved_at TIMESTAMPTZ;
ALTER TABLE break_glass_grants ADD COLUMN IF NOT EXISTS reviewed_by BIGINT REFERENCES users(id);
ALTER TABLE break_glass_grants ADD COLUMN IF NOT EXISTS reviewed_at TIMESTAMPTZ;
ALTER TABLE break_glass_grants ADD COLUMN IF NOT EXISTS requested_ttl_minutes INTEGER NOT NULL DEFAULT 30;
UPDATE break_glass_grants SET vendor_actor_id=actor_id WHERE vendor_actor_id IS NULL;
UPDATE break_glass_grants SET tenant_id=tenant WHERE tenant_id IS NULL;
UPDATE break_glass_grants SET ticket_id='legacy-' || id::text WHERE ticket_id IS NULL;
UPDATE break_glass_grants SET scope='events:read' WHERE scope IS NULL;
UPDATE break_glass_grants SET requested_at=created WHERE requested_at IS NULL;
-- Old administrator-seeded grants have no named hospital approval, so they must not activate.
UPDATE break_glass_grants SET revoked_at=now()
  WHERE approved_at IS NULL AND revoked_at IS NULL;
ALTER TABLE break_glass_grants ALTER COLUMN grant_id SET NOT NULL;
ALTER TABLE break_glass_grants ALTER COLUMN vendor_actor_id SET NOT NULL;
ALTER TABLE break_glass_grants ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE break_glass_grants ALTER COLUMN ticket_id SET NOT NULL;
ALTER TABLE break_glass_grants ALTER COLUMN scope SET NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS break_glass_grant_id_uidx ON break_glass_grants(grant_id);
CREATE INDEX IF NOT EXISTS break_glass_tenant_vendor_expiry_idx
  ON break_glass_grants(tenant_id, vendor_actor_id, expires_at DESC);
DO $grant_scope_constraint$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='break_glass_scope_check') THEN
    ALTER TABLE break_glass_grants ADD CONSTRAINT break_glass_scope_check
      CHECK (scope IN ('events:read', 'alerts:read', 'handoffs:read', 'metrics:read'));
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='break_glass_ttl_check') THEN
    ALTER TABLE break_glass_grants ADD CONSTRAINT break_glass_ttl_check
      CHECK (requested_ttl_minutes BETWEEN 1 AND 60);
  END IF;
END $grant_scope_constraint$;

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
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS acknowledged_by BIGINT;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS acknowledged_at TIMESTAMPTZ;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS verdict_by BIGINT;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS verdict_at TIMESTAMPTZ;
CREATE UNIQUE INDEX IF NOT EXISTS users_id_tenant_uidx ON users(id, tenant);
DO $constraint$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'alerts_acknowledged_by_tenant_fk') THEN
    ALTER TABLE alerts ADD CONSTRAINT alerts_acknowledged_by_tenant_fk
      FOREIGN KEY (acknowledged_by, tenant) REFERENCES users(id, tenant);
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'alerts_verdict_by_tenant_fk') THEN
    ALTER TABLE alerts ADD CONSTRAINT alerts_verdict_by_tenant_fk
      FOREIGN KEY (verdict_by, tenant) REFERENCES users(id, tenant);
  END IF;
END $constraint$;
CREATE UNIQUE INDEX IF NOT EXISTS alerts_id_tenant_uidx ON alerts(id, tenant);
CREATE INDEX IF NOT EXISTS alerts_tenant_id_idx ON alerts(tenant, id);

CREATE TABLE IF NOT EXISTS handoffs(id BIGSERIAL PRIMARY KEY, alert_id BIGINT, at TEXT, from_owner TEXT,
  to_owner TEXT, note TEXT);
ALTER TABLE handoffs ADD COLUMN IF NOT EXISTS tenant TEXT;
CREATE INDEX IF NOT EXISTS ho_idx ON handoffs(alert_id);
CREATE INDEX IF NOT EXISTS handoffs_tenant_alert_id_idx ON handoffs(tenant, alert_id, id);

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
  AS $$ SELECT COALESCE(NULLIF(current_setting('app.current_tenant_id', true), ''),
                        NULLIF(current_setting('app.tenant_id', true), '')) $$;
CREATE OR REPLACE FUNCTION app_role() RETURNS text LANGUAGE sql STABLE
  AS $$ SELECT COALESCE(NULLIF(current_setting('app.current_actor_role', true), ''),
                        NULLIF(current_setting('app.role', true), '')) $$;
CREATE OR REPLACE FUNCTION app_actor_id() RETURNS bigint LANGUAGE sql STABLE
  AS $$ SELECT COALESCE(NULLIF(current_setting('app.current_actor_id', true), ''),
                        NULLIF(current_setting('app.actor_id', true), ''))::bigint $$;

-- Is there an unrevoked, unexpired break-glass grant for this actor and this hospital? SECURITY DEFINER so
-- that the check does not depend on the caller's row access to break_glass_grants.
CREATE OR REPLACE FUNCTION break_glass_active(p_tenant text) RETURNS boolean
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
  SELECT p_tenant IS NOT NULL AND EXISTS (
    SELECT 1 FROM break_glass_grants g
    WHERE g.tenant_id = p_tenant AND g.vendor_actor_id = app_actor_id()
      AND g.approved_at IS NOT NULL AND g.revoked_at IS NULL AND g.expires_at > now())
$$;

CREATE OR REPLACE FUNCTION break_glass_scope_active(p_tenant text, p_scope text) RETURNS boolean
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
  SELECT p_tenant IS NOT NULL AND EXISTS (
    SELECT 1 FROM break_glass_grants g
    WHERE g.tenant_id = p_tenant AND g.vendor_actor_id = app_actor_id()
      AND g.scope = p_scope AND g.approved_at IS NOT NULL
      AND g.revoked_at IS NULL AND g.expires_at > now())
$$;

-- Lookups that must run before any tenant is known (login, session check, ingest key check).
-- They return one narrow row and run as the owner, so they are the only reads that cross tenants.
CREATE OR REPLACE FUNCTION auth_user_for_login(p_tenant text, p_username text)
  RETURNS TABLE(user_id bigint, user_tenant text, user_role text, user_account_type text,
                user_password_hash text, user_status text, user_is_active boolean, user_token_version integer)
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
  SELECT u.id, u.tenant, u.role, u.account_type, u.password_hash, u.status, u.is_active, u.token_version
  FROM users u
  WHERE u.username = p_username AND (
    (u.tenant = p_tenant AND u.role <> 'vendor_admin')
    OR (p_tenant = 'platform' AND u.role = 'vendor_admin' AND u.tenant IS NULL))
$$;

CREATE OR REPLACE FUNCTION auth_session(p_token_hash text)
  RETURNS TABLE(user_id bigint, user_tenant text, user_role text, user_name text, user_status text,
                user_account_type text, user_is_active boolean, session_token_version integer,
                user_token_version integer)
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
  SELECT u.id, u.tenant, u.role, u.username, u.status, u.account_type, u.is_active,
         s.token_version, u.token_version
  FROM sessions s JOIN users u ON u.id = s.user_id
  WHERE s.token_hash = p_token_hash AND s.expires_at > now()
    AND s.token_version = u.token_version AND u.is_active
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
REVOKE ALL ON FUNCTION break_glass_scope_active(text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION auth_user_for_login(text, text) TO soc_app;
GRANT EXECUTE ON FUNCTION auth_session(text) TO soc_app;
GRANT EXECUTE ON FUNCTION auth_ingest_key(text) TO soc_app;
GRANT EXECUTE ON FUNCTION break_glass_active(text) TO soc_app;
GRANT EXECUTE ON FUNCTION break_glass_scope_active(text, text) TO soc_app;

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
    OR (app_role() = 'vendor_admin' AND break_glass_scope_active(app_tenant(), 'events:read'))));
DROP POLICY IF EXISTS events_ingest ON events;
CREATE POLICY events_ingest ON events FOR INSERT
  WITH CHECK (tenant = app_tenant() AND app_role() = 'ingest');

ALTER TABLE alerts ENABLE ROW LEVEL SECURITY;
ALTER TABLE alerts FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS alerts_read ON alerts;
CREATE POLICY alerts_read ON alerts FOR SELECT
  USING (tenant = app_tenant() AND (
    app_role() IN ('hospital_admin', 'l1', 'l2', 'viewer', 'ingest')
    OR (app_role() = 'vendor_admin' AND (break_glass_scope_active(app_tenant(), 'alerts:read')
      OR break_glass_scope_active(app_tenant(), 'metrics:read')))));
DROP POLICY IF EXISTS alerts_ingest ON alerts;
CREATE POLICY alerts_ingest ON alerts FOR INSERT
  WITH CHECK (tenant = app_tenant() AND app_role() = 'ingest');
DROP POLICY IF EXISTS alerts_break_glass_activation ON alerts;
CREATE POLICY alerts_break_glass_activation ON alerts FOR INSERT
  WITH CHECK (tenant = app_tenant() AND app_role() = 'hospital_admin'
      AND rule = 'VENDOR_BREAK_GLASS_ACTIVATED' AND severity = 'critical' AND source = 'security'
      AND dkey LIKE 'break-glass:%');
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
    OR (app_role() = 'vendor_admin' AND (break_glass_scope_active(app_tenant(), 'handoffs:read')
      OR break_glass_scope_active(app_tenant(), 'alerts:read')))));
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
CREATE OR REPLACE FUNCTION reject_audit_event_mutation() RETURNS trigger
LANGUAGE plpgsql AS $audit$
BEGIN
  RAISE EXCEPTION 'audit_events is append-only' USING ERRCODE = '55000';
END $audit$;
DROP TRIGGER IF EXISTS audit_events_no_update_delete ON audit_events;
CREATE TRIGGER audit_events_no_update_delete
  BEFORE UPDATE OR DELETE ON audit_events
  FOR EACH ROW EXECUTE FUNCTION reject_audit_event_mutation();
DROP TRIGGER IF EXISTS audit_events_no_truncate ON audit_events;
CREATE TRIGGER audit_events_no_truncate
  BEFORE TRUNCATE ON audit_events
  FOR EACH STATEMENT EXECUTE FUNCTION reject_audit_event_mutation();

ALTER TABLE audit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_events FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS audit_events_read ON audit_events;
CREATE POLICY audit_events_read ON audit_events FOR SELECT
  USING (tenant_id = app_tenant() AND app_role() = 'hospital_admin');
DROP POLICY IF EXISTS audit_events_insert ON audit_events;
CREATE POLICY audit_events_insert ON audit_events FOR INSERT
  WITH CHECK (tenant_id = app_tenant()
    AND actor_id IS NOT DISTINCT FROM app_actor_id()
    AND actor_role = app_role());

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
  USING ((vendor_actor_id = app_actor_id() AND app_role() = 'vendor_admin')
      OR (tenant_id = app_tenant() AND app_role() = 'hospital_admin'));
DROP POLICY IF EXISTS break_glass_request ON break_glass_grants;
CREATE POLICY break_glass_request ON break_glass_grants FOR INSERT
  WITH CHECK (vendor_actor_id = app_actor_id() AND app_role() = 'vendor_admin'
      AND approved_by IS NULL AND approved_at IS NULL AND revoked_at IS NULL);
DROP POLICY IF EXISTS break_glass_hospital_update ON break_glass_grants;
CREATE POLICY break_glass_hospital_update ON break_glass_grants FOR UPDATE
  USING (tenant_id = app_tenant() AND app_role() = 'hospital_admin')
  WITH CHECK (tenant_id = app_tenant() AND app_role() = 'hospital_admin');

-- 5. Grants. soc_app gets only what the app uses. No CREATE, no TRUNCATE, no DDL.
GRANT USAGE ON SCHEMA public TO soc_app;
GRANT SELECT, INSERT ON tenants TO soc_app;
GRANT UPDATE (name) ON tenants TO soc_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON users, log_sources, ingest_keys, events, alerts, handoffs, sessions TO soc_app;
GRANT SELECT, INSERT ON audit_log TO soc_app;
REVOKE ALL ON audit_events FROM PUBLIC;
REVOKE UPDATE, DELETE, TRUNCATE ON audit_events FROM soc_app;
GRANT SELECT, INSERT ON audit_events TO soc_app;
GRANT SELECT, INSERT ON break_glass_grants TO soc_app;
GRANT UPDATE (approved_by, approved_at, expires_at, revoked_at, reviewed_by, reviewed_at)
  ON break_glass_grants TO soc_app;
GRANT SELECT, INSERT ON response_approvals TO soc_app;
GRANT UPDATE (status, approved_by, decided_at, decision_note) ON response_approvals TO soc_app;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO soc_app;

-- ===== PR 9: asset inventory, onboarding, intra-tenant handoffs, offboarding =====

-- Asset inventory (IEC 80001 / NIST CSF). Clinical equipment must be monitored agentlessly: no EDR agent and
-- no intrusive scan can run on a device that a patient depends on.
CREATE TABLE IF NOT EXISTS assets(
  asset_id BIGSERIAL PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  device_name TEXT NOT NULL,
  ip_address TEXT NOT NULL DEFAULT '',
  mac_address TEXT NOT NULL DEFAULT '',
  department TEXT NOT NULL DEFAULT '',
  asset_class TEXT NOT NULL DEFAULT 'workstation',
  monitoring_mode TEXT NOT NULL
    CHECK (monitoring_mode IN ('edr_managed', 'agentless_medical', 'network_infra', 'unmanaged')),
  criticality TEXT NOT NULL DEFAULT 'medium' CHECK (criticality IN ('low', 'medium', 'high', 'critical')),
  last_seen_at TIMESTAMPTZ,
  created TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, device_name),
  CONSTRAINT assets_medical_is_agentless CHECK (
    asset_class NOT IN ('mri', 'ct', 'x_ray', 'ultrasound', 'ventilator', 'patient_monitor', 'infusion_pump')
    OR monitoring_mode = 'agentless_medical'));
CREATE INDEX IF NOT EXISTS assets_tenant_idx ON assets(tenant_id, asset_id);

-- Hospital lifecycle: active -> offboarding -> archived -> purged. Only the steps below are allowed.
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS lifecycle_state TEXT NOT NULL DEFAULT 'active';
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS lifecycle_changed TEXT;
DO $lifecycle$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'tenants_lifecycle_check') THEN
    ALTER TABLE tenants ADD CONSTRAINT tenants_lifecycle_check
      CHECK (lifecycle_state IN ('active', 'offboarding', 'archived', 'purged'));
  END IF;
END $lifecycle$;

-- Ingest credentials: a short prefix for humans to recognise a key, and the hash for checking it. The raw key is
-- never stored. retire_after keeps a rotated key valid for an overlap window, then it stops on its own.
ALTER TABLE ingest_keys ADD COLUMN IF NOT EXISTS key_prefix TEXT NOT NULL DEFAULT '';
ALTER TABLE ingest_keys ADD COLUMN IF NOT EXISTS retire_after TIMESTAMPTZ;

-- Handoffs name real users (actor ids), not analyst name strings.
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS owner_user_id BIGINT;
ALTER TABLE handoffs ADD COLUMN IF NOT EXISTS from_user_id BIGINT;
ALTER TABLE handoffs ADD COLUMN IF NOT EXISTS to_user_id BIGINT;
DO $owner_fk$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'alerts_owner_user_tenant_fk') THEN
    ALTER TABLE alerts ADD CONSTRAINT alerts_owner_user_tenant_fk FOREIGN KEY (owner_user_id, tenant)
      REFERENCES users(id, tenant);
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'handoffs_to_user_tenant_fk') THEN
    ALTER TABLE handoffs ADD CONSTRAINT handoffs_to_user_tenant_fk FOREIGN KEY (to_user_id, tenant)
      REFERENCES users(id, tenant);
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'handoffs_from_user_tenant_fk') THEN
    ALTER TABLE handoffs ADD CONSTRAINT handoffs_from_user_tenant_fk FOREIGN KEY (from_user_id, tenant)
      REFERENCES users(id, tenant);
  END IF;
END $owner_fk$;

-- Who may own or receive an alert: an active hospital analyst (admin, L1 or L2) of that hospital.
CREATE OR REPLACE FUNCTION handoff_target_name(p_tenant text, p_user bigint) RETURNS text
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
  SELECT u.username FROM users u
  WHERE p_tenant IS NOT NULL AND u.id = p_user AND u.tenant = p_tenant
    AND u.is_active AND u.status = 'active' AND u.role IN ('hospital_admin', 'l1', 'l2')
    AND u.account_type = 'hospital_staff'
$$;

CREATE OR REPLACE FUNCTION handoff_target_active(p_tenant text, p_user bigint) RETURNS boolean
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
  SELECT handoff_target_name(p_tenant, p_user) IS NOT NULL
$$;

CREATE OR REPLACE FUNCTION hospital_analysts(p_tenant text)
  RETURNS TABLE(user_id bigint, username text, user_role text)
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
  SELECT u.id, u.username, u.role FROM users u
  WHERE u.tenant = p_tenant AND u.is_active AND u.status = 'active'
    AND u.role IN ('hospital_admin', 'l1', 'l2') AND u.account_type = 'hospital_staff'
  ORDER BY u.id
$$;

-- The only way a hospital's lifecycle changes. The update is a compare-and-set on the current state.
CREATE OR REPLACE FUNCTION set_tenant_lifecycle(p_tenant text, p_from text, p_to text) RETURNS boolean
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
BEGIN
  IF p_tenant IS NULL OR p_tenant = 'platform' THEN
    RETURN false;
  END IF;
  IF (p_from, p_to) NOT IN (('active', 'offboarding'), ('offboarding', 'archived')) THEN
    RAISE EXCEPTION 'illegal lifecycle step % -> %', p_from, p_to;
  END IF;
  UPDATE tenants SET lifecycle_state = p_to,
    lifecycle_changed = to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS')
    WHERE id = p_tenant AND lifecycle_state = p_from;
  RETURN FOUND;
END $$;

-- Row counts of everything a hospital holds. Used by the export hook and returned by the purge.
CREATE OR REPLACE FUNCTION tenant_export_counts(p_tenant text) RETURNS jsonb
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
  SELECT jsonb_build_object(
    'events', (SELECT count(*) FROM events WHERE tenant = p_tenant),
    'alerts', (SELECT count(*) FROM alerts WHERE tenant = p_tenant),
    'handoffs', (SELECT count(*) FROM handoffs WHERE tenant = p_tenant),
    'response_approvals', (SELECT count(*) FROM response_approvals WHERE tenant = p_tenant),
    'assets', (SELECT count(*) FROM assets WHERE tenant_id = p_tenant),
    'log_sources', (SELECT count(*) FROM log_sources WHERE tenant = p_tenant),
    'ingest_keys', (SELECT count(*) FROM ingest_keys WHERE tenant = p_tenant),
    'users', (SELECT count(*) FROM users WHERE tenant = p_tenant))
$$;

-- Purge an archived hospital. Operational data is deleted. Users are deactivated and their personal fields are
-- replaced, because audit rows point at them. Audit rows and the tenant row stay, so the record of what happened remains.
CREATE OR REPLACE FUNCTION purge_tenant_data(p_tenant text) RETURNS jsonb
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE before_counts jsonb;
BEGIN
  IF p_tenant IS NULL OR p_tenant = 'platform' THEN
    RAISE EXCEPTION 'this tenant cannot be purged';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM tenants WHERE id = p_tenant AND lifecycle_state = 'archived') THEN
    RAISE EXCEPTION 'tenant must be archived before it is purged';
  END IF;
  before_counts := tenant_export_counts(p_tenant);
  DELETE FROM response_approvals WHERE tenant = p_tenant;
  DELETE FROM handoffs WHERE tenant = p_tenant;
  DELETE FROM alerts WHERE tenant = p_tenant;
  DELETE FROM events WHERE tenant = p_tenant;
  DELETE FROM assets WHERE tenant_id = p_tenant;
  DELETE FROM ingest_keys WHERE tenant = p_tenant;
  DELETE FROM log_sources WHERE tenant = p_tenant;
  DELETE FROM sessions WHERE user_id IN (SELECT id FROM users WHERE tenant = p_tenant);
  UPDATE users SET username = 'purged-' || id::text, email = 'purged+' || id::text || '@invalid.local',
    is_active = FALSE, status = 'disabled', token_version = token_version + 1, password_hash = 'purged'
    WHERE tenant = p_tenant;
  UPDATE tenants SET lifecycle_state = 'purged',
    lifecycle_changed = to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS')
    WHERE id = p_tenant;
  RETURN before_counts;
END $$;

-- Ingest keys stop when their hospital is not active, and a rotated key stops after its overlap window.
CREATE OR REPLACE FUNCTION auth_ingest_key(p_key_hash text)
  RETURNS TABLE(key_id bigint, key_tenant text, key_log_source_id bigint)
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
  SELECT k.id, k.tenant, k.log_source_id
  FROM ingest_keys k
  JOIN log_sources ls ON ls.id = k.log_source_id
  JOIN tenants t ON t.id = k.tenant
  WHERE k.key_hash = p_key_hash AND k.revoked_at IS NULL
    AND (k.retire_after IS NULL OR k.retire_after > now())
    AND ls.disabled_at IS NULL AND ls.tenant = k.tenant AND t.lifecycle_state = 'active'
$$;

-- Row-level security for the new and changed tables.
ALTER TABLE assets ENABLE ROW LEVEL SECURITY;
ALTER TABLE assets FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS assets_read ON assets;
CREATE POLICY assets_read ON assets FOR SELECT
  USING (tenant_id = app_tenant() AND app_role() IN ('hospital_admin', 'l1', 'l2', 'viewer'));
DROP POLICY IF EXISTS assets_admin ON assets;
CREATE POLICY assets_admin ON assets FOR ALL
  USING (tenant_id = app_tenant() AND app_role() = 'hospital_admin')
  WITH CHECK (tenant_id = app_tenant() AND app_role() = 'hospital_admin');

-- A handoff is written by the acting analyst, to an active analyst of the same hospital.
DROP POLICY IF EXISTS handoffs_write ON handoffs;
CREATE POLICY handoffs_write ON handoffs FOR INSERT
  WITH CHECK (tenant = app_tenant() AND app_role() IN ('hospital_admin', 'l1', 'l2')
    AND from_user_id = app_actor_id() AND handoff_target_active(app_tenant(), to_user_id));

GRANT SELECT, INSERT, UPDATE, DELETE ON assets TO soc_app;
-- The blanket sequence grant above runs before this table exists, so grant its sequence explicitly.
GRANT USAGE, SELECT ON SEQUENCE assets_asset_id_seq TO soc_app;
REVOKE ALL ON FUNCTION handoff_target_name(text, bigint) FROM PUBLIC;
REVOKE ALL ON FUNCTION handoff_target_active(text, bigint) FROM PUBLIC;
REVOKE ALL ON FUNCTION hospital_analysts(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION set_tenant_lifecycle(text, text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION tenant_export_counts(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION purge_tenant_data(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION handoff_target_name(text, bigint) TO soc_app;
GRANT EXECUTE ON FUNCTION handoff_target_active(text, bigint) TO soc_app;
GRANT EXECUTE ON FUNCTION hospital_analysts(text) TO soc_app;
GRANT EXECUTE ON FUNCTION set_tenant_lifecycle(text, text, text) TO soc_app;
GRANT EXECUTE ON FUNCTION tenant_export_counts(text) TO soc_app;
GRANT EXECUTE ON FUNCTION purge_tenant_data(text) TO soc_app;

-- Whether a hospital's records were exported. Archive and purge require it. The vendor cannot read audit rows
-- directly (they are visible to the hospital admin only), so this check runs with the owner's rights.
CREATE OR REPLACE FUNCTION tenant_exported(p_tenant text) RETURNS boolean
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
  SELECT EXISTS (SELECT 1 FROM audit_events WHERE tenant_id = p_tenant AND action = 'tenant.export')
$$;
REVOKE ALL ON FUNCTION tenant_exported(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION tenant_exported(text) TO soc_app;
