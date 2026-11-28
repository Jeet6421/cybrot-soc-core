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
  audit_id BIGSERIAL,
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
  device_id TEXT,
  PRIMARY KEY (audit_id, occurred_at)
) PARTITION BY RANGE (occurred_at);
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

CREATE TABLE IF NOT EXISTS events(id BIGSERIAL, ts TEXT, tenant TEXT, source TEXT, type TEXT,
  "user" TEXT, host TEXT, ip TEXT, patient TEXT, detail TEXT, attack_id TEXT,
  destination TEXT, data_classification TEXT, destination_approved BOOLEAN,
  src_zone TEXT, dst_zone TEXT, boundary_violation BOOLEAN, approved_change BOOLEAN,
  log_source_id BIGINT, occurred_at TIMESTAMPTZ NOT NULL, dedupe_key TEXT,
  PRIMARY KEY (id, occurred_at)) PARTITION BY RANGE (occurred_at);
CREATE INDEX IF NOT EXISTS ev_idx ON events(tenant, type, ts);
CREATE INDEX IF NOT EXISTS ev_host_type_idx ON events(tenant, host, type, ts);
-- PR 13: columns must exist before the index that uses them. A legacy table reaches this point without them.
ALTER TABLE events ADD COLUMN IF NOT EXISTS log_source_id BIGINT;
ALTER TABLE events ADD COLUMN IF NOT EXISTS occurred_at TIMESTAMPTZ;
ALTER TABLE events ADD COLUMN IF NOT EXISTS dedupe_key TEXT;
-- PR 13: an identical event (same source id, or same canonical payload) is stored once. The partition key is part of
-- the index, so a replay of the same event (same occurred_at) always lands in the same partition and conflicts there.
CREATE UNIQUE INDEX IF NOT EXISTS events_dedupe_uidx ON events(tenant, (COALESCE(log_source_id, 0)), dedupe_key, occurred_at);
ALTER TABLE events ADD COLUMN IF NOT EXISTS destination TEXT;
ALTER TABLE events ADD COLUMN IF NOT EXISTS data_classification TEXT;
ALTER TABLE events ADD COLUMN IF NOT EXISTS destination_approved BOOLEAN;
ALTER TABLE events ADD COLUMN IF NOT EXISTS src_zone TEXT;
ALTER TABLE events ADD COLUMN IF NOT EXISTS dst_zone TEXT;
ALTER TABLE events ADD COLUMN IF NOT EXISTS boundary_violation BOOLEAN;
ALTER TABLE events ADD COLUMN IF NOT EXISTS approved_change BOOLEAN;

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

-- PR 12: which log source produced the alert (NULL = unattributed, e.g. older alerts or break-glass alerts).
-- The composite key makes an alert unable to name another hospital's log source.
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS log_source_id BIGINT;
CREATE UNIQUE INDEX IF NOT EXISTS log_sources_id_tenant_uidx ON log_sources(id, tenant);
DO $alert_source$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'alerts_log_source_tenant_fk') THEN
    ALTER TABLE alerts ADD CONSTRAINT alerts_log_source_tenant_fk
      FOREIGN KEY (log_source_id, tenant) REFERENCES log_sources(id, tenant);
  END IF;
END $alert_source$;

-- PR 12: standard analytical verdicts. Legacy labels (tp, fp, unclear) are migrated once; an unlabeled
-- alert keeps verdict NULL and is never stored under a label of its own.
UPDATE alerts SET verdict = CASE verdict WHEN 'tp' THEN 'true_positive_malicious'
                                         WHEN 'fp' THEN 'false_positive'
                                         WHEN 'unclear' THEN 'inconclusive' END
  WHERE verdict IN ('tp', 'fp', 'unclear');
DO $verdict_check$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'alerts_verdict_check') THEN
    ALTER TABLE alerts ADD CONSTRAINT alerts_verdict_check
      CHECK (verdict IS NULL OR verdict IN ('true_positive_malicious', 'true_positive_benign',
                                            'false_positive', 'inconclusive'));
  END IF;
END $verdict_check$;

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

-- ---- PR 10/11: durable response jobs (the outbox) ---------------------------------------------------------
-- A response is one row from the moment it is requested. A disruptive one waits in 'pending_approval' until a
-- second person approves it (maker-checker), then becomes 'queued'. Workers claim queued rows (see below).
-- Alerts, owners, status and handoffs are never written here.
CREATE TABLE IF NOT EXISTS response_jobs(
  job_id BIGSERIAL PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  alert_id BIGINT NOT NULL,
  action_type TEXT NOT NULL CHECK (action_type IN ('isolate_host', 'disable_account', 'block_ip')),
  risk_tier TEXT NOT NULL DEFAULT 'disruptive' CHECK (risk_tier IN ('read_only', 'disruptive')),
  playbook_id TEXT NOT NULL DEFAULT '',
  playbook_version TEXT NOT NULL DEFAULT '',
  playbook_digest TEXT NOT NULL DEFAULT '',
  target_asset_id BIGINT,
  target_host TEXT NOT NULL CHECK (length(btrim(target_host)) BETWEEN 1 AND 200),
  idempotency_key TEXT NOT NULL CHECK (length(idempotency_key) BETWEEN 1 AND 120),
  status TEXT NOT NULL DEFAULT 'pending_approval'
    CHECK (status IN ('pending_approval', 'rejected', 'queued', 'running', 'succeeded', 'dead')),
  requested_by BIGINT NOT NULL,
  approved_by BIGINT,
  approved_at TIMESTAMPTZ,
  attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
  max_attempts INTEGER NOT NULL DEFAULT 5 CHECK (max_attempts BETWEEN 1 AND 20),
  next_run_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  locked_by TEXT,
  lease_expires_at TIMESTAMPTZ,
  result JSONB NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(result) = 'object'),
  errors JSONB NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(errors) = 'array'),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, idempotency_key),
  FOREIGN KEY (alert_id, tenant_id) REFERENCES alerts(id, tenant),
  FOREIGN KEY (requested_by, tenant_id) REFERENCES users(id, tenant),
  FOREIGN KEY (approved_by, tenant_id) REFERENCES users(id, tenant),
  CHECK ((status = 'running') = (locked_by IS NOT NULL AND lease_expires_at IS NOT NULL)),
  CHECK (approved_by IS NULL OR approved_by <> requested_by),
  CHECK (status <> 'pending_approval' OR approved_by IS NULL),
  CHECK (status NOT IN ('queued', 'running', 'succeeded', 'dead') OR risk_tier = 'read_only' OR approved_by IS NOT NULL)
);
CREATE INDEX IF NOT EXISTS response_jobs_due_idx ON response_jobs(next_run_at)
  WHERE status IN ('queued', 'running');

ALTER TABLE response_jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE response_jobs FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS response_jobs_read ON response_jobs;
CREATE POLICY response_jobs_read ON response_jobs FOR SELECT
  USING (tenant_id = app_tenant() AND app_role() IN ('hospital_admin', 'l1', 'l2', 'viewer'));
-- Requesting: any analyst role, in their own hospital, as themselves. A disruptive job starts pending.
DROP POLICY IF EXISTS response_jobs_request ON response_jobs;
CREATE POLICY response_jobs_request ON response_jobs FOR INSERT
  WITH CHECK (tenant_id = app_tenant() AND app_role() IN ('hospital_admin', 'l1', 'l2')
    AND attempts = 0 AND requested_by = app_actor_id() AND approved_by IS NULL AND approved_at IS NULL
    AND (status = 'pending_approval' OR (status = 'queued' AND risk_tier = 'read_only')));
-- Deciding: a hospital admin or an L2 analyst, never the requester (maker-checker). Only two outcomes exist.
DROP POLICY IF EXISTS response_jobs_decide ON response_jobs;
CREATE POLICY response_jobs_decide ON response_jobs FOR UPDATE
  USING (tenant_id = app_tenant() AND app_role() IN ('hospital_admin', 'l2')
    AND status = 'pending_approval' AND requested_by <> app_actor_id())
  WITH CHECK (tenant_id = app_tenant() AND app_role() IN ('hospital_admin', 'l2')
    AND ((status = 'queued' AND approved_by = app_actor_id() AND approved_at IS NOT NULL
          AND requested_by <> approved_by)
      OR (status = 'rejected' AND approved_by IS NULL)));

GRANT SELECT, INSERT ON response_jobs TO soc_app;
GRANT UPDATE (status, approved_by, approved_at, updated_at) ON response_jobs TO soc_app;
GRANT USAGE, SELECT ON SEQUENCE response_jobs_job_id_seq TO soc_app;

-- Row counts of everything a hospital holds. Used by the export hook and returned by the purge.
CREATE OR REPLACE FUNCTION tenant_export_counts(p_tenant text) RETURNS jsonb
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
  SELECT jsonb_build_object(
    'events', (SELECT count(*) FROM events WHERE tenant = p_tenant),
    'alerts', (SELECT count(*) FROM alerts WHERE tenant = p_tenant),
    'handoffs', (SELECT count(*) FROM handoffs WHERE tenant = p_tenant),
    'response_approvals', (SELECT count(*) FROM response_approvals WHERE tenant = p_tenant),
    'response_jobs', (SELECT count(*) FROM response_jobs WHERE tenant_id = p_tenant),
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
  DELETE FROM response_jobs WHERE tenant_id = p_tenant;
  DELETE FROM response_approvals WHERE tenant = p_tenant;
  DELETE FROM handoffs WHERE tenant = p_tenant;
  DELETE FROM alerts WHERE tenant = p_tenant;
  DELETE FROM events WHERE tenant = p_tenant;
  DELETE FROM assets WHERE tenant_id = p_tenant;
  DELETE FROM ingest_keys WHERE tenant = p_tenant;
  DELETE FROM log_sources WHERE tenant = p_tenant;
  DELETE FROM ingest_rate WHERE tenant_id = p_tenant;
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


-- Claim up to p_limit due jobs for one worker. A job is due when it is queued and its time has come, or when it is
-- running under a lease that has expired (the worker crashed). A crashed job that has used its last attempt is
-- dead-lettered instead of retried forever. Each claim writes its audit row in the same transaction.
CREATE OR REPLACE FUNCTION claim_response_jobs(p_worker text, p_limit integer, p_lease_seconds integer)
  RETURNS SETOF response_jobs
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE j response_jobs%ROWTYPE;
BEGIN
  IF p_worker IS NULL OR length(p_worker) NOT BETWEEN 1 AND 120 THEN
    RAISE EXCEPTION 'worker id must be 1 to 120 characters' USING ERRCODE = '22023';
  END IF;
  IF p_limit NOT BETWEEN 1 AND 100 THEN
    RAISE EXCEPTION 'limit must be 1 to 100' USING ERRCODE = '22023';
  END IF;
  IF p_lease_seconds NOT BETWEEN 5 AND 3600 THEN
    RAISE EXCEPTION 'lease must be 5 to 3600 seconds' USING ERRCODE = '22023';
  END IF;
  UPDATE response_jobs SET status = 'dead', locked_by = NULL, lease_expires_at = NULL, updated_at = now(),
    errors = errors || jsonb_build_array(jsonb_build_object('at', now(), 'error', 'lease expired after the last attempt'))
  WHERE status = 'running' AND lease_expires_at < now() AND attempts >= max_attempts;
  FOR j IN
    UPDATE response_jobs SET status = 'running', locked_by = p_worker,
      lease_expires_at = now() + make_interval(secs => p_lease_seconds),
      attempts = response_jobs.attempts + 1, updated_at = now()
    WHERE job_id IN (
      SELECT c.job_id FROM response_jobs c
      WHERE (c.status = 'queued' AND c.next_run_at <= now())
         OR (c.status = 'running' AND c.lease_expires_at < now())
      ORDER BY c.next_run_at, c.job_id
      LIMIT p_limit
      FOR UPDATE SKIP LOCKED)
    RETURNING response_jobs.*
  LOOP
    INSERT INTO audit_events(tenant_id, actor_id, actor_role, auth_context, action, resource_type, resource_id,
      resource_classification, outcome, metadata, request_id)
    VALUES (j.tenant_id, NULL, 'worker', 'system', 'response_job.start', 'response_job', j.job_id::text,
      'security_event', 'allow',
      jsonb_build_object('attempt', j.attempts, 'action_type', j.action_type,
        'playbook_id', j.playbook_id, 'playbook_version', j.playbook_version),
      'response-job-' || j.job_id || '-start-' || j.attempts);
    RETURN NEXT j;
  END LOOP;
  RETURN;
END $$;

-- Record one attempt's outcome, with its audit row, in one transaction. Only the worker that holds the job's lease may
-- write it; if the lease was taken over the call returns 'lost_lease' and changes nothing.
-- outcome: succeeded | retry (back off, dead-letter when out of attempts) | dead (permanent) | defer (not run here;
-- the attempt is not counted).
CREATE OR REPLACE FUNCTION finish_response_job(p_job bigint, p_worker text, p_outcome text, p_result jsonb,
    p_error text, p_retry_seconds integer)
  RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE r response_jobs%ROWTYPE;
  err jsonb := NULL;
  final_status text;
BEGIN
  IF p_outcome NOT IN ('succeeded', 'retry', 'dead', 'defer') THEN
    RAISE EXCEPTION 'unknown outcome' USING ERRCODE = '22023';
  END IF;
  SELECT * INTO r FROM response_jobs
    WHERE job_id = p_job AND status = 'running' AND locked_by = p_worker AND lease_expires_at >= now()
    FOR UPDATE;
  IF NOT FOUND THEN
    RETURN 'lost_lease';
  END IF;
  IF p_error IS NOT NULL THEN
    err := jsonb_build_array(jsonb_build_object('at', now(), 'error', left(p_error, 300)));
  END IF;
  IF p_outcome = 'succeeded' THEN
    UPDATE response_jobs SET status = 'succeeded', result = COALESCE(p_result, '{}'::jsonb), locked_by = NULL,
      lease_expires_at = NULL, updated_at = now() WHERE job_id = p_job;
  ELSIF p_outcome = 'retry' AND r.attempts < r.max_attempts THEN
    UPDATE response_jobs SET status = 'queued', locked_by = NULL, lease_expires_at = NULL,
      next_run_at = now() + make_interval(secs => GREATEST(p_retry_seconds, 1)),
      errors = errors || COALESCE(err, '[]'::jsonb), updated_at = now() WHERE job_id = p_job;
  ELSIF p_outcome = 'defer' THEN
    UPDATE response_jobs SET status = 'queued', locked_by = NULL, lease_expires_at = NULL,
      next_run_at = now() + make_interval(secs => GREATEST(p_retry_seconds, 1)),
      attempts = GREATEST(attempts - 1, 0), updated_at = now() WHERE job_id = p_job;
  ELSE
    UPDATE response_jobs SET status = 'dead', locked_by = NULL, lease_expires_at = NULL,
      errors = errors || COALESCE(err, '[]'::jsonb), updated_at = now() WHERE job_id = p_job;
  END IF;
  SELECT status INTO final_status FROM response_jobs WHERE job_id = p_job;
  INSERT INTO audit_events(tenant_id, actor_id, actor_role, auth_context, action, resource_type, resource_id,
    resource_classification, outcome, metadata, request_id)
  VALUES (r.tenant_id, NULL, 'worker', 'system', 'response_job.finish', 'response_job', p_job::text,
    'security_event', CASE WHEN p_outcome = 'succeeded' THEN 'allow' ELSE 'error' END,
    jsonb_build_object('result', p_outcome, 'status', final_status, 'attempt', r.attempts),
    'response-job-' || p_job || '-finish-' || r.attempts);
  RETURN 'ok';
END $$;

-- The asset a job targets, resolved inside the job's own hospital. Used by the executor before it runs anything, so
-- the check cannot be skipped and never sees another hospital's inventory. Returns NULL when nothing matches.
CREATE OR REPLACE FUNCTION resolve_job_target(p_job bigint) RETURNS jsonb
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
  SELECT CASE WHEN count(a.asset_id) = 0 THEN NULL ELSE jsonb_build_object(
    'asset_id', min(a.asset_id),
    'device_name', min(a.device_name),
    'medical', bool_or(a.asset_class IN ('mri', 'ct', 'x_ray', 'ultrasound', 'ventilator', 'patient_monitor', 'infusion_pump')
      OR a.monitoring_mode = 'agentless_medical')) END
  FROM response_jobs j
  LEFT JOIN assets a ON a.tenant_id = j.tenant_id AND (a.device_name = j.target_host OR a.ip_address = j.target_host)
  WHERE j.job_id = p_job
$$;

REVOKE ALL ON FUNCTION claim_response_jobs(text, integer, integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION finish_response_job(bigint, text, text, jsonb, text, integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION resolve_job_target(bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION claim_response_jobs(text, integer, integer) TO soc_app;
GRANT EXECUTE ON FUNCTION finish_response_job(bigint, text, text, jsonb, text, integer) TO soc_app;
GRANT EXECUTE ON FUNCTION resolve_job_target(bigint) TO soc_app;

-- ---- PR 13: time partitions, 180-day retention, ingest rate windows -----------------------------------------------
-- events and audit_events are monthly range partitions on occurred_at. Retention never deletes rows: it drops whole
-- partitions once they end before the cutoff, so every row newer than the cutoff is kept. CERT-In Directions 2022
-- require logs to be kept at least 180 days. The retention floor below is enforced in the database too.
CREATE TABLE IF NOT EXISTS partition_catalog(
  parent TEXT NOT NULL CHECK (parent IN ('events', 'audit_events')),
  partition_name TEXT PRIMARY KEY,
  range_start TIMESTAMPTZ NOT NULL,
  range_end TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  dropped_at TIMESTAMPTZ,
  dropped_rows BIGINT);

-- Creates monthly partitions from the start of the retention window (or from p_from when earlier) through two months
-- ahead. Idempotent. Skips a parent that is not partitioned yet (a legacy database; see scripts/partition_migrate.py).
CREATE OR REPLACE FUNCTION ensure_time_partitions(p_from timestamptz DEFAULT NULL) RETURNS integer
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public SET timezone = 'UTC' AS $$
DECLARE
  parent text;
  m timestamptz;
  first_m timestamptz := date_trunc('month', now() - interval '200 days');
  last_m timestamptz := date_trunc('month', now()) + interval '3 months';
  pname text;
  made integer := 0;
BEGIN
  IF p_from IS NOT NULL AND date_trunc('month', p_from) < first_m THEN
    first_m := date_trunc('month', p_from);
  END IF;
  FOREACH parent IN ARRAY ARRAY['events', 'audit_events'] LOOP
    IF NOT EXISTS (SELECT 1 FROM pg_class WHERE relname = parent AND relkind = 'p') THEN
      RAISE NOTICE 'skipping partitions for %: the table is not partitioned yet', parent;
      CONTINUE;
    END IF;
    m := first_m;
    WHILE m < last_m LOOP
      pname := parent || '_p' || to_char(m, 'YYYYMM');
      IF to_regclass('public.' || pname) IS NULL THEN
        EXECUTE format('CREATE TABLE public.%I PARTITION OF public.%I FOR VALUES FROM (%L) TO (%L)',
                       pname, parent, m, m + interval '1 month');
        INSERT INTO partition_catalog(parent, partition_name, range_start, range_end)
          VALUES (parent, pname, m, m + interval '1 month') ON CONFLICT (partition_name) DO NOTHING;
        made := made + 1;
      END IF;
      m := m + interval '1 month';
    END LOOP;
  END LOOP;
  RETURN made;
END $$;

-- Drops every catalogued partition that ends at or before now() - p_retention_days, and prunes ingest rate windows
-- older than two days. Refuses any retention below 180 days. Returns each dropped partition and its row count.
CREATE OR REPLACE FUNCTION drop_expired_partitions(p_retention_days integer DEFAULT 180)
  RETURNS TABLE(partition_name text, rows_dropped bigint)
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public SET timezone = 'UTC' AS $$
DECLARE
  r record;
  n bigint;
  cutoff timestamptz;
BEGIN
  IF p_retention_days IS NULL OR p_retention_days < 180 THEN
    RAISE EXCEPTION 'retention must be at least 180 days (CERT-In)' USING ERRCODE = '22023';
  END IF;
  cutoff := now() - make_interval(days => p_retention_days);
  FOR r IN SELECT c.partition_name AS pname, c.range_end FROM partition_catalog c
           WHERE c.dropped_at IS NULL AND c.range_end <= cutoff ORDER BY c.range_end LOOP
    EXECUTE format('SELECT count(*) FROM public.%I', r.pname) INTO n;
    EXECUTE format('DROP TABLE public.%I', r.pname);
    UPDATE partition_catalog c SET dropped_at = now(), dropped_rows = n WHERE c.partition_name = r.pname;
    partition_name := r.pname;
    rows_dropped := n;
    RETURN NEXT;
  END LOOP;
  DELETE FROM ingest_rate WHERE window_start < now() - interval '2 days';
  RETURN;
END $$;

-- Ingest quota per (tenant, log source) and minute. Written by the app in the same transaction as the ingest, so one
-- noisy source cannot use another hospital's quota. The row lock is per window.
CREATE TABLE IF NOT EXISTS ingest_rate(
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  log_source_id BIGINT NOT NULL DEFAULT 0,
  window_start TIMESTAMPTZ NOT NULL,
  events BIGINT NOT NULL DEFAULT 0 CHECK (events >= 0),
  payload_bytes BIGINT NOT NULL DEFAULT 0 CHECK (payload_bytes >= 0),
  PRIMARY KEY (tenant_id, log_source_id, window_start));
ALTER TABLE ingest_rate ENABLE ROW LEVEL SECURITY;
ALTER TABLE ingest_rate FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS ingest_rate_tenant ON ingest_rate;
CREATE POLICY ingest_rate_tenant ON ingest_rate FOR ALL
  USING (tenant_id = app_tenant()) WITH CHECK (tenant_id = app_tenant());

REVOKE ALL ON ingest_rate FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE ON ingest_rate TO soc_app;
REVOKE ALL ON FUNCTION ensure_time_partitions(timestamptz) FROM PUBLIC;
REVOKE ALL ON FUNCTION drop_expired_partitions(integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ensure_time_partitions(timestamptz) TO soc_app;
GRANT EXECUTE ON FUNCTION drop_expired_partitions(integer) TO soc_app;

-- PR 14: TOTP MFA state, account lockout and login rate limits. The runtime role never updates these columns
-- directly. Every read and write goes through a SECURITY DEFINER function, which runs as the owner.
ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_secret_enc TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_last_counter BIGINT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS failed_login_attempts INTEGER NOT NULL DEFAULT 0
  CHECK (failed_login_attempts >= 0);
ALTER TABLE users ADD COLUMN IF NOT EXISTS locked_until TIMESTAMPTZ;

-- One row per (source address, tenant, username): a fixed window, counted on every attempt.
CREATE TABLE IF NOT EXISTS login_rate(ip TEXT NOT NULL, tenant TEXT NOT NULL, username TEXT NOT NULL,
  window_start TIMESTAMPTZ NOT NULL, attempts INTEGER NOT NULL CHECK (attempts >= 0),
  PRIMARY KEY (ip, tenant, username));

CREATE OR REPLACE FUNCTION auth_login_rate_spend(p_ip text, p_tenant text, p_username text,
                                                 p_limit integer, p_window_seconds integer)
  RETURNS TABLE(allowed boolean, retry_after integer)
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
  w timestamptz;
BEGIN
  INSERT INTO login_rate AS l(ip, tenant, username, window_start, attempts)
  VALUES (p_ip, p_tenant, p_username, now(), 1)
  ON CONFLICT (ip, tenant, username) DO UPDATE
    SET window_start = CASE WHEN l.window_start <= now() - make_interval(secs => p_window_seconds)
                            THEN now() ELSE l.window_start END,
        attempts = CASE WHEN l.window_start <= now() - make_interval(secs => p_window_seconds)
                        THEN 1 ELSE l.attempts + 1 END
    WHERE l.window_start <= now() - make_interval(secs => p_window_seconds) OR l.attempts < p_limit;
  IF FOUND THEN
    RETURN QUERY SELECT true, 0;
    RETURN;
  END IF;
  SELECT l.window_start INTO w FROM login_rate l
    WHERE l.ip = p_ip AND l.tenant = p_tenant AND l.username = p_username;
  RETURN QUERY SELECT false,
    greatest(1, ceil(extract(epoch FROM (w + make_interval(secs => p_window_seconds) - now())))::integer);
END
$$;

CREATE OR REPLACE FUNCTION auth_user_security(p_user_id bigint)
  RETURNS TABLE(mfa_enabled boolean, mfa_secret_enc text, mfa_last_counter bigint, locked boolean,
                lock_seconds integer)
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
  SELECT u.mfa_enabled, u.mfa_secret_enc, u.mfa_last_counter,
         (u.locked_until IS NOT NULL AND u.locked_until > now()),
         greatest(0, ceil(extract(epoch FROM (u.locked_until - now())))::integer)
  FROM users u WHERE u.id = p_user_id
$$;

-- Counts one failure. The fifth consecutive failure locks the account and resets the count.
CREATE OR REPLACE FUNCTION auth_login_failed(p_user_id bigint, p_max integer, p_lock_seconds integer)
  RETURNS TABLE(locked boolean, failed integer)
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
BEGIN
  RETURN QUERY
  UPDATE users u SET
    failed_login_attempts = CASE WHEN u.failed_login_attempts + 1 >= p_max THEN 0
                                 ELSE u.failed_login_attempts + 1 END,
    locked_until = CASE WHEN u.failed_login_attempts + 1 >= p_max
                        THEN now() + make_interval(secs => p_lock_seconds) ELSE u.locked_until END
  WHERE u.id = p_user_id
  RETURNING (u.locked_until IS NOT NULL AND u.locked_until > now()), u.failed_login_attempts;
END
$$;

CREATE OR REPLACE FUNCTION auth_login_succeeded(p_user_id bigint) RETURNS void
  LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
  UPDATE users SET failed_login_attempts = 0, locked_until = NULL
  WHERE id = p_user_id AND (failed_login_attempts <> 0 OR locked_until IS NOT NULL)
$$;

-- Anti-replay: a time step is accepted once. The update is atomic, so two concurrent requests cannot both win.
CREATE OR REPLACE FUNCTION auth_mfa_consume(p_user_id bigint, p_step bigint) RETURNS boolean
  LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
  WITH done AS (
    UPDATE users SET mfa_last_counter = p_step
    WHERE id = p_user_id AND mfa_enabled AND (mfa_last_counter IS NULL OR mfa_last_counter < p_step)
    RETURNING 1)
  SELECT EXISTS (SELECT 1 FROM done)
$$;

-- Stores a pending (not yet confirmed) secret. Refused once MFA is on, so a stolen session cannot reset it.
CREATE OR REPLACE FUNCTION auth_mfa_store_pending(p_user_id bigint, p_secret_enc text) RETURNS boolean
  LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
  WITH done AS (
    UPDATE users SET mfa_secret_enc = p_secret_enc, mfa_last_counter = NULL
    WHERE id = p_user_id AND NOT mfa_enabled RETURNING 1)
  SELECT EXISTS (SELECT 1 FROM done)
$$;

CREATE OR REPLACE FUNCTION auth_mfa_enable(p_user_id bigint, p_step bigint) RETURNS boolean
  LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
  WITH done AS (
    UPDATE users SET mfa_enabled = TRUE, mfa_last_counter = p_step
    WHERE id = p_user_id AND NOT mfa_enabled AND mfa_secret_enc IS NOT NULL
      AND (mfa_last_counter IS NULL OR mfa_last_counter < p_step)
    RETURNING 1)
  SELECT EXISTS (SELECT 1 FROM done)
$$;

REVOKE ALL ON FUNCTION auth_login_rate_spend(text, text, text, integer, integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION auth_user_security(bigint) FROM PUBLIC;
REVOKE ALL ON FUNCTION auth_login_failed(bigint, integer, integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION auth_login_succeeded(bigint) FROM PUBLIC;
REVOKE ALL ON FUNCTION auth_mfa_consume(bigint, bigint) FROM PUBLIC;
REVOKE ALL ON FUNCTION auth_mfa_store_pending(bigint, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION auth_mfa_enable(bigint, bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION auth_login_rate_spend(text, text, text, integer, integer) TO soc_app;
GRANT EXECUTE ON FUNCTION auth_user_security(bigint) TO soc_app;
GRANT EXECUTE ON FUNCTION auth_login_failed(bigint, integer, integer) TO soc_app;
GRANT EXECUTE ON FUNCTION auth_login_succeeded(bigint) TO soc_app;
GRANT EXECUTE ON FUNCTION auth_mfa_consume(bigint, bigint) TO soc_app;
GRANT EXECUTE ON FUNCTION auth_mfa_store_pending(bigint, text) TO soc_app;
GRANT EXECUTE ON FUNCTION auth_mfa_enable(bigint, bigint) TO soc_app;

-- PR 16: clock-skew tracking per log source (CERT-In NTP check), threat categories on alerts, and the kind an ingest
-- key's source was registered with. Ingest keys cannot read log_sources under RLS, so the reads and writes go through
-- SECURITY DEFINER functions.
ALTER TABLE log_sources ADD COLUMN IF NOT EXISTS skew_last_seconds DOUBLE PRECISION;
ALTER TABLE log_sources ADD COLUMN IF NOT EXISTS skew_checked_at TIMESTAMPTZ;
ALTER TABLE log_sources ADD COLUMN IF NOT EXISTS skew_window_start TIMESTAMPTZ;
ALTER TABLE log_sources ADD COLUMN IF NOT EXISTS skew_window_max_seconds DOUBLE PRECISION;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS threat_category TEXT;
ALTER TABLE alerts DROP CONSTRAINT IF EXISTS alerts_threat_category_check;
ALTER TABLE alerts ADD CONSTRAINT alerts_threat_category_check
  CHECK (threat_category IS NULL OR threat_category IN ('ransomware', 'phishing', 'credential_abuse_impossible_travel', 'patient_record_snooping', 'medical_device_unexpected_egress', 'unknown_network_asset', 'tampering', 'other'));

CREATE OR REPLACE FUNCTION ingest_source_kind(p_log_source_id bigint) RETURNS text
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
  SELECT kind FROM log_sources WHERE id = p_log_source_id
$$;

-- Records the latest drift and the largest drift in the last 24 hours. The window restarts after 24 hours.
CREATE OR REPLACE FUNCTION record_ingest_skew(p_log_source_id bigint, p_last double precision,
                                             p_batch_max double precision) RETURNS void
  LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
  UPDATE log_sources SET
    skew_last_seconds = p_last,
    skew_checked_at = now(),
    skew_window_max_seconds = CASE WHEN skew_window_start IS NULL OR skew_window_start < now() - interval '24 hours'
                                   THEN p_batch_max
                                   ELSE greatest(skew_window_max_seconds, p_batch_max) END,
    skew_window_start = CASE WHEN skew_window_start IS NULL OR skew_window_start < now() - interval '24 hours'
                             THEN now() ELSE skew_window_start END
  WHERE id = p_log_source_id
$$;

REVOKE ALL ON FUNCTION ingest_source_kind(bigint) FROM PUBLIC;
REVOKE ALL ON FUNCTION record_ingest_skew(bigint, double precision, double precision) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION ingest_source_kind(bigint) TO soc_app;
GRANT EXECUTE ON FUNCTION record_ingest_skew(bigint, double precision, double precision) TO soc_app;

-- Create the partitions this database needs now (idempotent; the worker repeats it hourly).
SELECT ensure_time_partitions();
