"""Cybrot SOC Core - prototype: ingest -> detect -> triage queue -> metrics -> exit criteria.

Who may call /api/:
- A logged-in user (a session token). The role decides what they may do. Their hospital is the tenant.
- An ingest key, for POST /api/events and POST /api/ingest/* only. The key is bound to one hospital and one log source.
Nothing else is accepted. There is no shared operator token.

The tenant always comes from the caller's identity. A tenant_id in the query can only narrow within that scope;
anything else is refused with 403 before a query runs. PostgreSQL row-level security enforces the same rule
underneath: every transaction carries the identity in transaction-local settings (see db/schema.sql).
"""
import hashlib, ipaddress, json, os, re, secrets, sys, uuid
import playbooks
from datetime import datetime, timedelta, timezone

import psycopg
from flask import Flask, g, request, jsonify, send_from_directory
from werkzeug.middleware.proxy_fix import ProxyFix

import auth, detect, generate

# Runtime connection, as the soc_app role (never the owner). Read at call time.
ANALYSTS = os.environ.get("ANALYSTS", "analyst1,analyst2,analyst3").split(",")
# Lab-only endpoints (synthetic data, demo load, reset). They need the owner role, so they use LAB_DATABASE_URL.
# Set LAB_ENDPOINTS=0 in any environment where real logs or real analysts' work could be in the database.
LAB_ENDPOINTS = os.environ.get("LAB_ENDPOINTS", "1") == "1"
LAB_PATHS = {"/api/demo", "/api/autolabel", "/api/reset"}
SESSION_HOURS = float(os.environ.get("SOC_SESSION_HOURS", "8"))
PUBLIC_ROUTES = {("POST", "/api/login")}
HOSPITAL_READ = ("hospital_admin", "l1", "l2", "viewer")
ROUTE_ROLES = {
    ("POST", "/api/events"): {"ingest"},
    ("GET", "/api/events"): {"hospital_admin", "l1", "l2", "vendor_admin"},
    ("POST", "/api/ingest/wazuh"): {"ingest"},
    ("GET", "/api/tenants"): {"vendor_admin"},
    ("GET", "/api/break-glass/grants"): {"vendor_admin", "hospital_admin"},
    ("POST", "/api/break-glass/grants"): {"vendor_admin"},
    ("POST", "/api/break-glass/grants/<uuid:grant_id>/approve"): {"hospital_admin"},
    ("POST", "/api/break-glass/grants/<uuid:grant_id>/revoke"): {"hospital_admin"},
    ("POST", "/api/break-glass/grants/<uuid:grant_id>/review"): {"hospital_admin"},
    ("POST", "/api/tenants"): {"vendor_admin"},
    ("GET", "/api/users"): {"hospital_admin"},
    ("POST", "/api/users"): {"hospital_admin"},
    ("PATCH", "/api/users/<int:uid>"): {"hospital_admin"},
    ("POST", "/api/users/<int:uid>/disable"): {"hospital_admin"},
    ("GET", "/api/log-sources"): set(HOSPITAL_READ),
    ("POST", "/api/log-sources"): {"hospital_admin"},
    ("POST", "/api/log-sources/<int:sid>/disable"): {"hospital_admin"},
    ("GET", "/api/credentials"): {"hospital_admin"},
    ("POST", "/api/credentials"): {"hospital_admin"},
    ("POST", "/api/credentials/<int:kid>/revoke"): {"hospital_admin"},
    ("POST", "/api/credentials/<int:kid>/rotate"): {"hospital_admin"},
    ("POST", "/api/logout"): {"session"},
    ("POST", "/api/mfa/setup"): {"session"},
    ("POST", "/api/mfa/verify"): {"session"},
    ("GET", "/api/me"): {"session"},
    ("GET", "/api/settings"): {"hospital_admin"},
    ("PUT", "/api/settings"): {"hospital_admin"},
    ("GET", "/api/alerts"): set(HOSPITAL_READ) | {"vendor_admin"},
    ("GET", "/api/alerts/<int:i>"): set(HOSPITAL_READ) | {"vendor_admin"},
    ("POST", "/api/alerts/<int:i>/ack"): {"hospital_admin", "l1", "l2"},
    ("POST", "/api/alerts/<int:i>/verdict"): {"hospital_admin", "l2"},
    ("GET", "/api/analysts"): set(HOSPITAL_READ),
    ("GET", "/api/assets"): set(HOSPITAL_READ),
    ("POST", "/api/assets"): {"hospital_admin"},
    ("PATCH", "/api/assets/<int:asset_id>"): {"hospital_admin"},
    ("GET", "/api/data-flow"): {"hospital_admin"},
    ("POST", "/api/offboarding/start"): {"hospital_admin"},
    ("POST", "/api/tenants/<tid>/offboarding/export"): {"vendor_admin"},
    ("POST", "/api/tenants/<tid>/offboarding/archive"): {"vendor_admin"},
    ("POST", "/api/tenants/<tid>/offboarding/purge"): {"vendor_admin"},
    ("POST", "/api/alerts/<int:i>/handoff"): {"hospital_admin", "l1", "l2"},
    ("GET", "/api/alerts/<int:i>/handoffs"): set(HOSPITAL_READ) | {"vendor_admin"},
    ("GET", "/api/alerts/<int:i>/response-approvals"): {"hospital_admin", "l1", "l2"},
    ("POST", "/api/alerts/<int:i>/response-approvals"): {"hospital_admin", "l1", "l2"},
    ("POST", "/api/response-approvals/<int:approval_id>/decision"): {"hospital_admin", "l2"},
    ("GET", "/api/metrics"): set(HOSPITAL_READ) | {"vendor_admin"},
    ("GET", "/api/exit-criteria"): set(HOSPITAL_READ) | {"vendor_admin"},
    ("GET", "/api/detection-quality"): set(HOSPITAL_READ) | {"vendor_admin"},
    ("GET", "/api/soc-visibility"): set(HOSPITAL_READ) | {"vendor_admin"},
    ("POST", "/api/demo"): {"vendor_admin"},
    ("POST", "/api/autolabel"): {"vendor_admin"},
    ("POST", "/api/reset"): {"vendor_admin"},
}
SAFE_ALERT_FIELDS = ("id", "created", "event_ts", "tenant", "rule", "rule_version", "severity",
                     "summary", "owner", "step", "status", "ack_at", "verdict", "source",
                     "last_handoff")
app = Flask(__name__, static_folder="static")
# PR 15: nginx is the only route to the app, so trust exactly one proxy hop. request.remote_addr then holds the real
# client address, which PR 14's per-source login limit needs. Nothing else can reach the app directly.
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)


def _int_setting(name, default):
    try:
        return int(os.environ.get(name, "") or default)
    except ValueError:
        return default


# CERT-In Directions (2022) require logs and records to be kept for at least 180 days. Lower values are refused.
RETENTION_DAYS = _int_setting("RETENTION_DAYS", 180)
if RETENTION_DAYS < 180:
    raise RuntimeError("RETENTION_DAYS must be at least 180 (CERT-In Directions 2022)")
app.config["MAX_CONTENT_LENGTH"] = _int_setting("INGEST_MAX_BODY_BYTES", 1_000_000)


def _ingest_limits():
    """Quotas per (tenant, log source) per minute, and the largest batch. Read on each request."""
    return {"events": _int_setting("INGEST_EVENTS_PER_MINUTE", 60000),
            "bytes": _int_setting("INGEST_BYTES_PER_MINUTE", 60_000_000),
            "max_batch": _int_setting("INGEST_MAX_BATCH", 1000)}


class RateLimited(Exception):
    def __init__(self, retry_after):
        super().__init__("ingest rate limit reached")
        self.retry_after = retry_after


@app.errorhandler(RateLimited)
def _rate_limited(e):
    response = jsonify(error="ingest rate limit reached for this log source; retry after the window",
                       retry_after=e.retry_after)
    response.status_code = 429
    response.headers["Retry-After"] = str(e.retry_after)
    return response


@app.errorhandler(413)
def _body_too_large(_e):
    return jsonify(error="request body is too large"), 413


def _spend_ingest_quota(c, tenant, log_source_id, events, payload_bytes, limits):
    """Charge one request to its (tenant, log source) minute window in one atomic statement. A refused request writes
    nothing, so a noisy source cannot use up another hospital's quota."""
    retry_after = max(1, 60 - datetime.now(timezone.utc).second)
    if events > limits["events"] or payload_bytes > limits["bytes"]:
        raise RateLimited(retry_after)
    row = c.execute(
        "INSERT INTO ingest_rate(tenant_id, log_source_id, window_start, events, payload_bytes) "
        "VALUES (%(t)s, %(s)s, date_trunc('minute', now()), %(e)s, %(b)s) "
        "ON CONFLICT (tenant_id, log_source_id, window_start) DO UPDATE SET "
        "events = ingest_rate.events + EXCLUDED.events, "
        "payload_bytes = ingest_rate.payload_bytes + EXCLUDED.payload_bytes "
        "WHERE ingest_rate.events + EXCLUDED.events <= %(max_e)s "
        "AND ingest_rate.payload_bytes + EXCLUDED.payload_bytes <= %(max_b)s "
        "RETURNING events",
        {"t": tenant, "s": log_source_id or 0, "e": events, "b": payload_bytes,
         "max_e": limits["events"], "max_b": limits["bytes"]}).fetchone()
    if row is None:
        raise RateLimited(retry_after)


def _occurred_at(ts):
    """The event's own time as an aware UTC datetime. A time with no zone is read as UTC."""
    if not isinstance(ts, str) or not ts.strip():
        raise Refuse(400, "each event needs a ts in ISO 8601 form")
    try:
        parsed = datetime.fromisoformat(ts.strip().replace("Z", "+00:00"))
    except ValueError:
        raise Refuse(400, "ts must be an ISO 8601 date and time")
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _dedupe_key(e):
    """Identity of an event for idempotent ingest: the sender's source event id when it has one, otherwise a SHA-256
    of the canonical payload. Server-assigned fields are excluded, so a replay gets the same key."""
    source_id = e.get("source_event_id")
    if isinstance(source_id, str) and source_id.strip():
        return "id:" + source_id.strip()[:200]
    payload = {k: v for k, v in e.items() if k not in ("tenant", "log_source_id", "occurred_at", "dedupe_key")}
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def endpoint_allows(method, route, identity):
    allowed = ROUTE_ROLES.get((method, route))
    if not allowed or not identity:
        return False
    if identity["kind"] == "ingest":
        return "ingest" in allowed
    return identity["kind"] == "session" and (
        "session" in allowed or identity["role"] in allowed)

GATE_NAMES = {
    "foundation": "Logs flow end to end",
    "detection": "All planted attacks detected",
    "response": "Every alert has an owner and a response step",
    "review": "False-positive rate within the agreed target",
}


class Row(dict):
    """A row that can be read by column name or by position, like sqlite3.Row."""

    def __getitem__(self, key):
        if isinstance(key, int):
            return list(self.values())[key]
        return dict.__getitem__(self, key)


def _row_factory(cursor):
    names = [d.name for d in (cursor.description or [])]

    def make(values):
        return Row(zip(names, values))
    return make


class Refuse(Exception):
    """Stop the request with an HTTP status and a message. Raised before any query that would touch other data."""

    def __init__(self, status, message):
        super().__init__(message)
        self.status = status
        self.message = message


@app.errorhandler(Refuse)
def _refused(e):
    identity = g.get("identity")
    context = g.get("ctx")
    ingest_rejected = e.status == 400 and identity and identity.get("kind") == "ingest"
    if (e.status in (401, 403, 404) or ingest_rejected) and identity and context and context.get("tenant"):
        c = db()
        c.rollback()
        _bind(c, context["tenant"], context["role"], context["actor_id"])
        route_args = request.view_args or {}
        resource_id = next((value for value in route_args.values() if isinstance(value, int)), None)
        _record_current_audit(
            c, action="ingest.reject" if ingest_rejected else "authorization.denied", resource_type="api_request",
            resource_id=resource_id, resource_classification="security_event", outcome="deny")
        commit()
    return jsonify(error=e.message), e.status


def connect(url=None):
    """A new connection as the runtime role. Raises if DATABASE_URL is not set."""
    url = url or os.environ.get("DATABASE_URL", "")
    if not url:
        raise RuntimeError("DATABASE_URL is required (the soc_app runtime connection string)")
    return psycopg.connect(url, row_factory=_row_factory)


def _bind(conn, tenant, role, actor_id):
    """Set the identity for the current transaction only. COMMIT or ROLLBACK clears it, so a pooled
    connection can never carry one request's identity into the next one."""
    tenant_value = tenant or ""
    role_value = role or ""
    actor_value = "" if actor_id is None else str(actor_id)
    conn.execute("SELECT set_config('app.current_tenant_id', %s, true), "
                 "set_config('app.current_actor_id', %s, true), "
                 "set_config('app.current_actor_role', %s, true), "
                 "set_config('app.tenant_id', %s, true), set_config('app.role', %s, true), "
                 "set_config('app.actor_id', %s, true)",
                 (tenant_value, actor_value, role_value, tenant_value, role_value, actor_value))


def db():
    """One connection per request, closed when the request ends (see _close_db)."""
    if "db" not in g:
        g.db = connect()
        ctx = g.get("ctx")
        if ctx:
            _bind(g.db, ctx["tenant"], ctx["role"], ctx["actor_id"])
    return g.db


def set_context(tenant, role, actor_id):
    g.ctx = {"tenant": tenant, "role": role, "actor_id": actor_id}
    _bind(db(), tenant, role, actor_id)


def commit():
    """Commit, then bind the identity again: the settings end with each transaction."""
    c = db()
    c.commit()
    ctx = g.get("ctx")
    _bind(c, ctx["tenant"] if ctx else None, ctx["role"] if ctx else None, ctx["actor_id"] if ctx else None)


@app.teardown_appcontext
def _close_db(exc):
    c = g.pop("db", None)
    if c is not None:
        c.close()


@app.after_request
def _commit_break_glass_audit(response):
    # A successful break-glass read must persist its audit row. Normal read-only requests
    # stay uncommitted; this commits the audit and the authorized read in the same transaction.
    if g.get("break_glass_read") and response.status_code < 400:
        commit()
    return response


def now():
    return datetime.now(timezone.utc).strftime(detect.FMT)


def _fp_target():
    """Agreed false-positive ceiling as a fraction, e.g. FP_TARGET=0.10. Unset until the team agrees a number."""
    raw = os.environ.get("FP_TARGET", "").strip()
    try:
        return float(raw) if raw else None
    except ValueError:
        return None


# Standard analytical verdicts. An alert with no verdict is "unlabeled" and is stored as NULL, never as a label.
TP_MALICIOUS = "true_positive_malicious"
TP_BENIGN = "true_positive_benign"
FALSE_POSITIVE = "false_positive"
INCONCLUSIVE = "inconclusive"
VERDICTS = (TP_MALICIOUS, TP_BENIGN, FALSE_POSITIVE, INCONCLUSIVE)
DECISIVE = (TP_MALICIOUS, TP_BENIGN, FALSE_POSITIVE)


def _quality_thresholds():
    """Tuning gate: a rule and log source group is evaluated against FP_TARGET only when it has this much label
    coverage and this many decisive labels. Invalid values fall back to the defaults."""
    try:
        coverage = float(os.environ.get("MIN_LABEL_COVERAGE", "0.80") or "0.80")
    except ValueError:
        coverage = 0.80
    try:
        sample = int(os.environ.get("MIN_LABELED_SAMPLE", "30") or "30")
    except ValueError:
        sample = 30
    return (coverage if 0 <= coverage <= 1 else 0.80), (sample if sample >= 1 else 30)


def audit(action, detail=""):
    """One row in the legacy audit log, for the identity that is currently bound."""
    ctx = g.ctx
    db().execute("INSERT INTO audit_log(tenant, actor_id, action, detail) VALUES (%s, %s, %s, %s)",
                 (ctx["tenant"], ctx["actor_id"], action, detail[:300]))


_AUDIT_VERDICTS = set(VERDICTS)
_AUDIT_STATUSES = {"new", "ack", "closed", "pending", "disabled"}
_AUDIT_DECISIONS = {"approved", "rejected"}
_AUDIT_SCOPES = {"events:read", "alerts:read", "handoffs:read", "metrics:read"}
_JOB_STATUSES = {"pending_approval", "rejected", "queued", "running", "succeeded", "dead"}


def redact_audit_metadata(metadata):
    """Keep only known, non-sensitive audit facts; free text, secrets, and PHI are dropped."""
    if not isinstance(metadata, dict):
        return {}
    safe = {}
    for key in ("verdict", "previous_verdict", "new_verdict"):
        value = metadata.get(key)
        if value is None or value in _AUDIT_VERDICTS:
            if key in metadata:
                safe[key] = value
    for key in ("status", "previous_status", "new_status"):
        value = metadata.get(key)
        if value in _AUDIT_STATUSES:
            safe[key] = value
    for key in ("role", "previous_role", "new_role"):
        value = metadata.get(key)
        if value in auth.HOSPITAL_ROLES:
            safe[key] = value
    for key in ("decision",):
        value = metadata.get(key)
        if value in _AUDIT_DECISIONS:
            safe[key] = value
    if metadata.get("scope") in _AUDIT_SCOPES:
        safe["scope"] = metadata["scope"]
    if metadata.get("priority") in {"high", "critical"}:
        safe["priority"] = metadata["priority"]
    for key in ("owner_from", "owner_to"):
        value = metadata.get(key)
        if value in ANALYSTS:
            safe[key] = value
    if metadata.get("monitoring_mode") in MONITORING_MODES:
        safe["monitoring_mode"] = metadata["monitoring_mode"]
    action = metadata.get("response_action")
    if action in RESPONSE_ACTIONS:
        safe["response_action"] = action
    if metadata.get("job_status") in _JOB_STATUSES:
        safe["job_status"] = metadata["job_status"]
    if metadata.get("risk_tier") in ("read_only", "disruptive"):
        safe["risk_tier"] = metadata["risk_tier"]
    for key in ("playbook_id", "playbook_version"):
        value = metadata.get(key)
        if isinstance(value, str) and re.fullmatch(r"[a-z0-9_.-]{1,40}", value):
            safe[key] = value
    for key in ("record_count", "alerts_created", "credential_id",
                "previous_credential_id", "new_credential_id", "log_source_id", "overlap_minutes",
                "users_disabled", "keys_revoked", "source_count", "changed_fields", "to_actor_id", "from_actor_id"):
        value = metadata.get(key)
        if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 10**12:
            safe[key] = value
    token_version_advanced = metadata.get("token_version_advanced")
    if isinstance(token_version_advanced, bool):
        safe["token_version_advanced"] = token_version_advanced
    return safe


def _session_audit_actor():
    identity = g.get("identity")
    if not identity or identity.get("kind") != "session" or identity.get("actor_id") is None:
        raise Refuse(401, "an authenticated user session is required")
    return identity


def record_audit_event(db_session, *, tenant_id, actor_id, actor_role, action, resource_type,
                       resource_id, resource_classification, outcome="allow", auth_context="session",
                       break_glass_grant_id=None, metadata=None, source_ip=None, device_id=None):
    """Append one redacted audit event using the caller's transaction."""
    if outcome not in ("allow", "deny", "error"):
        raise ValueError("invalid audit outcome")
    if auth_context not in ("session", "break_glass", "ingest_key", "system"):
        raise ValueError("invalid audit authentication context")
    safe_metadata = json.dumps(redact_audit_metadata(metadata), sort_keys=True, separators=(",", ":"))
    db_session.execute(
        "INSERT INTO audit_events(tenant_id, actor_id, actor_role, auth_context, break_glass_grant_id, "
        "action, resource_type, resource_id, resource_classification, outcome, metadata, request_id, "
        "source_ip, device_id) "
        "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s, %s, %s)",
        (tenant_id, actor_id, actor_role, auth_context, break_glass_grant_id, action, resource_type,
         str(resource_id) if resource_id is not None else None, resource_classification, outcome,
         safe_metadata, uuid.uuid4().hex, source_ip, device_id))


def _record_current_audit(db_session, *, action, resource_type, resource_id=None,
                          resource_classification="security_event", outcome="allow", metadata=None):
    identity = g.get("identity") or {}
    context = g.get("ctx") or {}
    tenant_id = context.get("tenant")
    if not tenant_id:
        raise RuntimeError("audit event requires a tenant-bound request context")
    kind = identity.get("kind")
    auth_context = "break_glass" if g.get("break_glass_read") else (
        "ingest_key" if kind == "ingest" else "session" if kind == "session" else "system")
    actor_id = identity.get("actor_id")
    actor_role = identity.get("role") or context.get("role") or "system"
    return record_audit_event(
        db_session, tenant_id=tenant_id, actor_id=actor_id, actor_role=actor_role,
        auth_context=auth_context, action=action, resource_type=resource_type,
        resource_id=resource_id, resource_classification=resource_classification,
        outcome=outcome, metadata=metadata, source_ip=request.remote_addr,
        device_id=request.headers.get("X-Device-ID"),
        break_glass_grant_id=g.get("break_glass_grant_id"))


def raise_alert(c, tenant, rule, sev, summary, key, event_ts, attack_id=None, source="builtin",
                detail="", step=None, log_source_id=None):
    dup = c.execute("SELECT 1 FROM alerts WHERE rule=%s AND tenant=%s AND dkey=%s AND event_ts>=%s",
                    (rule, tenant, key, detect._ago(event_ts, 10))).fetchone() if event_ts else None
    if dup:
        return None
    n = c.execute("SELECT COUNT(*) FROM alerts WHERE tenant=%s", (tenant,)).fetchone()[0]
    owner = ANALYSTS[n % len(ANALYSTS)]
    step = step or detect.PLAYBOOK.get(rule, "Review the alert details and decide: escalate, fix, or close as benign.")
    cur = c.execute("INSERT INTO alerts(created,event_ts,tenant,rule,rule_version,severity,summary,dkey,owner,step,attack_id,source,detail,log_source_id) "
                    "VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id",
                    (now(), event_ts, tenant, rule, detect.rule_version(rule), sev, summary, key, owner, step, attack_id, source, detail,
                     log_source_id))
    return cur.fetchone()["id"]


def _redact_text(value):
    """Mask credentials accidentally embedded in free text before telemetry leaves the service."""
    if not isinstance(value, str):
        return value
    import re
    value = re.sub(r"(?i)\b(bearer\s+)[A-Za-z0-9._~+/-]+=*", r"\1[REDACTED]", value)
    value = re.sub(r"(?i)\b(password|passwd|token|secret|api[_-]?key|authorization)\b\s*[:=]\s*[^\s,;]+",
                   r"\1=[REDACTED]", value)
    value = re.sub(r"\b[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}\b", "[EMAIL]", value)
    value = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "[IP]", value)
    value = re.sub(r"(?i)\b(user|patient|account)(?:\s+(?:id|name))?\s*[:=]\s*[^\s,;]+",
                   r"\1=[REDACTED]", value)
    return re.sub(r"(?i)(-enc(?:odedcommand)?\s+)[A-Za-z0-9+/=]+", r"\1[REDACTED]", value)


def _safe_alert(row):
    result = {key: row[key] for key in SAFE_ALERT_FIELDS if key in row}
    for key in ("summary", "step", "last_handoff"):
        if key in result:
            result[key] = _redact_text(result[key])
    return result


# ---- Identity ---------------------------------------------------------------------------------

def _token_from_request():
    token = (request.headers.get("Authorization") or "").removeprefix("Bearer ").strip()
    if not token and request.path.startswith("/api/ingest/"):
        token = request.args.get("token", "")  # Wazuh's integration cannot send headers
    return token


def _is_ingest_post():
    return request.method == "POST" and (request.path == "/api/events" or request.path.startswith("/api/ingest/"))


@app.before_request
def authenticate():
    """Resolve the caller once per request. Sets g.identity and the transaction context, or stops the request."""
    g.ctx = None
    g.identity = None
    if not request.path.startswith("/api/") or (request.method, request.path) in PUBLIC_ROUTES:
        return None
    token = _token_from_request()
    if not token:
        raise Refuse(401, "unauthorized")
    h = auth.token_hash(token)
    conn = db()
    key = conn.execute("SELECT * FROM auth_ingest_key(%s)", (h,)).fetchone()
    if key:
        if not _is_ingest_post():
            raise Refuse(403, "an ingest key can only send events; it cannot call this endpoint")
        g.identity = {"kind": "ingest", "tenant": key["key_tenant"], "role": "ingest", "actor_id": None,
                      "name": f"ingest-key-{key['key_id']}", "log_source_id": key["key_log_source_id"]}
        set_context(key["key_tenant"], "ingest", None)
        return None
    sess = conn.execute("SELECT * FROM auth_session(%s)", (h,)).fetchone()
    if (not sess or sess["user_status"] != "active" or not sess["user_is_active"]
            or sess["session_token_version"] != sess["user_token_version"]):
        raise Refuse(401, "unauthorized")
    if _is_ingest_post():
        raise Refuse(403, "event ingest needs an ingest key, not a user session")
    tenant = auth.PLATFORM_TENANT if sess["user_role"] == "vendor_admin" else sess["user_tenant"]
    g.identity = {"kind": "session", "tenant": tenant, "role": sess["user_role"],
                  "account_type": sess["user_account_type"], "token_version": sess["user_token_version"],
                  "actor_id": sess["user_id"], "name": sess["user_name"], "token_hash": h}
    set_context(tenant, sess["user_role"], sess["user_id"])
    if (os.environ.get("SOC_REQUIRE_PRIVILEGED_MFA") == "1" and sess["user_role"] in PRIVILEGED_MFA_ROLES
            and request.path not in MFA_ENROLMENT_PATHS):
        security = conn.execute("SELECT mfa_enabled FROM auth_user_security(%s)", (sess["user_id"],)).fetchone()
        if not security["mfa_enabled"]:
            raise Refuse(403, "MFA is required for this account: enrol with POST /api/mfa/setup, "
                              "then POST /api/mfa/verify")
    return None


@app.before_request
def gate_lab_endpoints():
    if not LAB_ENDPOINTS and request.path in LAB_PATHS:
        return jsonify(error="lab endpoint disabled (LAB_ENDPOINTS=0)"), 404
    return None


@app.before_request
def enforce_endpoint_rbac():
    """Deny API routes unless the method and matched route are explicitly in the role matrix."""
    if not request.path.startswith("/api/") or request.method == "OPTIONS":
        return None
    if (request.method, request.path) in PUBLIC_ROUTES:
        return None
    key = (request.method, request.url_rule.rule if request.url_rule else request.path)
    identity = g.get("identity")
    if not endpoint_allows(key[0], key[1], identity):
        raise Refuse(403, "endpoint is not authorized for this identity")
    return None


def _require_ingest():
    ident = g.identity
    if ident["kind"] != "ingest":
        raise Refuse(403, "this endpoint takes an ingest key")
    return ident


def _require_vendor():
    ident = g.identity
    if ident["kind"] != "session" or ident["role"] != "vendor_admin":
        raise Refuse(403, "vendor_admin only")
    return ident


_VENDOR_READ_SCOPES = {
    ("GET", "/api/events"): "events:read",
    ("GET", "/api/alerts"): "alerts:read",
    ("GET", "/api/alerts/<int:i>"): "alerts:read",
    ("GET", "/api/alerts/<int:i>/handoffs"): "handoffs:read",
    ("GET", "/api/metrics"): "metrics:read",
    ("GET", "/api/exit-criteria"): "metrics:read",
    ("GET", "/api/detection-quality"): "metrics:read",
    ("GET", "/api/soc-visibility"): "metrics:read",
}


def _active_break_glass_grant(tenant, scope):
    return db().execute(
        "SELECT grant_id, scope FROM break_glass_grants WHERE vendor_actor_id=%s AND tenant_id=%s "
        "AND scope=%s AND approved_at IS NOT NULL AND revoked_at IS NULL AND expires_at>now() "
        "ORDER BY approved_at DESC LIMIT 1",
        (g.identity["actor_id"], tenant, scope),
    ).fetchone()


def hospital_scope(*allowed):
    """The one hospital this request may work on. Refuses before any query when the caller is out of scope.

    - A hospital user works on their own hospital. A tenant_id in the request must equal it; otherwise 403.
    - A vendor admin reaches hospital data only where 'vendor_admin' is in `allowed` (reads), only with a
      tenant_id, and only with an active break-glass grant. Every such read is audited.
    """
    ident = g.identity
    wanted = request.args.get("tenant_id") or request.args.get("tenant") or None
    if ident["kind"] != "session":
        raise Refuse(403, "ingest keys cannot read or change hospital data")
    if ident["role"] == "vendor_admin":
        if "vendor_admin" not in allowed:
            raise Refuse(403, "vendor_admin has no routine access to this")
        if not wanted:
            raise Refuse(403, "name the hospital (tenant_id) to request break-glass access")
        route = (request.method, request.url_rule.rule if request.url_rule else request.path)
        required_scope = _VENDOR_READ_SCOPES.get(route)
        if not required_scope:
            raise Refuse(403, "this diagnostic endpoint is not in a supported break-glass scope")
        grant = _active_break_glass_grant(wanted, required_scope)
        if not grant:
            raise Refuse(403, "no active break-glass grant for this hospital and scope")
        set_context(wanted, "vendor_admin", ident["actor_id"])
        g.break_glass_read = True
        g.break_glass_grant_id = grant["grant_id"]
        audit("break_glass.read", request.path)
        _record_current_audit(
            db(), action="break_glass.access", resource_type="api_request",
            resource_classification="security_event", metadata={"scope": required_scope})
        return wanted
    if wanted and wanted != ident["tenant"]:
        raise Refuse(403, "tenant_id does not match your session")
    if ident["role"] not in allowed:
        raise Refuse(403, "your role cannot do this")
    if request.method != "GET" and _lifecycle(ident["tenant"]) != "active":
        raise Refuse(409, "this hospital is being offboarded; no new changes are accepted")
    return ident["tenant"]


def _grant_state(row):
    if row["revoked_at"] is not None:
        return "revoked"
    if row["approved_at"] is None:
        return "pending"
    return "active" if row["expires_at"] > datetime.now(timezone.utc) else "expired"


def _grant_json(row):
    return {
        "grant_id": str(row["grant_id"]), "vendor_actor_id": row["vendor_actor_id"],
        "tenant_id": row["tenant_id"], "ticket_id": row["ticket_id"], "reason": row["reason"],
        "scope": row["scope"], "requested_at": row["requested_at"],
        "approved_by": row["approved_by"], "approved_at": row["approved_at"],
        "expires_at": row["expires_at"], "revoked_at": row["revoked_at"],
        "reviewed_by": row["reviewed_by"], "reviewed_at": row["reviewed_at"],
        "state": _grant_state(row),
    }


def _grant_or_404(c, grant_id):
    row = c.execute("SELECT * FROM break_glass_grants WHERE grant_id=%s", (str(grant_id),)).fetchone()
    if not row:
        raise Refuse(404, "break-glass grant not found in this hospital")
    return row


@app.get("/api/break-glass/grants")
def list_break_glass_grants():
    c = db()
    rows = c.execute(
        "SELECT * FROM break_glass_grants ORDER BY requested_at DESC, grant_id DESC LIMIT 200"
    ).fetchall()
    _record_current_audit(
        c, action="break_glass.grant.list", resource_type="break_glass_grant",
        resource_classification="security_event", metadata={"record_count": len(rows)})
    commit()
    return jsonify(grants=[_grant_json(row) for row in rows])


@app.post("/api/break-glass/grants")
def request_break_glass_grant():
    ident = _require_vendor()
    body = _body(required=True)
    tenant = _text(body, "tenant_id", 120)
    ticket_id = _text(body, "ticket_id", 120)
    reason = _text(body, "reason", 1000)
    scope = _text(body, "scope", 80)
    if not tenant or not ticket_id or not reason or not scope:
        raise Refuse(400, "tenant_id, ticket_id, reason, and scope are required")
    if scope not in _AUDIT_SCOPES:
        raise Refuse(400, "scope must be events:read, alerts:read, handoffs:read, or metrics:read")
    ttl = body.get("ttl_minutes", 30)
    if isinstance(ttl, bool) or not isinstance(ttl, int) or not 1 <= ttl <= 60:
        raise Refuse(400, "ttl_minutes must be an integer between 1 and 60")
    c = db()
    if not c.execute("SELECT 1 FROM tenants WHERE id=%s", (tenant,)).fetchone() or tenant == auth.PLATFORM_TENANT:
        raise Refuse(404, "target hospital not found")
    set_context(tenant, "vendor_admin", ident["actor_id"])
    row = c.execute(
        "INSERT INTO break_glass_grants(actor_id, tenant, reason, granted_by, created, expires_at, "
        "vendor_actor_id, tenant_id, ticket_id, scope, requested_at, requested_ttl_minutes) "
        "VALUES (%s, %s, %s, %s, now(), now() + (%s * interval '1 minute'), %s, %s, %s, %s, now(), %s) "
        "RETURNING *",
        (ident["actor_id"], tenant, reason, ident["name"], ttl, ident["actor_id"], tenant,
         ticket_id, scope, ttl),
    ).fetchone()
    _record_current_audit(
        c, action="break_glass.request", resource_type="break_glass_grant",
        resource_id=row["grant_id"], resource_classification="security_event",
        metadata={"scope": scope})
    commit()
    return jsonify(_grant_json(row)), 201


@app.post("/api/break-glass/grants/<uuid:grant_id>/approve")
def approve_break_glass_grant(grant_id):
    c = db()
    row = _grant_or_404(c, grant_id)
    if row["approved_at"] is not None or row["revoked_at"] is not None:
        raise Refuse(409, "grant is no longer pending approval")
    actor = _session_audit_actor()
    approved = c.execute(
        "UPDATE break_glass_grants SET approved_by=%s, approved_at=now(), "
        "expires_at=now() + (requested_ttl_minutes * interval '1 minute') "
        "WHERE grant_id=%s AND approved_at IS NULL AND revoked_at IS NULL RETURNING *",
        (actor["actor_id"], str(grant_id)),
    ).fetchone()
    if not approved:
        raise Refuse(409, "grant is no longer pending approval")
    g.break_glass_grant_id = approved["grant_id"]
    _record_current_audit(
        c, action="break_glass.activate", resource_type="break_glass_grant",
        resource_id=approved["grant_id"], resource_classification="security_event",
        metadata={"scope": approved["scope"], "priority": "high"})
    event_time = now()
    alert = c.execute(
        "INSERT INTO alerts(created, event_ts, tenant, rule, rule_version, severity, summary, dkey, "
        "owner, step, source, detail) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING id",
        (event_time, event_time, approved["tenant_id"], "VENDOR_BREAK_GLASS_ACTIVATED", "1",
         "critical", "Vendor break-glass access activated; review the access grant.",
         "break-glass:" + str(approved["grant_id"]), ANALYSTS[0],
         "Review the vendor access request and confirm the session is limited to its approved scope.",
         "security", ""),
    ).fetchone()
    _record_current_audit(
        c, action="alert.create", resource_type="alert", resource_id=alert["id"],
        resource_classification="telemetry",
        metadata={"rule": "VENDOR_BREAK_GLASS_ACTIVATED", "severity": "critical"})
    commit()
    return jsonify(grant=_grant_json(approved), alert_id=alert["id"])


@app.post("/api/break-glass/grants/<uuid:grant_id>/revoke")
def revoke_break_glass_grant(grant_id):
    c = db()
    row = _grant_or_404(c, grant_id)
    if row["revoked_at"] is not None:
        raise Refuse(409, "grant is already revoked")
    actor = _session_audit_actor()
    updated = c.execute(
        "UPDATE break_glass_grants SET revoked_at=now() WHERE grant_id=%s AND revoked_at IS NULL RETURNING *",
        (str(grant_id),),
    ).fetchone()
    _record_current_audit(
        c, action="break_glass.revoke", resource_type="break_glass_grant",
        resource_id=grant_id, resource_classification="security_event",
        metadata={"scope": row["scope"]})
    commit()
    return jsonify(grant=_grant_json(updated), revoked_by=actor["actor_id"])


@app.post("/api/break-glass/grants/<uuid:grant_id>/review")
def review_break_glass_grant(grant_id):
    c = db()
    row = _grant_or_404(c, grant_id)
    if row["approved_at"] is None:
        raise Refuse(409, "pending grants do not need a post-session review")
    if row["revoked_at"] is None and c.execute(
        "SELECT %s::timestamptz > now() AS active", (row["expires_at"],)
    ).fetchone()["active"]:
        raise Refuse(409, "review is available after the grant expires or is revoked")
    if row["reviewed_at"] is not None:
        raise Refuse(409, "grant has already been reviewed")
    actor = _session_audit_actor()
    updated = c.execute(
        "UPDATE break_glass_grants SET reviewed_by=%s, reviewed_at=now() "
        "WHERE grant_id=%s AND reviewed_at IS NULL RETURNING *",
        (actor["actor_id"], str(grant_id)),
    ).fetchone()
    _record_current_audit(
        c, action="break_glass.review", resource_type="break_glass_grant",
        resource_id=grant_id, resource_classification="security_event",
        metadata={"scope": row["scope"]})
    commit()
    return jsonify(grant=_grant_json(updated))


def _body(required=False):
    body = request.get_json(force=True, silent=True)
    if body is None or not isinstance(body, dict):
        if required:
            raise Refuse(400, "send a JSON object")
        return {}
    return body


def _text(body, key, limit=None):
    """A request field as stripped text. Anything that is not a string counts as missing."""
    value = body.get(key)
    if not isinstance(value, str):
        value = ""
    value = value.strip()
    return value[:limit] if limit else value


def _alert_or_404(i):
    row = db().execute("SELECT id, owner, owner_user_id, status, tenant FROM alerts WHERE id=%s", (i,)).fetchone()
    if not row:
        raise Refuse(404, "alert not found")  # also what another hospital's alert returns
    return row


# ---- Events ingest ------------------------------------------------------------------------------

def _store_events(c, evs):
    """Store new events, skip identical ones, and run the detection rules on what was stored.
    Returns (alert ids, stored count, duplicate count). The caller commits."""
    made_ids, stored, duplicates = [], 0, 0
    for e in sorted(evs, key=lambda x: x["ts"]):
        e.setdefault("occurred_at", _occurred_at(e["ts"]))
        e.setdefault("dedupe_key", _dedupe_key(e))
        e.setdefault("attack_id", None)
        for k in ("user", "host", "ip", "patient", "detail", "source"):
            e.setdefault(k, "")
        for k in ("destination", "data_classification", "destination_approved", "src_zone", "dst_zone",
                  "boundary_violation", "approved_change", "log_source_id"):
            e.setdefault(k, None)
        row = c.execute('INSERT INTO events(ts,tenant,source,type,"user",host,ip,patient,detail,attack_id, '
                        'destination,data_classification,destination_approved,src_zone,dst_zone,boundary_violation,approved_change,log_source_id,'
                        'occurred_at,dedupe_key) '
                        "VALUES(%(ts)s,%(tenant)s,%(source)s,%(type)s,%(user)s,%(host)s,%(ip)s,%(patient)s,%(detail)s,%(attack_id)s, "
                        "%(destination)s,%(data_classification)s,%(destination_approved)s,%(src_zone)s,%(dst_zone)s,%(boundary_violation)s,%(approved_change)s,%(log_source_id)s,"
                        "%(occurred_at)s,%(dedupe_key)s) "
                        "ON CONFLICT (tenant, (COALESCE(log_source_id, 0)), dedupe_key, occurred_at) DO NOTHING RETURNING id",
                        e).fetchone()
        if row is None:
            duplicates += 1  # the same event was already stored: no second row and no second alert
            continue
        stored += 1
        hit = detect.evaluate(c, e)
        if hit:
            i = raise_alert(c, e["tenant"], *hit[:3], hit[3], e["ts"], e["attack_id"],
                            log_source_id=e.get("log_source_id"))
            if i:
                made_ids.append(i)
    return made_ids, stored, duplicates


@app.post("/api/events")
def ingest():
    ident = _require_ingest()
    raw_bytes = len(request.get_data(cache=True))
    body = request.get_json(force=True)
    evs = body if isinstance(body, list) else [body]
    limits = _ingest_limits()
    if len(evs) > limits["max_batch"]:
        raise Refuse(413, f"send at most {limits['max_batch']} events per request")
    now_utc = datetime.now(timezone.utc)
    for e in evs:
        if not isinstance(e, dict):
            raise Refuse(400, "each event must be a JSON object")
        # An ingest key is bound to one hospital and one log source. Events for any other hospital are refused.
        if e.get("tenant") not in (None, "", ident["tenant"]):
            raise Refuse(403, "event tenant does not match this ingest key")
        occurred = _occurred_at(e.get("ts"))
        if occurred < now_utc - timedelta(days=RETENTION_DAYS):
            raise Refuse(400, f"event is older than the {RETENTION_DAYS}-day retention window")
        if occurred > now_utc + timedelta(days=1):
            raise Refuse(400, "event time is more than a day in the future")
        e["tenant"] = ident["tenant"]
        e["log_source_id"] = ident["log_source_id"]
        e["occurred_at"] = occurred
        # Detection compares timestamps as text in detect.FMT, so store the canonical UTC form, whatever the sender sent.
        e["ts"] = occurred.strftime(detect.FMT)
    c = db()
    _spend_ingest_quota(c, ident["tenant"], ident["log_source_id"], len(evs), raw_bytes, limits)
    made_ids, stored, duplicates = _store_events(c, evs)
    _record_current_audit(
        c, action="event.ingest", resource_type="event_batch", resource_id=None,
        resource_classification="telemetry",
        metadata={"record_count": len(evs), "stored": stored, "duplicates": duplicates,
                  "alerts_created": len(made_ids)})
    for alert_id in made_ids:
        _record_current_audit(
            c, action="alert.create", resource_type="alert", resource_id=alert_id,
            resource_classification="telemetry", metadata={"status": "new"})
    commit()
    return jsonify(events=len(evs), stored=stored, duplicates=duplicates, alerts_created=len(made_ids))


@app.get("/api/events")
def list_events():
    """Read a tenant's event stream. Viewers and ingest keys cannot read event payloads."""
    tenant = hospital_scope("hospital_admin", "l1", "l2", "vendor_admin")
    try:
        limit = int(request.args.get("limit", "100"))
        before_id = int(request.args["before_id"]) if request.args.get("before_id") else None
    except ValueError:
        raise Refuse(400, "limit and before_id must be integers")
    if not 1 <= limit <= 500:
        raise Refuse(400, "limit must be between 1 and 500")
    if before_id is not None and before_id < 1:
        raise Refuse(400, "before_id must be positive")
    query = ('SELECT id, ts, tenant, source, type, host, data_classification, '
             'boundary_violation, approved_change, log_source_id FROM events WHERE tenant=%s')
    params = [tenant]
    if request.args.get("type"):
        query += " AND type=%s"
        params.append(request.args["type"])
    if request.args.get("host"):
        query += " AND host=%s"
        params.append(request.args["host"])
    if before_id is not None:
        query += " AND id < %s"
        params.append(before_id)
    rows = db().execute(query + " ORDER BY id DESC LIMIT %s", [*params, limit]).fetchall()
    events = [{key: _redact_text(row[key]) if key in ("source", "type", "host", "data_classification") else row[key]
               for key in row} for row in rows]
    _record_current_audit(
        db(), action="event.read", resource_type="event_batch", resource_id=None,
        resource_classification="telemetry", metadata={"record_count": len(rows)})
    commit()
    return jsonify(events=events, next_before_id=events[-1]["id"] if len(events) == limit else None)


@app.post("/api/ingest/wazuh")
def ingest_wazuh():
    """Accepts a Wazuh integration (webhook) alert and drops it in the same triage queue."""
    ident = _require_ingest()
    _spend_ingest_quota(db(), ident["tenant"], ident["log_source_id"], 1,
                        len(request.get_data(cache=True)), _ingest_limits())
    a = request.get_json(force=True)
    rule = a.get("rule") or {}
    rid = str(rule.get("id", "0"))
    lvl = int(rule.get("level", 3))
    sev = "critical" if lvl >= 12 else "high" if lvl >= 10 else "medium" if lvl >= 7 else "low"
    agent = (a.get("agent") or {}).get("name", "unknown")
    detail = detect.wazuh_detail(a)
    # Same rule on the same host but a different file/process is a different alert.
    key = f"{agent}|{detail}" if detail else agent
    c = db()
    i = raise_alert(c, ident["tenant"], f"WAZUH:{rid}", sev, f"{rule.get('description', 'Wazuh alert')} ({agent})",
                    key, a.get("timestamp", now())[:19], None, "wazuh",
                    detail=detail, step=detect.wazuh_step(rid, lvl), log_source_id=ident["log_source_id"])
    commit()
    return jsonify(alert_id=i)


# ---- Vendor: tenants ------------------------------------------------------------------------------

@app.get("/api/tenants")
def list_tenants():
    _require_vendor()
    rows = db().execute("SELECT id, name, created, lifecycle_state FROM tenants ORDER BY id").fetchall()
    return jsonify([dict(r) for r in rows])


@app.post("/api/tenants")
def create_tenant():
    _require_vendor()
    body = _body(required=True)
    tid = _text(body, "id")
    if not auth.TENANT_ID_RE.fullmatch(tid):
        raise Refuse(400, "id must be 2 to 63 lowercase letters, digits or hyphens, starting with a letter or digit")
    if tid == auth.PLATFORM_TENANT:
        raise Refuse(400, "'platform' is reserved for the vendor")
    name = _text(body, "name", 120) or tid
    c = db()
    if c.execute("SELECT 1 FROM tenants WHERE id=%s", (tid,)).fetchone():
        raise Refuse(409, "tenant already exists")
    c.execute("INSERT INTO tenants(id, name) VALUES(%s, %s)", (tid, name))
    audit("tenant.create", tid)
    commit()
    return jsonify(id=tid, name=name), 201


# ---- Hospital admin: users, log sources, credentials ----------------------------------------

@app.get("/api/users")
def list_users():
    hospital_scope("hospital_admin")
    rows = db().execute("SELECT id, username, email, role, account_type, is_active, token_version, status, created "
                        "FROM users ORDER BY id").fetchall()
    _record_current_audit(
        db(), action="user.list", resource_type="user_collection", resource_id=None,
        resource_classification="identity_metadata", metadata={"record_count": len(rows)})
    commit()
    return jsonify([dict(r) for r in rows])


@app.post("/api/users")
def create_user():
    tenant = hospital_scope("hospital_admin")
    body = _body(required=True)
    username = _text(body, "username").lower()
    email = _text(body, "email").lower()
    role = body.get("role")
    password = body.get("password")
    if not auth.USERNAME_RE.fullmatch(username):
        raise Refuse(400, "username must be 3 to 40 lowercase letters, digits, dots, hyphens or underscores")
    problem = auth.email_problem(email)
    if problem:
        raise Refuse(400, problem)
    if role not in auth.HOSPITAL_ROLES:
        raise Refuse(400, f"role must be one of: {', '.join(auth.HOSPITAL_ROLES)}")
    problem = auth.password_problem(password)
    if problem:
        raise Refuse(400, problem)
    c = db()
    if c.execute("SELECT 1 FROM users WHERE username=%s OR lower(email)=%s", (username, email)).fetchone():
        raise Refuse(409, "username or email already belongs to an account")
    row = c.execute("INSERT INTO users(tenant, username, email, role, account_type, is_active, password_hash) "
                    "VALUES(%s, %s, %s, %s, 'hospital_staff', TRUE, %s) "
                    "ON CONFLICT DO NOTHING RETURNING id",
                    (tenant, username, email, role, auth.hash_password(password))).fetchone()
    if not row:
        raise Refuse(409, "username or email already belongs to an account")
    _record_current_audit(
        c, action="user.create", resource_type="user", resource_id=row["id"],
        resource_classification="identity_metadata", metadata={"role": role})
    audit("user.create", f"{username} ({role})")
    commit()
    return jsonify(id=row["id"], username=username, email=email, role=role,
                   account_type="hospital_staff"), 201


@app.patch("/api/users/<int:uid>")
def change_user_role(uid):
    hospital_scope("hospital_admin")
    body = _body(required=True)
    role = body.get("role")
    if role not in auth.HOSPITAL_ROLES:
        raise Refuse(400, f"role must be one of: {', '.join(auth.HOSPITAL_ROLES)}")
    row = db().execute("SELECT username, role FROM users WHERE id=%s AND is_active", (uid,)).fetchone()
    if not row:
        raise Refuse(404, "user not found or inactive")
    if row["role"] == role:
        return jsonify(id=uid, role=role, token_version_advanced=False)
    c = db()
    c.execute("UPDATE users SET role=%s, token_version=token_version+1 WHERE id=%s", (role, uid))
    _record_current_audit(
        c, action="user.role.change", resource_type="user", resource_id=uid,
        resource_classification="identity_metadata", metadata={"previous_role": row["role"], "new_role": role})
    audit("user.role.change", f"{row['username']}: {row['role']} -> {role}")
    commit()
    return jsonify(id=uid, role=role, token_version_advanced=True)


@app.post("/api/users/<int:uid>/disable")
def disable_user(uid):
    hospital_scope("hospital_admin")
    if uid == g.identity["actor_id"]:
        raise Refuse(400, "you cannot disable your own account")
    c = db()
    row = c.execute("UPDATE users SET status='disabled', is_active=FALSE, token_version=token_version+1 "
                    "WHERE id=%s AND status='active' AND is_active RETURNING username", (uid,)).fetchone()
    if not row:
        raise Refuse(404, "user not found or already disabled")
    _record_current_audit(
        c, action="user.disable", resource_type="user", resource_id=uid,
        resource_classification="identity_metadata",
        metadata={"status": "disabled", "token_version_advanced": True})
    audit("user.disable", row["username"])
    commit()
    return jsonify(ok=True)


@app.get("/api/log-sources")
def list_log_sources():
    hospital_scope(*HOSPITAL_READ)
    rows = db().execute("SELECT id, name, kind, created, disabled_at FROM log_sources ORDER BY id").fetchall()
    return jsonify([dict(r) for r in rows])


@app.post("/api/log-sources")
def create_log_source():
    hospital_scope("hospital_admin")
    body = _body(required=True)
    name = _text(body, "name")
    if not name or len(name) > 80:
        raise Refuse(400, "name must be 1 to 80 characters")
    kind = _text(body, "kind", 40)
    c = db()
    if c.execute("SELECT 1 FROM log_sources WHERE name=%s", (name,)).fetchone():
        raise Refuse(409, "log source already exists in this hospital")
    row = c.execute("INSERT INTO log_sources(tenant, name, kind) VALUES(%s, %s, %s) RETURNING id",
                    (g.identity["tenant"], name, kind)).fetchone()
    audit("log_source.create", name)
    commit()
    return jsonify(id=row["id"], name=name, kind=kind), 201


@app.post("/api/log-sources/<int:sid>/disable")
def disable_log_source(sid):
    hospital_scope("hospital_admin")
    c = db()
    row = c.execute("UPDATE log_sources SET disabled_at=%s WHERE id=%s AND disabled_at IS NULL RETURNING name",
                    (now(), sid)).fetchone()
    if not row:
        raise Refuse(404, "log source not found or already disabled")
    audit("log_source.disable", row["name"])
    commit()
    return jsonify(ok=True)


@app.get("/api/credentials")
def list_credentials():
    """Ingest keys for this hospital. Metadata only: the key itself is shown once, when it is created."""
    hospital_scope("hospital_admin")
    rows = db().execute("SELECT id, label, log_source_id, key_prefix, created, revoked_at, retire_after "
                        "FROM ingest_keys ORDER BY id").fetchall()
    _record_current_audit(
        db(), action="credential.list", resource_type="credential_collection", resource_id=None,
        resource_classification="credential_metadata", metadata={"record_count": len(rows)})
    commit()
    return jsonify([dict(r) for r in rows])


@app.post("/api/credentials")
def create_credential():
    tenant = hospital_scope("hospital_admin")
    body = _body(required=True)
    sid = body.get("log_source_id")
    if not isinstance(sid, int):
        raise Refuse(400, "log_source_id must be a number")
    label = _text(body, "label", 80)
    c = db()
    # The log source is looked up under this hospital's identity, so another hospital's source is not found.
    if not c.execute("SELECT 1 FROM log_sources WHERE id=%s AND disabled_at IS NULL", (sid,)).fetchone():
        raise Refuse(404, "log source not found")
    key = secrets.token_urlsafe(32)
    row = c.execute("INSERT INTO ingest_keys(tenant, label, key_hash, key_prefix, log_source_id) "
                    "VALUES(%s, %s, %s, %s, %s) RETURNING id",
                    (tenant, label, auth.token_hash(key), key[:8], sid)).fetchone()
    _record_current_audit(
        c, action="credential.create", resource_type="ingest_key", resource_id=row["id"],
        resource_classification="credential_metadata",
        metadata={"credential_id": row["id"], "log_source_id": sid})
    audit("credential.create", f"key {row['id']} for log source {sid}")
    commit()
    return jsonify(id=row["id"], log_source_id=sid, label=label, key=key, key_prefix=key[:8],
                   note="Store this key now. It is not shown again."), 201


@app.post("/api/credentials/<int:kid>/revoke")
def revoke_credential(kid):
    hospital_scope("hospital_admin")
    c = db()
    row = c.execute("UPDATE ingest_keys SET revoked_at=COALESCE(revoked_at, %s) WHERE id=%s RETURNING id", (now(), kid)).fetchone()
    if not row:
        raise Refuse(404, "credential not found")
    _record_current_audit(
        c, action="credential.revoke", resource_type="ingest_key", resource_id=row["id"],
        resource_classification="credential_metadata", metadata={"credential_id": row["id"]})
    audit("credential.revoke", f"key {kid}")
    commit()
    return jsonify(ok=True)


@app.post("/api/credentials/<int:kid>/rotate")
def rotate_credential(kid):
    """Issue a new key for the same log source. The old key keeps working for overlap_minutes (0 to 1440, default 60),
    so the collector can switch over without a gap. Then it stops on its own, or the admin revokes it early."""
    tenant = hospital_scope("hospital_admin")
    body = _body()
    overlap = body.get("overlap_minutes", 60)
    if isinstance(overlap, bool) or not isinstance(overlap, int) or not 0 <= overlap <= 1440:
        raise Refuse(400, "overlap_minutes must be an integer between 0 and 1440")
    c = db()
    old = c.execute(
        "UPDATE ingest_keys SET retire_after = now() + (%s * interval '1 minute') "
        "WHERE id=%s AND revoked_at IS NULL AND (retire_after IS NULL OR retire_after > now()) "
        "RETURNING id, label, log_source_id, retire_after",
        (overlap, kid)).fetchone()
    if not old:
        raise Refuse(404, "credential not found or already retired")
    key = secrets.token_urlsafe(32)
    new = c.execute(
        "INSERT INTO ingest_keys(tenant, label, key_hash, key_prefix, log_source_id) VALUES(%s, %s, %s, %s, %s) RETURNING id",
        (tenant, old["label"], auth.token_hash(key), key[:8], old["log_source_id"])).fetchone()
    _record_current_audit(
        c, action="credential.rotate", resource_type="ingest_key", resource_id=new["id"],
        resource_classification="credential_metadata",
        metadata={"previous_credential_id": old["id"], "new_credential_id": new["id"],
                  "log_source_id": old["log_source_id"], "overlap_minutes": overlap})
    audit("credential.rotate", f"key {old['id']} -> {new['id']}")
    commit()
    return jsonify(id=new["id"], log_source_id=old["log_source_id"], label=old["label"], key=key,
                   key_prefix=key[:8], previous_credential_id=old["id"], previous_retire_after=old["retire_after"],
                   note="Store this key now. It is not shown again. The old key stops at previous_retire_after."), 201


# ---- Hospital onboarding: asset inventory and data-flow check ----------------------------------------

# Clinical equipment: a patient depends on these, so they are watched without an agent or an intrusive scan.
MEDICAL_CLASSES = ("mri", "ct", "x_ray", "ultrasound", "ventilator", "patient_monitor", "infusion_pump")
ASSET_CLASSES = MEDICAL_CLASSES + ("workstation", "server", "network_device", "other")
MONITORING_MODES = ("edr_managed", "agentless_medical", "network_infra", "unmanaged")
CRITICALITY = ("low", "medium", "high", "critical")
_MAC_RE = re.compile(r"[0-9A-F]{2}(:[0-9A-F]{2}){5}")


def _asset_fields(body, current=None):
    """Checked asset fields. On an update, `current` supplies the values that were not sent, so the result is checked as a whole."""
    current = current or {}

    def pick(key, default=""):
        return _text(body, key, 120) if key in body else (current.get(key) or default)

    device_name = pick("device_name")
    if not device_name:
        raise Refuse(400, "device_name is required")
    ip = pick("ip_address")
    if ip:
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            raise Refuse(400, "ip_address is not a valid IPv4 or IPv6 address")
    mac = pick("mac_address").upper()
    if mac and not _MAC_RE.fullmatch(mac):
        raise Refuse(400, "mac_address must look like 00:1A:2B:3C:4D:5E")
    asset_class = pick("asset_class", "workstation")
    if asset_class not in ASSET_CLASSES:
        raise Refuse(400, "asset_class must be one of: " + ", ".join(ASSET_CLASSES))
    monitoring_mode = pick("monitoring_mode")
    if monitoring_mode not in MONITORING_MODES:
        raise Refuse(400, "monitoring_mode must be one of: " + ", ".join(MONITORING_MODES))
    if asset_class in MEDICAL_CLASSES and monitoring_mode != "agentless_medical":
        raise Refuse(400, "clinical equipment must use monitoring_mode agentless_medical")
    criticality = pick("criticality", "medium")
    if criticality not in CRITICALITY:
        raise Refuse(400, "criticality must be one of: " + ", ".join(CRITICALITY))
    return {"device_name": device_name, "ip_address": ip, "mac_address": mac,
            "department": pick("department")[:80], "asset_class": asset_class,
            "monitoring_mode": monitoring_mode, "criticality": criticality}


@app.get("/api/assets")
def list_assets():
    tenant = hospital_scope(*HOSPITAL_READ)
    rows = db().execute(
        "SELECT asset_id, device_name, ip_address, mac_address, department, asset_class, monitoring_mode, "
        "criticality, last_seen_at FROM assets WHERE tenant_id=%s ORDER BY asset_id", (tenant,)).fetchall()
    return jsonify([dict(r) for r in rows])


@app.post("/api/assets")
def create_asset():
    tenant = hospital_scope("hospital_admin")
    fields = _asset_fields(_body(required=True))
    c = db()
    try:
        row = c.execute(
            "INSERT INTO assets(tenant_id, device_name, ip_address, mac_address, department, asset_class, "
            "monitoring_mode, criticality) VALUES (%s, %s, %s, %s, %s, %s, %s, %s) RETURNING asset_id",
            (tenant, fields["device_name"], fields["ip_address"], fields["mac_address"], fields["department"],
             fields["asset_class"], fields["monitoring_mode"], fields["criticality"])).fetchone()
    except psycopg.errors.UniqueViolation:
        raise Refuse(409, "an asset with this device_name already exists")
    _record_current_audit(
        c, action="asset.create", resource_type="asset", resource_id=row["asset_id"],
        resource_classification="telemetry", metadata={"monitoring_mode": fields["monitoring_mode"]})
    commit()
    return jsonify(asset_id=row["asset_id"], **fields), 201


@app.patch("/api/assets/<int:asset_id>")
def update_asset(asset_id):
    tenant = hospital_scope("hospital_admin")
    body = _body(required=True)
    c = db()
    current = c.execute("SELECT * FROM assets WHERE asset_id=%s AND tenant_id=%s", (asset_id, tenant)).fetchone()
    if not current:
        raise Refuse(404, "asset not found")
    fields = _asset_fields(body, dict(current))
    try:
        c.execute(
            "UPDATE assets SET device_name=%s, ip_address=%s, mac_address=%s, department=%s, asset_class=%s, "
            "monitoring_mode=%s, criticality=%s, updated=now() WHERE asset_id=%s AND tenant_id=%s",
            (fields["device_name"], fields["ip_address"], fields["mac_address"], fields["department"],
             fields["asset_class"], fields["monitoring_mode"], fields["criticality"], asset_id, tenant))
    except psycopg.errors.UniqueViolation:
        raise Refuse(409, "an asset with this device_name already exists")
    changed = sorted(k for k in fields if current.get(k) != fields[k])
    _record_current_audit(
        c, action="asset.update", resource_type="asset", resource_id=asset_id,
        resource_classification="telemetry", metadata={"changed_fields": len(changed)})
    commit()
    return jsonify(asset_id=asset_id, **fields)


@app.get("/api/data-flow")
def data_flow():
    """Is data arriving, and is it usable? Last event time, accepted and rejected counts, and a readiness sample."""
    tenant = hospital_scope("hospital_admin")
    c = db()
    since = (datetime.now(timezone.utc) - timedelta(hours=24)).strftime(detect.FMT)
    sources = c.execute(
        "SELECT ls.id, ls.name, ls.kind, ls.disabled_at IS NOT NULL AS disabled, "
        "(SELECT max(e.ts) FROM events e WHERE e.tenant = ls.tenant AND e.log_source_id = ls.id) AS last_seen_event_ts, "
        "(SELECT count(*) FROM events e WHERE e.tenant = ls.tenant AND e.log_source_id = ls.id AND e.ts >= %s) "
        "AS accepted_24h FROM log_sources ls WHERE ls.tenant = %s ORDER BY ls.id", (since, tenant)).fetchall()
    rejected = c.execute(
        "SELECT count(*) FROM audit_events WHERE tenant_id = %s AND action = 'ingest.reject' "
        "AND occurred_at >= now() - interval '24 hours'", (tenant,)).fetchone()[0]
    sample = c.execute('SELECT ts, source, type, host, "user" FROM events WHERE tenant = %s ORDER BY id DESC LIMIT 20',
                       (tenant,)).fetchall()
    ready = [bool(r["ts"] and r["source"] and r["type"] and (r["host"] or r["user"])) for r in sample]
    _record_current_audit(
        c, action="data_flow.verify", resource_type="log_source_collection", resource_id=None,
        resource_classification="telemetry", metadata={"source_count": len(sources)})
    commit()
    last_seen = max((s_["last_seen_event_ts"] for s_ in sources if s_["last_seen_event_ts"]), default=None)
    return jsonify(
        last_seen_event_ts=last_seen,
        accepted_24h=sum(s_["accepted_24h"] for s_ in sources),
        rejected_24h=rejected,
        sources=[dict(s_) for s_ in sources],
        readiness={"checked": len(ready), "normalized": sum(ready),
                   "note": "a sampled event is ready when it has time, source, type and host or user"})


# ---- Hospital offboarding: separate from vendor support -----------------------------------------------

def _lifecycle(tenant):
    row = db().execute("SELECT lifecycle_state FROM tenants WHERE id=%s", (tenant,)).fetchone()
    return row["lifecycle_state"] if row else None


@app.post("/api/offboarding/start")
def start_offboarding():
    """The hospital admin starts offboarding. Every login and ingest key stops, and no new changes are accepted."""
    tenant = hospital_scope("hospital_admin")
    c = db()
    if not c.execute("SELECT set_tenant_lifecycle(%s, 'active', 'offboarding') AS ok", (tenant,)).fetchone()["ok"]:
        raise Refuse(409, "this hospital is not active")
    disabled = c.execute("UPDATE users SET is_active = FALSE, status = 'disabled', token_version = token_version + 1 "
                         "WHERE tenant = %s AND is_active", (tenant,)).rowcount
    revoked = c.execute("UPDATE ingest_keys SET revoked_at = COALESCE(revoked_at, %s) "
                        "WHERE tenant = %s AND revoked_at IS NULL", (now(), tenant)).rowcount
    _record_current_audit(
        c, action="tenant.offboarding.start", resource_type="tenant", resource_id=None,
        resource_classification="security_event", metadata={"users_disabled": disabled, "keys_revoked": revoked})
    commit()
    return jsonify(state="offboarding", users_disabled=disabled, keys_revoked=revoked)


def _vendor_hospital(tid):
    """The vendor's checks for an offboarding step: a real hospital, not the platform itself."""
    ident = _require_vendor()
    row = None if (not tid or tid == auth.PLATFORM_TENANT) else db().execute(
        "SELECT id, lifecycle_state FROM tenants WHERE id=%s", (tid,)).fetchone()
    if not row:
        raise Refuse(404, "hospital not found")
    return ident, row["lifecycle_state"]


def _vendor_audit(c, ident, tid, action, metadata):
    """A vendor step is written into the hospital's own audit trail, in the same transaction as the step."""
    set_context(tid, "vendor_admin", ident["actor_id"])
    record_audit_event(c, tenant_id=tid, actor_id=ident["actor_id"], actor_role="vendor_admin", action=action,
                       resource_type="tenant", resource_id=tid, resource_classification="security_event",
                       outcome="allow", auth_context="session", metadata=metadata, source_ip=request.remote_addr)


@app.post("/api/tenants/<tid>/offboarding/export")
def export_tenant(tid):
    """Compliance export hook. Records what the hospital holds and a digest of it. Delivering the bundle is wired up per hospital."""
    ident, state = _vendor_hospital(tid)
    if state not in ("offboarding", "archived"):
        raise Refuse(409, "export is available while a hospital is offboarding or archived")
    c = db()
    counts = c.execute("SELECT tenant_export_counts(%s) AS counts", (tid,)).fetchone()["counts"]
    digest = hashlib.sha256(json.dumps(counts, sort_keys=True).encode()).hexdigest()
    _vendor_audit(c, ident, tid, "tenant.export", {"record_count": sum(counts.values())})
    commit()
    return jsonify(tenant=tid, state=state, record_counts=counts, digest_sha256=digest)


@app.post("/api/tenants/<tid>/offboarding/archive")
def archive_tenant(tid):
    ident, state = _vendor_hospital(tid)
    c = db()
    if state != "offboarding":
        raise Refuse(409, "only a hospital that is offboarding can be archived")
    if not c.execute("SELECT tenant_exported(%s) AS ok", (tid,)).fetchone()["ok"]:
        raise Refuse(409, "export the hospital's records before archiving")
    if not c.execute("SELECT set_tenant_lifecycle(%s, 'offboarding', 'archived') AS ok", (tid,)).fetchone()["ok"]:
        raise Refuse(409, "the hospital changed state; reload and try again")
    _vendor_audit(c, ident, tid, "tenant.archive", {})
    commit()
    return jsonify(tenant=tid, state="archived")


@app.post("/api/tenants/<tid>/offboarding/purge")
def purge_tenant(tid):
    """Delete the hospital's operational data. Audit rows and the tenant record stay. Users are anonymised."""
    ident, state = _vendor_hospital(tid)
    if state != "archived":
        raise Refuse(409, "only an archived hospital can be purged")
    c = db()
    if not c.execute("SELECT tenant_exported(%s) AS ok", (tid,)).fetchone()["ok"]:
        raise Refuse(409, "export the hospital's records before purging")
    try:
        removed = c.execute("SELECT purge_tenant_data(%s) AS counts", (tid,)).fetchone()["counts"]
    except psycopg.Error:
        raise Refuse(409, "the purge was refused; the hospital's data is unchanged")
    _vendor_audit(c, ident, tid, "tenant.purge", {"record_count": sum(removed.values())})
    commit()
    return jsonify(tenant=tid, state="purged", removed=removed)


# ---- Sessions ------------------------------------------------------------------------------------

# PR 14: login lockout, login rate limits and TOTP MFA.
LOCKOUT_FAILURES = 5
LOCKOUT_SECONDS = 15 * 60
LOGIN_WINDOW_SECONDS = 15 * 60
PRIVILEGED_MFA_ROLES = ("hospital_admin", "l2", "vendor_admin")
# Routes an account may use before it enrols when SOC_REQUIRE_PRIVILEGED_MFA=1: enrolment itself, sign-out, identity.
MFA_ENROLMENT_PATHS = {"/api/mfa/setup", "/api/mfa/verify", "/api/logout", "/api/me"}
# One message for every failed sign-in, so a caller cannot tell which factor was wrong.
INVALID_LOGIN = "invalid tenant, username, password or code"


def mfa_key():
    """SOC_SECRET_KEY encrypts TOTP secrets. Without it no MFA route or login check runs: the request fails closed."""
    key = os.environ.get("SOC_SECRET_KEY", "")
    if not key:
        raise Refuse(503, "MFA is not configured: SOC_SECRET_KEY is not set")
    return key


def _auth_event(c, tenant, role, user_id, action, outcome, reason=None):
    """A high-priority auth record in audit_events. The identity is bound first, because the table's policy checks it."""
    set_context(tenant, role, user_id)
    metadata = {"priority": "high"} | ({"reason": reason} if reason else {})
    record_audit_event(c, tenant_id=tenant, actor_id=user_id, actor_role=role, action=action,
                       resource_type="auth", resource_id=user_id, resource_classification="security_event",
                       outcome=outcome, auth_context="system", metadata=metadata, source_ip=request.remote_addr)


def _count_login_failure(c, row, tenant, reason):
    """Counts one failed password or code against a real account, audits it, and commits. The caller then refuses."""
    state = c.execute("SELECT locked, failed FROM auth_login_failed(%s, %s, %s)",
                      (row["user_id"], LOCKOUT_FAILURES, LOCKOUT_SECONDS)).fetchone()
    action = "auth.lockout" if state["locked"] else ("auth.mfa.fail" if reason == "mfa" else "auth.password.fail")
    _auth_event(c, tenant, row["user_role"], row["user_id"], action, "deny", reason)
    commit()


@app.post("/api/login")
def login():
    body = _body(required=True)
    tenant = _text(body, "tenant")
    username = _text(body, "username").lower()
    password = body.get("password") if isinstance(body.get("password"), str) else ""
    code = body.get("totp_code") if isinstance(body.get("totp_code"), str) else ""
    if not (tenant and username and password):
        raise Refuse(400, "tenant, username and password are required")
    c = db()
    # Every attempt counts, right or wrong, against (source address, tenant, username).
    spend = c.execute(
        "SELECT allowed, retry_after FROM auth_login_rate_spend(%s, %s, %s, %s, %s)",
        (request.remote_addr or "", tenant, username, _int_setting("SOC_LOGIN_RATE_LIMIT", 20),
         LOGIN_WINDOW_SECONDS)).fetchone()
    if not spend["allowed"]:
        commit()
        response = jsonify(error="too many login attempts; retry after the window")
        response.status_code = 429
        response.headers["Retry-After"] = str(spend["retry_after"])
        return response
    row = c.execute("SELECT * FROM auth_user_for_login(%s, %s)", (tenant, username)).fetchone()
    stored = row["user_password_hash"] if row else auth.DUMMY_HASH
    password_ok = auth.verify_password(password, stored)
    if not row or row["user_status"] != "active" or not row["user_is_active"]:
        print(f"login refused for tenant {tenant}", file=sys.stderr, flush=True)
        raise Refuse(401, INVALID_LOGIN)
    context_tenant = auth.PLATFORM_TENANT if row["user_role"] == "vendor_admin" else row["user_tenant"]
    if not password_ok:
        _count_login_failure(c, row, context_tenant, "password")
        raise Refuse(401, INVALID_LOGIN)
    security = c.execute("SELECT * FROM auth_user_security(%s)", (row["user_id"],)).fetchone()
    if security["locked"]:
        _auth_event(c, context_tenant, row["user_role"], row["user_id"], "auth.lockout.refused", "deny", "locked")
        commit()
        raise Refuse(423, f"account is locked after repeated failures; try again in {security['lock_seconds']} seconds")
    if security["mfa_enabled"]:
        if not code.strip():
            response = jsonify(error="enter the 6-digit code from your authenticator app", mfa_required=True)
            response.status_code = 401
            return response
        secret = auth.decrypt_secret(security["mfa_secret_enc"] or "", mfa_key())
        if secret is None:
            raise Refuse(503, "MFA secret cannot be read: SOC_SECRET_KEY does not match the key it was saved with")
        step = auth.verify_totp(secret, code, last_counter=security["mfa_last_counter"])
        if step is None or not c.execute("SELECT auth_mfa_consume(%s, %s)", (row["user_id"], step)).fetchone()[0]:
            _count_login_failure(c, row, context_tenant, "mfa")
            raise Refuse(401, INVALID_LOGIN)
        _auth_event(c, context_tenant, row["user_role"], row["user_id"], "auth.mfa.verify", "allow")
    c.execute("SELECT auth_login_succeeded(%s)", (row["user_id"],))
    token = auth.new_token()
    set_context(context_tenant, row["user_role"], row["user_id"])
    c.execute("INSERT INTO sessions(token_hash, user_id, token_version, expires_at) "
              "VALUES (%s, %s, %s, now() + make_interval(secs => %s))",
              (auth.token_hash(token), row["user_id"], row["user_token_version"], SESSION_HOURS * 3600.0))
    audit("login")
    commit()
    return jsonify(token=token, tenant=context_tenant, role=row["user_role"], username=username,
                   expires_in_hours=SESSION_HOURS)


@app.post("/api/logout")
def logout():
    if g.identity["kind"] != "session":
        raise Refuse(403, "not a user session")
    c = db()
    c.execute("DELETE FROM sessions WHERE token_hash=%s", (g.identity["token_hash"],))
    audit("logout")
    commit()
    return jsonify(ok=True)


@app.get("/api/me")
def me():
    ident = g.identity
    return jsonify(kind=ident["kind"], username=ident.get("name"), tenant=ident["tenant"], role=ident["role"])


@app.get("/api/settings")
def get_hospital_settings():
    tenant = hospital_scope("hospital_admin")
    row = db().execute("SELECT id, name, created FROM tenants WHERE id=%s", (tenant,)).fetchone()
    if not row:
        raise Refuse(404, "hospital not found")
    return jsonify(tenant=row["id"], name=row["name"], created=row["created"])


@app.put("/api/settings")
def update_hospital_settings():
    tenant = hospital_scope("hospital_admin")
    body = _body(required=True)
    if "tenant" in body:
        requested_tenant = body["tenant"]
        if not isinstance(requested_tenant, str) or not requested_tenant.strip():
            raise Refuse(400, "tenant must be a non-empty string when supplied")
        if requested_tenant != tenant:
            raise Refuse(403, "tenant does not match your session")
    raw_name = body.get("name")
    name = raw_name.strip() if isinstance(raw_name, str) else ""
    if not name or len(name) > 120:
        raise Refuse(400, "name must be 1 to 120 characters")
    row = db().execute("UPDATE tenants SET name=%s WHERE id=%s RETURNING id, name", (name, tenant)).fetchone()
    if not row:
        raise Refuse(404, "hospital not found")
    audit("tenant.settings.update", f"name={name}")
    commit()
    return jsonify(tenant=row["id"], name=row["name"])


# ---- Triage --------------------------------------------------------------------------------------

@app.get("/api/alerts")
def alerts():
    tenant = hospital_scope(*HOSPITAL_READ, "vendor_admin")
    # Keep alert responses to a telemetry allowlist; free-form detail and resolution can carry secrets or PHI.
    q = ("SELECT id, created, event_ts, tenant, rule, rule_version, severity, summary, owner, step, status, ack_at, "
         "verdict, source, (SELECT from_owner || ' -> ' || to_owner "
         "FROM handoffs h WHERE h.alert_id = alerts.id ORDER BY h.id DESC LIMIT 1) AS last_handoff "
         "FROM alerts WHERE tenant=%s")
    args = [tenant]
    for f in ("status", "owner"):
        if request.args.get(f):
            q += f" AND {f}=%s"
            args.append(request.args[f])
    rows = db().execute(q + " ORDER BY id DESC LIMIT 200", args).fetchall()
    return jsonify([_safe_alert(r) for r in rows])


@app.get("/api/alerts/<int:i>")
def alert_detail(i):
    """Return the safe telemetry view for one alert in the caller's hospital."""
    tenant = hospital_scope(*HOSPITAL_READ, "vendor_admin")
    row = db().execute(
        "SELECT id, created, event_ts, tenant, rule, rule_version, severity, summary, owner, step, status, ack_at, "
        "verdict, source, (SELECT from_owner || ' -> ' || to_owner "
        "FROM handoffs h WHERE h.alert_id = alerts.id ORDER BY h.id DESC LIMIT 1) AS last_handoff "
        "FROM alerts WHERE id=%s AND tenant=%s", (i, tenant)).fetchone()
    if not row:
        raise Refuse(404, "alert not found")
    _record_current_audit(
        db(), action="alert.detail.read", resource_type="alert", resource_id=i,
        resource_classification="telemetry")
    commit()
    return jsonify(_safe_alert(row))


@app.post("/api/alerts/<int:i>/ack")
def ack(i):
    hospital_scope("hospital_admin", "l1", "l2")
    actor = _session_audit_actor()
    row = _alert_or_404(i)
    c = db()
    c.execute("UPDATE alerts SET status='ack', ack_at=%s, acknowledged_by=%s, acknowledged_at=now() "
              "WHERE id=%s AND status='new'", (now(), actor["actor_id"], i))
    _record_current_audit(
        c, action="alert.ack", resource_type="alert", resource_id=i,
        resource_classification="telemetry",
        metadata={"previous_status": row["status"], "status": "ack"})
    commit()
    return jsonify(ok=True)


@app.post("/api/alerts/<int:i>/verdict")
def verdict(i):
    hospital_scope("hospital_admin", "l2")
    actor = _session_audit_actor()
    body = _body(required=True)
    v = body.get("verdict")
    if v not in VERDICTS:
        raise Refuse(400, "verdict must be one of: " + ", ".join(VERDICTS))
    note = _text(body, "note", 500)  # optional closing note, kept with the alert
    row = _alert_or_404(i)
    c = db()
    c.execute("UPDATE alerts SET verdict=%s, status='closed', ack_at=COALESCE(ack_at,%s), "
              "acknowledged_by=COALESCE(acknowledged_by,%s), acknowledged_at=COALESCE(acknowledged_at,now()), "
              "verdict_by=%s, verdict_at=now(), resolution=COALESCE(NULLIF(%s,''), resolution) WHERE id=%s",
              (v, now(), actor["actor_id"], actor["actor_id"], note, i))
    _record_current_audit(
        c, action="alert.verdict", resource_type="alert", resource_id=i,
        resource_classification="telemetry",
        metadata={"previous_verdict": row.get("verdict"), "new_verdict": v})
    audit("alert.verdict", f"alert {i}: {v}")
    commit()
    return jsonify(ok=True)


@app.get("/api/analysts")
def analysts():
    """Active analysts of this hospital. Their user ids are what a handoff names."""
    tenant = hospital_scope(*HOSPITAL_READ)
    rows = db().execute("SELECT user_id, username, user_role FROM hospital_analysts(%s)", (tenant,)).fetchall()
    return jsonify(analysts=[dict(r) for r in rows])


@app.post("/api/alerts/<int:i>/handoff")
def handoff(i):
    """Pass an open alert to another active analyst of the same hospital. Both users are recorded by id."""
    hospital_scope("hospital_admin", "l1", "l2")
    actor = _session_audit_actor()
    body = _body(required=True)
    if "to_owner" in body:
        raise Refuse(400, "to_owner is retired: send to_actor_id (an id from GET /api/analysts)")
    to_id = body.get("to_actor_id")
    if isinstance(to_id, bool) or not isinstance(to_id, int):
        raise Refuse(400, "to_actor_id must be the id of an active analyst in this hospital")
    note = _text(body, "note", 500)
    row = _alert_or_404(i)
    if row["status"] == "closed":
        raise Refuse(409, "alert is closed")
    target = db().execute("SELECT handoff_target_name(%s, %s) AS name", (row["tenant"], to_id)).fetchone()["name"]
    if not target:
        raise Refuse(400, "to_actor_id must be an active analyst in this hospital")
    if row["owner_user_id"] == to_id or (row["owner_user_id"] is None and row["owner"] == target):
        raise Refuse(400, f"alert is already owned by {target}")
    c = db()
    c.execute("INSERT INTO handoffs(alert_id,at,from_owner,to_owner,note,tenant,from_user_id,to_user_id) "
              "VALUES(%s,%s,%s,%s,%s,%s,%s,%s)",
              (i, now(), row["owner"], target, note, row["tenant"], actor["actor_id"], to_id))
    c.execute("UPDATE alerts SET owner=%s, owner_user_id=%s WHERE id=%s", (target, to_id, i))
    _record_current_audit(
        c, action="alert.handoff", resource_type="alert", resource_id=i,
        resource_classification="telemetry",
        metadata={"from_actor_id": actor["actor_id"], "to_actor_id": to_id})
    audit("alert.handoff", f"alert {i} to {target}")
    commit()
    return jsonify(ok=True, from_owner=row["owner"], to_owner=target, to_actor_id=to_id)


@app.get("/api/alerts/<int:i>/handoffs")
def handoffs(i):
    hospital_scope(*HOSPITAL_READ, "vendor_admin")
    _alert_or_404(i)
    rows = db().execute("SELECT at, from_owner, to_owner FROM handoffs WHERE alert_id=%s ORDER BY id", (i,)).fetchall()
    _record_current_audit(
        db(), action="alert.handoffs.read", resource_type="alert", resource_id=i,
        resource_classification="telemetry", metadata={"record_count": len(rows)})
    commit()
    return jsonify([dict(r) for r in rows])


RESPONSE_ACTIONS = {"isolate_host", "disable_account", "block_ip"}


@app.get("/api/alerts/<int:i>/response-approvals")
def list_response_approvals(i):
    hospital_scope("hospital_admin", "l1", "l2")
    _alert_or_404(i)
    rows = db().execute(
        "SELECT id, alert_id, action, target, reason, status, requested_by, requested_at, "
        "approved_by, decided_at, decision_note FROM response_approvals "
        "WHERE alert_id=%s ORDER BY id DESC", (i,)).fetchall()
    _record_current_audit(
        db(), action="response_approval.list", resource_type="alert", resource_id=i,
        resource_classification="security_event", metadata={"record_count": len(rows)})
    commit()
    return jsonify([{key: _redact_text(value) if key in ("target", "reason", "decision_note") else value
                     for key, value in row.items()} for row in rows])


MEDICAL_REFUSAL = "disruptive containment is blocked on medical equipment (IEC 80001)"


def _asset_for_target(tenant, action, target):
    """The hospital's asset that a host or IP target names, or None. Accounts name no asset."""
    if action not in ("isolate_host", "block_ip"):
        return None
    return db().execute(
        "SELECT asset_id, device_name, asset_class, monitoring_mode FROM assets "
        "WHERE tenant_id=%s AND (device_name=%s OR ip_address=%s) ORDER BY asset_id LIMIT 1",
        (tenant, target, target)).fetchone()


def _is_medical(asset):
    return asset["asset_class"] in MEDICAL_CLASSES or asset["monitoring_mode"] == "agentless_medical"


@app.post("/api/alerts/<int:i>/response-approvals")
def request_response_approval(i):
    """Ask for a response. The server picks the playbook from its allowlist; a disruptive one is queued only after a
    second person approves it (maker-checker)."""
    tenant = hospital_scope("hospital_admin", "l1", "l2")
    body = _body(required=True)
    if set(body) - {"action", "target", "reason"}:
        raise Refuse(400, "only action, target and reason are accepted; the server chooses the playbook")
    action = body.get("action")
    if action not in RESPONSE_ACTIONS:
        raise Refuse(400, f"action must be one of: {', '.join(sorted(RESPONSE_ACTIONS))}")
    try:
        target = playbooks.validate_target(action, body.get("target"))
    except playbooks.TargetRefused as e:
        raise Refuse(400, str(e))
    reason_raw = body.get("reason")
    reason = reason_raw.strip() if isinstance(reason_raw, str) else ""
    if not reason or len(reason) > 500:
        raise Refuse(400, "reason must be 1 to 500 characters")
    alert = _alert_or_404(i)
    if alert["status"] == "closed":
        raise Refuse(409, "cannot request a response for a closed alert")
    pb = playbooks.playbook_for(action)
    asset = _asset_for_target(tenant, action, target)
    if asset is None and action == "isolate_host":
        raise Refuse(400, "target is not an asset of this hospital")
    if asset is not None and pb.tier == "disruptive" and _is_medical(asset):
        raise Refuse(409, MEDICAL_REFUSAL)
    pending = db().execute(
        "SELECT id FROM response_approvals WHERE alert_id=%s AND action=%s AND target=%s AND status='pending'",
        (i, action, target)).fetchone()
    if pending:
        raise Refuse(409, "a matching response approval is already pending")
    row = db().execute(
        "INSERT INTO response_approvals(tenant, alert_id, action, target, reason, requested_by) "
        "VALUES(%s, %s, %s, %s, %s, %s) "
        "ON CONFLICT (alert_id, action, target) WHERE status='pending' DO NOTHING "
        "RETURNING id, status",
        (tenant, i, action, target, reason, g.identity["actor_id"])).fetchone()
    if not row:
        raise Refuse(409, "a matching response approval is already pending")
    job_status = "pending_approval" if pb.tier == "disruptive" else "queued"
    job = db().execute(
        "INSERT INTO response_jobs(tenant_id, alert_id, action_type, risk_tier, playbook_id, playbook_version, "
        "playbook_digest, target_asset_id, target_host, idempotency_key, status, requested_by) "
        "VALUES(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING job_id",
        (tenant, i, action, pb.tier, pb.playbook_id, pb.version, pb.sha256,
         asset["asset_id"] if asset else None, target, f"approval:{row['id']}", job_status,
         g.identity["actor_id"])).fetchone()
    _record_current_audit(
        db(), action="response_approval.request", resource_type="response_approval", resource_id=row["id"],
        resource_classification="security_event",
        metadata={"response_action": action, "status": row["status"]})
    _record_current_audit(
        db(), action="response_job.request", resource_type="response_job", resource_id=job["job_id"],
        resource_classification="security_event",
        metadata={"response_action": action, "playbook_id": pb.playbook_id, "playbook_version": pb.version,
                  "risk_tier": pb.tier, "job_status": job_status})
    audit("response_approval.request", f"approval {row['id']}: {action} for alert {i}")
    commit()
    return jsonify(id=row["id"], job_id=job["job_id"], alert_id=i, action=action, target=_redact_text(target),
                   status=row["status"], job_status=job_status, playbook_id=pb.playbook_id,
                   playbook_version=pb.version, execution="not_performed"), 201


@app.post("/api/response-approvals/<int:approval_id>/decision")
def decide_response_approval(approval_id):
    """A second person decides. Approval queues the job; rejection closes it. The requester can never decide."""
    tenant = hospital_scope("hospital_admin", "l2")
    body = _body(required=True)
    decision = body.get("decision")
    if decision not in ("approved", "rejected"):
        raise Refuse(400, "decision must be approved or rejected")
    note = _text(body, "note", 500)
    row = db().execute(
        "SELECT id, alert_id, action, target, status, requested_by FROM response_approvals "
        "WHERE id=%s AND tenant=%s", (approval_id, tenant)).fetchone()
    if not row:
        raise Refuse(404, "response approval not found")
    if row["status"] != "pending":
        raise Refuse(409, "response approval has already been decided")
    actor = g.identity["actor_id"]
    if row["requested_by"] == actor:
        raise Refuse(409, "the requester cannot approve their own response")
    job = db().execute(
        "SELECT job_id, status FROM response_jobs WHERE tenant_id=%s AND idempotency_key=%s",
        (tenant, f"approval:{approval_id}")).fetchone()
    if job is None or job["status"] != "pending_approval":
        raise Refuse(409, "response job is not awaiting approval")
    if decision == "approved":
        asset = _asset_for_target(tenant, row["action"], row["target"])
        if asset is not None and _is_medical(asset):
            raise Refuse(409, MEDICAL_REFUSAL)
    decided_at = datetime.now(timezone.utc)
    db().execute(
        "UPDATE response_approvals SET status=%s, approved_by=%s, decided_at=%s, decision_note=%s "
        "WHERE id=%s",
        (decision, actor, decided_at, note, approval_id))
    if decision == "approved":
        moved = db().execute(
            "UPDATE response_jobs SET status='queued', approved_by=%s, approved_at=%s, updated_at=now() "
            "WHERE job_id=%s RETURNING job_id", (actor, decided_at, job["job_id"])).fetchone()
        job_status = "queued"
        audit_action = "response_job.queue"
    else:
        moved = db().execute(
            "UPDATE response_jobs SET status='rejected', updated_at=now() WHERE job_id=%s RETURNING job_id",
            (job["job_id"],)).fetchone()
        job_status = "rejected"
        audit_action = "response_job.reject"
    if not moved:
        raise Refuse(409, "response job could not be decided")
    _record_current_audit(
        db(), action="response_approval.decision", resource_type="response_approval", resource_id=approval_id,
        resource_classification="security_event",
        metadata={"response_action": row["action"], "decision": decision})
    _record_current_audit(
        db(), action=audit_action, resource_type="response_job", resource_id=job["job_id"],
        resource_classification="security_event",
        metadata={"response_action": row["action"], "job_status": job_status})
    audit("response_approval.decision", f"approval {approval_id}: {decision}")
    commit()
    return jsonify(id=approval_id, alert_id=row["alert_id"], action=row["action"],
                   target=_redact_text(row["target"]), status=decision, job_id=job["job_id"],
                   job_status=job_status, execution="queued" if decision == "approved" else "not_performed")


# ---- Metrics and exit criteria -----------------------------------------------------------------

def _metrics(tenant=None):
    """Counts for one hospital (tenant given) or for all of them (tenant None). Row-level security applies too."""
    c = db()
    p = {"t": tenant}
    scope = "(%(t)s::text IS NULL OR tenant = %(t)s)"  # NULL means no filter

    def one(sql):
        return c.execute(sql.format(s=scope), p).fetchone()[0]

    tp = one("SELECT COUNT(*) FROM alerts WHERE verdict IN ('true_positive_malicious', 'true_positive_benign') AND {s}")
    fp = one("SELECT COUNT(*) FROM alerts WHERE verdict='false_positive' AND {s}")
    planted = one("SELECT COUNT(DISTINCT attack_id) FROM events WHERE attack_id IS NOT NULL AND {s}")
    caught = one("SELECT COUNT(DISTINCT attack_id) FROM alerts WHERE attack_id IS NOT NULL AND {s}")
    mtta = one("SELECT CAST(AVG(EXTRACT(EPOCH FROM (CAST(ack_at AS timestamp) - CAST(created AS timestamp)))) "
               "AS DOUBLE PRECISION) FROM alerts WHERE ack_at IS NOT NULL AND {s}")
    weekly = []
    for r in c.execute("SELECT to_char(CAST(created AS timestamp), 'IYYY-\"W\"IW') AS week, "
                       "COUNT(*) FILTER (WHERE verdict IN ('true_positive_malicious', 'true_positive_benign')) AS tp, "
                       "COUNT(*) FILTER (WHERE verdict='false_positive') AS fp "
                       "FROM alerts WHERE verdict IN ('true_positive_malicious', 'true_positive_benign', 'false_positive') "
                       "AND " + scope + " GROUP BY week ORDER BY week", p):
        weekly.append({"week": r["week"], "tp": r["tp"], "fp": r["fp"],
                       "false_positive_rate": round(r["fp"] / (r["tp"] + r["fp"]), 3)})
    by_sev = {r[0]: r[1] for r in c.execute(
        "SELECT severity, COUNT(*) FROM alerts WHERE " + scope + " GROUP BY severity", p)}
    return dict(events=one("SELECT COUNT(*) FROM events WHERE {s}"), alerts=one("SELECT COUNT(*) FROM alerts WHERE {s}"),
                by_severity=by_sev,
                unacknowledged=one("SELECT COUNT(*) FROM alerts WHERE status='new' AND {s}"),
                unlabeled=one("SELECT COUNT(*) FROM alerts WHERE verdict IS NULL AND {s}"),
                labeled_alerts=tp + fp,
                false_positive_rate=round(fp / (tp + fp), 3) if tp + fp else None,
                false_positive_rate_by_week=weekly,
                planted_attacks=planted, detected_attacks=caught,
                detection_rate=round(caught / planted, 3) if planted else None,
                mean_time_to_ack_s=round(mtta, 1) if mtta is not None else None)


@app.get("/api/metrics")
def metrics():
    return jsonify(_metrics(hospital_scope(*HOSPITAL_READ, "vendor_admin")))


# ---- Detection quality (FP_TARGET) and SOC visibility -------------------------------------------------

QUALITY_DEFINITIONS = {
    "label_coverage": "labeled / total_alerts. Labeled means a decisive verdict: true_positive_malicious, "
                      "true_positive_benign or false_positive.",
    "observed_fp_rate": "false_positive / labeled. Both true-positive labels count as not false positive. "
                        "Null when nothing is labeled.",
    "fp_min": "false_positive / total_alerts. Assumes every unlabeled or inconclusive alert was a true positive.",
    "fp_max": "(false_positive + unlabeled + inconclusive) / total_alerts. Assumes every unresolved alert "
              "was a false positive. The honest ceiling while review is incomplete.",
    "eligible_for_tuning": "True only when label_coverage >= MIN_LABEL_COVERAGE and labeled >= MIN_LABELED_SAMPLE. "
                           "Ineligible groups are never judged against FP_TARGET.",
    "fp_target_status": "within_target (fp_max <= FP_TARGET), above_target (fp_min > FP_TARGET), "
                        "undetermined (the bounds straddle the target), not_eligible, or no_target.",
}


def _quality_row(r, min_cov, min_n, target):
    total = r["total_alerts"]
    fp = r["false_positive"]
    labeled = r["tp_malicious"] + r["tp_benign"] + fp
    unresolved = total - labeled  # unlabeled and inconclusive alerts
    coverage = labeled / total if total else 0.0
    reasons = []
    if coverage < min_cov:
        reasons.append(f"label coverage {coverage:.0%} is below {min_cov:.0%}")
    if labeled < min_n:
        reasons.append(f"{labeled} labeled alerts, need {min_n}")
    eligible = not reasons
    observed = round(fp / labeled, 3) if labeled else None
    fp_min = round(fp / total, 3) if total else None
    fp_max = round((fp + unresolved) / total, 3) if total else None
    if target is None:
        status = "no_target"
    elif not eligible:
        status = "not_eligible"
    elif fp_max <= target:
        status = "within_target"
    elif fp_min > target:
        status = "above_target"
    else:
        status = "undetermined"
    return {
        "tenant_id": r["tenant"], "rule_id": r["rule_id"],
        "log_source_id": r["log_source_id"],
        "log_source": r["log_source"] or ("unattributed" if r["log_source_id"] is None else None),
        "total_alerts": total, "labeled_alerts": labeled, "label_coverage": round(coverage, 3),
        "verdicts": {TP_MALICIOUS: r["tp_malicious"], TP_BENIGN: r["tp_benign"], FALSE_POSITIVE: fp,
                     INCONCLUSIVE: r["inconclusive"], "unlabeled": r["unlabeled"]},
        "observed_fp_rate": observed, "fp_min": fp_min, "fp_max": fp_max,
        "eligible_for_tuning": eligible, "eligibility_reasons": reasons,
        "fp_target": target, "fp_target_status": status,
    }


def _detection_quality(tenant):
    """One row per (rule, log source) for this hospital. Unattributed alerts form their own group."""
    min_cov, min_n = _quality_thresholds()
    target = _fp_target()
    rows = db().execute(
        "SELECT a.tenant, a.rule AS rule_id, a.log_source_id, ls.name AS log_source, "
        "COUNT(*) AS total_alerts, "
        "COUNT(*) FILTER (WHERE a.verdict = 'true_positive_malicious') AS tp_malicious, "
        "COUNT(*) FILTER (WHERE a.verdict = 'true_positive_benign') AS tp_benign, "
        "COUNT(*) FILTER (WHERE a.verdict = 'false_positive') AS false_positive, "
        "COUNT(*) FILTER (WHERE a.verdict = 'inconclusive') AS inconclusive, "
        "COUNT(*) FILTER (WHERE a.verdict IS NULL) AS unlabeled "
        "FROM alerts a LEFT JOIN log_sources ls ON ls.id = a.log_source_id AND ls.tenant = a.tenant "
        "WHERE a.tenant = %(t)s "
        "GROUP BY a.tenant, a.rule, a.log_source_id, ls.name "
        "ORDER BY a.rule, a.log_source_id NULLS FIRST",
        {"t": tenant}).fetchall()
    return [_quality_row(dict(r), min_cov, min_n, target) for r in rows]


def _soc_visibility(tenant):
    """What the SOC can see of this hospital's estate, from its own inventory, events and refusal records."""
    c = db()
    p = {"t": tenant}
    a = c.execute("SELECT COUNT(*) AS total, COUNT(*) FILTER (WHERE monitoring_mode = 'edr_managed') AS edr, "
                  "COUNT(*) FILTER (WHERE monitoring_mode = 'agentless_medical') AS agentless_medical, "
                  "COUNT(*) FILTER (WHERE monitoring_mode = 'unmanaged') AS unmanaged "
                  "FROM assets WHERE tenant_id = %(t)s", p).fetchone()
    unknown = c.execute(
        "SELECT COUNT(DISTINCT e.host) FROM events e WHERE e.tenant = %(t)s AND COALESCE(e.host, '') <> '' "
        "AND NOT EXISTS (SELECT 1 FROM assets x WHERE x.tenant_id = e.tenant "
        "AND (x.device_name = e.host OR x.ip_address = e.host))", p).fetchone()[0]
    refused = c.execute("SELECT COUNT(*) FROM audit_events WHERE tenant_id = %(t)s AND outcome = 'deny'",
                        p).fetchone()[0]
    total = a["total"]
    return {
        "total_assets": total,
        "monitored_assets": total - a["unmanaged"],
        "edr_managed_assets": a["edr"],
        "agentless_medical_assets": a["agentless_medical"],
        "edr_coverage": round(a["edr"] / total, 3) if total else None,
        "unmanaged_assets": a["unmanaged"],
        "unknown_hosts_seen": unknown,
        "unknown_or_unmanaged_assets": a["unmanaged"] + unknown,
        "cross_tenant_or_unauthorized_attempts": refused,
        "definitions": {
            "monitored_assets": "assets whose monitoring_mode is not unmanaged",
            "edr_coverage": "edr_managed / total_assets",
            "unknown_hosts_seen": "distinct event hosts with no matching asset by device name or IP",
            "cross_tenant_or_unauthorized_attempts": "refused requests recorded for this hospital "
                                                     "(authorization denials and rejected ingest)",
        },
    }


def _gate_results(m, tenant=None):
    """Pass, fail, or not_measured for each roadmap gate in the prototype plan. not_measured means no data yet."""
    c = db()
    out = []

    def gate(gid, status, detail):
        out.append({"id": gid, "name": GATE_NAMES[gid], "status": status, "detail": detail})

    gate("foundation", "pass" if m["events"] > 0 else "not_measured",
         f"{m['events']} events stored" if m["events"] else "no events yet")

    if not m["planted_attacks"]:
        gate("detection", "not_measured", "no planted attacks in the data yet (run scripts/attack_sim.py)")
    else:
        ok = m["detection_rate"] == 1.0
        gate("detection", "pass" if ok else "fail",
             f"{m['detected_attacks']} of {m['planted_attacks']} planted attacks detected")

    missing = c.execute("SELECT COUNT(*) FROM alerts WHERE (COALESCE(owner,'')='' OR COALESCE(step,'')='') "
                        "AND (%(t)s::text IS NULL OR tenant = %(t)s)", {"t": tenant}).fetchone()[0]
    if not m["alerts"]:
        gate("response", "not_measured", "no alerts yet")
    else:
        gate("response", "pass" if missing == 0 else "fail",
             f"{m['alerts'] - missing} of {m['alerts']} alerts have an owner and a step")

    target = _fp_target()
    groups = _detection_quality(tenant) if tenant else []
    if target is None:
        gate("review", "not_measured", "set FP_TARGET to the false-positive ceiling the team agrees")
    elif not groups:
        gate("review", "not_measured", "no alerts yet")
    elif any(x["fp_target_status"] == "above_target" for x in groups):
        bad = sum(1 for x in groups if x["fp_target_status"] == "above_target")
        gate("review", "fail", f"{bad} of {len(groups)} rule and log source groups exceed target {target:.1%}")
    elif all(x["fp_target_status"] == "within_target" for x in groups):
        gate("review", "pass", f"all {len(groups)} rule and log source groups are within target {target:.1%} "
                               "even at their worst case")
    else:
        waiting = sum(1 for x in groups if x["fp_target_status"] != "within_target")
        gate("review", "not_measured", f"{waiting} of {len(groups)} groups need more label coverage, more "
                                       "labeled alerts, or a decisive result before the target can be judged")
    return out


@app.get("/api/exit-criteria")
def exit_criteria():
    tenant = hospital_scope(*HOSPITAL_READ, "vendor_admin")
    m = _metrics(tenant)
    gates = _gate_results(m, tenant)
    return jsonify(gates=gates, all_pass=all(g["status"] == "pass" for g in gates), fp_target=_fp_target())


@app.get("/api/detection-quality")
def detection_quality():
    tenant = hospital_scope(*HOSPITAL_READ, "vendor_admin")
    min_cov, min_n = _quality_thresholds()
    return jsonify(fp_target=_fp_target(), min_label_coverage=min_cov, min_labeled_sample=min_n,
                   definitions=QUALITY_DEFINITIONS, rules=_detection_quality(tenant))


@app.get("/api/soc-visibility")
def soc_visibility():
    tenant = hospital_scope(*HOSPITAL_READ, "vendor_admin")
    return jsonify(_soc_visibility(tenant))


# ---- Lab-only endpoints (owner role, vendor admin only) ---------------------------------------------

def _lab_connection():
    url = os.environ.get("LAB_DATABASE_URL", "")
    if not url:
        raise Refuse(503, "lab endpoints need LAB_DATABASE_URL (the owner role); they are not available here")
    return connect(url)


@app.post("/api/demo")
def demo():
    """Load synthetic logs + planted attacks (lab only)."""
    _require_vendor()
    generated = generate.generate()
    evs = generated if isinstance(generated, list) else [generated]
    c = _lab_connection()
    try:
        made_ids, _, _ = _store_events(c, evs)
        c.commit()
    finally:
        c.close()
    return jsonify(events=len(evs), alerts_created=len(made_ids))


@app.post("/api/autolabel")
def autolabel():
    """Lab shortcut: label alerts from planted ground truth. Real triage uses manual verdicts."""
    _require_vendor()
    c = _lab_connection()
    try:
        c.execute("UPDATE alerts SET verdict=CASE WHEN attack_id IS NOT NULL THEN 'true_positive_malicious' ELSE 'false_positive' END WHERE verdict IS NULL AND source='builtin'")
        c.commit()
    finally:
        c.close()
    return jsonify(ok=True)


@app.post("/api/reset")
def reset():
    _require_vendor()
    c = _lab_connection()
    try:
        c.execute("TRUNCATE events, alerts, handoffs, response_approvals, response_jobs RESTART IDENTITY")
        c.commit()
    finally:
        c.close()
    return jsonify(ok=True)


@app.get("/")
def home():
    return send_from_directory("static", "index.html")


# Registered last: routes/mfa.py imports this module for the shared helpers (db, Refuse, commit, audit).
from routes.mfa import bp as mfa_bp  # noqa: E402

app.register_blueprint(mfa_bp)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
