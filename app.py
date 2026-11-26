"""Cybrot SOC Core - prototype: ingest -> detect -> triage queue -> metrics -> exit criteria.

Who may call /api/:
- A logged-in user (a session token). The role decides what they may do. Their hospital is the tenant.
- An ingest key, for POST /api/events and POST /api/ingest/* only. The key is bound to one hospital and one log source.
Nothing else is accepted. There is no shared operator token.

The tenant always comes from the caller's identity. A tenant_id in the query can only narrow within that scope;
anything else is refused with 403 before a query runs. PostgreSQL row-level security enforces the same rule
underneath: every transaction carries the identity in transaction-local settings (see db/schema.sql).
"""
import json, os, secrets, sys, threading, time, urllib.error, urllib.request
from datetime import datetime, timezone

import psycopg
from flask import Flask, g, request, jsonify, send_from_directory

import auth, detect, generate

# Runtime connection, as the soc_app role (never the owner). Read at call time.
ANALYSTS = os.environ.get("ANALYSTS", "analyst1,analyst2,analyst3").split(",")
# Lab-only endpoints (synthetic data, demo load, reset). They need the owner role, so they use LAB_DATABASE_URL.
# Set LAB_ENDPOINTS=0 in any environment where real logs or real analysts' work could be in the database.
LAB_ENDPOINTS = os.environ.get("LAB_ENDPOINTS", "1") == "1"
LAB_PATHS = {"/api/demo", "/api/autolabel", "/api/reset"}
SESSION_HOURS = float(os.environ.get("SOC_SESSION_HOURS", "8"))
# Playbook hook (v0.7): every new alert is POSTed as JSON to this URL, e.g. a Shuffle webhook. Empty = off.
PLAYBOOK_TIMEOUT = float(os.environ.get("PLAYBOOK_TIMEOUT", "3"))
PUBLIC_ROUTES = {("POST", "/api/login")}
HOSPITAL_READ = ("hospital_admin", "l1", "l2", "viewer")
app = Flask(__name__, static_folder="static")

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
    conn.execute("SELECT set_config('app.tenant_id', %s, true), set_config('app.role', %s, true), "
                 "set_config('app.actor_id', %s, true)",
                 (tenant or "", role or "", "" if actor_id is None else str(actor_id)))


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


def now():
    return datetime.now(timezone.utc).strftime(detect.FMT)


def _fp_target():
    """Agreed false-positive ceiling as a fraction, e.g. FP_TARGET=0.10. Unset until the team agrees a number."""
    raw = os.environ.get("FP_TARGET", "").strip()
    try:
        return float(raw) if raw else None
    except ValueError:
        return None


def audit(action, detail=""):
    """One row in the audit log, for the identity that is currently bound."""
    ctx = g.ctx
    db().execute("INSERT INTO audit_log(tenant, actor_id, action, detail) VALUES (%s, %s, %s, %s)",
                 (ctx["tenant"], ctx["actor_id"], action, detail[:300]))


def raise_alert(c, tenant, rule, sev, summary, key, event_ts, attack_id=None, source="builtin",
                detail="", step=None):
    dup = c.execute("SELECT 1 FROM alerts WHERE rule=%s AND tenant=%s AND dkey=%s AND event_ts>=%s",
                    (rule, tenant, key, detect._ago(event_ts, 10))).fetchone() if event_ts else None
    if dup:
        return None
    n = c.execute("SELECT COUNT(*) FROM alerts WHERE tenant=%s", (tenant,)).fetchone()[0]
    owner = ANALYSTS[n % len(ANALYSTS)]
    step = step or detect.PLAYBOOK.get(rule, "Review the alert details and decide: escalate, fix, or close as benign.")
    cur = c.execute("INSERT INTO alerts(created,event_ts,tenant,rule,rule_version,severity,summary,dkey,owner,step,attack_id,source,detail) "
                    "VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id",
                    (now(), event_ts, tenant, rule, detect.rule_version(rule), sev, summary, key, owner, step, attack_id, source, detail))
    return cur.fetchone()["id"]


def _playbook_url():
    """Read at call time so the setting can change without reloading the module."""
    return os.environ.get("PLAYBOOK_WEBHOOK", "").strip()


def _alert_payload(row):
    keys = ("id", "created", "tenant", "rule", "rule_version", "severity", "summary", "owner", "step", "detail", "attack_id", "source")
    return {"event": "alert.created", "alert": {k: row[k] for k in keys}}


def _playbook_secret():
    return os.environ.get("PLAYBOOK_SECRET", "")


def sign(secret, timestamp, body):
    """HMAC-SHA256 over '<timestamp>.<raw body>'. The receiver recomputes it and compares (see docs/SHUFFLE.md)."""
    import hashlib, hmac
    mac = hmac.new(secret.encode(), f"{timestamp}.".encode() + body, hashlib.sha256)
    return "sha256=" + mac.hexdigest()


def _send(url, payload, timeout=None, attempts=3, delay=1.0):
    """POST one alert to the playbook webhook. Returns True on a 2xx reply. Never raises; the URL is not logged.
    Signed with PLAYBOOK_SECRET when set. Server errors and network errors are retried with backoff;
    4xx replies are not, because retrying a rejected request does not help."""
    body = json.dumps(payload).encode()
    secret = _playbook_secret()
    event_id = f"alert-{payload.get('alert', {}).get('id', 'unknown')}"  # same on every retry: lets the receiver de-duplicate
    for n in range(attempts):
        ts = str(int(time.time()))
        headers = {"Content-Type": "application/json", "X-Cybrot-Event-Id": event_id, "X-Cybrot-Timestamp": ts}
        if secret:
            headers["X-Cybrot-Signature"] = sign(secret, ts, body)
        req = urllib.request.Request(url, data=body, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=timeout or PLAYBOOK_TIMEOUT) as r:
                if 200 <= r.status < 300:
                    return True
        except urllib.error.HTTPError as e:
            print(f"playbook webhook failed: HTTP {e.code}", file=sys.stderr, flush=True)
            if 400 <= e.code < 500:
                return False
        except Exception as e:  # delivery problems must never break ingest
            print(f"playbook webhook failed: {type(e).__name__}", file=sys.stderr, flush=True)
        if n < attempts - 1:
            time.sleep(delay * (2 ** n))
    return False


def _dispatch(url, payload):
    threading.Thread(target=_send, args=(url, payload), daemon=True).start()


def _notify_new(c, ids):
    """Called after commit, so a rolled-back alert is never sent."""
    url = _playbook_url()
    if not url or not ids:
        return
    marks = ",".join(["%s"] * len(ids))
    for row in c.execute(f"SELECT * FROM alerts WHERE id IN ({marks}) ORDER BY id", ids).fetchall():
        _dispatch(url, _alert_payload(row))


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
    if not sess or sess["user_status"] != "active":
        raise Refuse(401, "unauthorized")
    if _is_ingest_post():
        raise Refuse(403, "event ingest needs an ingest key, not a user session")
    g.identity = {"kind": "session", "tenant": sess["user_tenant"], "role": sess["user_role"],
                  "actor_id": sess["user_id"], "name": sess["user_name"], "token_hash": h}
    set_context(sess["user_tenant"], sess["user_role"], sess["user_id"])
    return None


@app.before_request
def gate_lab_endpoints():
    if not LAB_ENDPOINTS and request.path in LAB_PATHS:
        return jsonify(error="lab endpoint disabled (LAB_ENDPOINTS=0)"), 404
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


def _break_glass_active(tenant):
    row = db().execute("SELECT break_glass_active(%s) AS ok", (tenant,)).fetchone()
    return bool(row["ok"])


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
        if not _break_glass_active(wanted):
            raise Refuse(403, "no active break-glass grant for this hospital")
        set_context(wanted, "vendor_admin", ident["actor_id"])
        audit("break_glass.read", request.path)
        return wanted
    if wanted and wanted != ident["tenant"]:
        raise Refuse(403, "tenant_id does not match your session")
    if ident["role"] not in allowed:
        raise Refuse(403, "your role cannot do this")
    return ident["tenant"]


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
    row = db().execute("SELECT id, owner, status, tenant FROM alerts WHERE id=%s", (i,)).fetchone()
    if not row:
        raise Refuse(404, "alert not found")  # also what another hospital's alert returns
    return row


# ---- Events ingest ------------------------------------------------------------------------------

def _store_events(c, evs):
    """Store events and run the detection rules. Returns the new alert ids. The caller commits."""
    made_ids = []
    for e in sorted(evs, key=lambda x: x["ts"]):
        e.setdefault("attack_id", None)
        for k in ("user", "host", "ip", "patient", "detail", "source"):
            e.setdefault(k, "")
        for k in ("destination", "data_classification", "destination_approved", "src_zone", "dst_zone",
                  "boundary_violation", "approved_change", "log_source_id"):
            e.setdefault(k, None)
        c.execute('INSERT INTO events(ts,tenant,source,type,"user",host,ip,patient,detail,attack_id, '
                  'destination,data_classification,destination_approved,src_zone,dst_zone,boundary_violation,approved_change,log_source_id) '
                  "VALUES(%(ts)s,%(tenant)s,%(source)s,%(type)s,%(user)s,%(host)s,%(ip)s,%(patient)s,%(detail)s,%(attack_id)s, "
                  "%(destination)s,%(data_classification)s,%(destination_approved)s,%(src_zone)s,%(dst_zone)s,%(boundary_violation)s,%(approved_change)s,%(log_source_id)s)", e)
        hit = detect.evaluate(c, e)
        if hit:
            i = raise_alert(c, e["tenant"], *hit[:3], hit[3], e["ts"], e["attack_id"])
            if i:
                made_ids.append(i)
    return made_ids


@app.post("/api/events")
def ingest():
    ident = _require_ingest()
    body = request.get_json(force=True)
    evs = body if isinstance(body, list) else [body]
    for e in evs:
        if not isinstance(e, dict):
            raise Refuse(400, "each event must be a JSON object")
        # An ingest key is bound to one hospital and one log source. Events for any other hospital are refused.
        if e.get("tenant") not in (None, "", ident["tenant"]):
            raise Refuse(403, "event tenant does not match this ingest key")
        e["tenant"] = ident["tenant"]
        e["log_source_id"] = ident["log_source_id"]
    made_ids = _store_events(db(), evs)
    commit()
    _notify_new(db(), made_ids)
    return jsonify(events=len(evs), alerts_created=len(made_ids))


@app.post("/api/ingest/wazuh")
def ingest_wazuh():
    """Accepts a Wazuh integration (webhook) alert and drops it in the same triage queue."""
    ident = _require_ingest()
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
                    detail=detail, step=detect.wazuh_step(rid, lvl))
    commit()
    _notify_new(db(), [i] if i else [])
    return jsonify(alert_id=i)


# ---- Vendor: tenants ------------------------------------------------------------------------------

@app.get("/api/tenants")
def list_tenants():
    _require_vendor()
    rows = db().execute("SELECT id, name, created FROM tenants ORDER BY id").fetchall()
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
    rows = db().execute("SELECT id, username, role, status, created FROM users ORDER BY id").fetchall()
    return jsonify([dict(r) for r in rows])


@app.post("/api/users")
def create_user():
    tenant = hospital_scope("hospital_admin")
    body = _body(required=True)
    username = _text(body, "username").lower()
    role = body.get("role")
    password = body.get("password")
    if not auth.USERNAME_RE.fullmatch(username):
        raise Refuse(400, "username must be 3 to 40 lowercase letters, digits, dots, hyphens or underscores")
    if role not in auth.HOSPITAL_ROLES:
        raise Refuse(400, f"role must be one of: {', '.join(auth.HOSPITAL_ROLES)}")
    problem = auth.password_problem(password)
    if problem:
        raise Refuse(400, problem)
    c = db()
    if c.execute("SELECT 1 FROM users WHERE username=%s", (username,)).fetchone():
        raise Refuse(409, "username already exists in this hospital")
    row = c.execute("INSERT INTO users(tenant, username, role, password_hash) VALUES(%s, %s, %s, %s) RETURNING id",
                    (tenant, username, role, auth.hash_password(password))).fetchone()
    audit("user.create", f"{username} ({role})")
    commit()
    return jsonify(id=row["id"], username=username, role=role), 201


@app.post("/api/users/<int:uid>/disable")
def disable_user(uid):
    hospital_scope("hospital_admin")
    if uid == g.identity["actor_id"]:
        raise Refuse(400, "you cannot disable your own account")
    c = db()
    row = c.execute("UPDATE users SET status='disabled' WHERE id=%s AND status='active' RETURNING username", (uid,)).fetchone()
    if not row:
        raise Refuse(404, "user not found or already disabled")
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
    rows = db().execute("SELECT id, label, log_source_id, created, revoked_at FROM ingest_keys ORDER BY id").fetchall()
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
    row = c.execute("INSERT INTO ingest_keys(tenant, label, key_hash, log_source_id) VALUES(%s, %s, %s, %s) RETURNING id",
                    (tenant, label, auth.token_hash(key), sid)).fetchone()
    audit("credential.create", f"key {row['id']} for log source {sid}")
    commit()
    return jsonify(id=row["id"], log_source_id=sid, label=label, key=key,
                   note="Store this key now. It is not shown again."), 201


@app.post("/api/credentials/<int:kid>/revoke")
def revoke_credential(kid):
    hospital_scope("hospital_admin")
    c = db()
    row = c.execute("UPDATE ingest_keys SET revoked_at=COALESCE(revoked_at, %s) WHERE id=%s RETURNING id", (now(), kid)).fetchone()
    if not row:
        raise Refuse(404, "credential not found")
    audit("credential.revoke", f"key {kid}")
    commit()
    return jsonify(ok=True)


# ---- Sessions ------------------------------------------------------------------------------------

@app.post("/api/login")
def login():
    body = _body(required=True)
    tenant = _text(body, "tenant")
    username = _text(body, "username").lower()
    password = body.get("password") if isinstance(body.get("password"), str) else ""
    if not (tenant and username and password):
        raise Refuse(400, "tenant, username and password are required")
    c = db()
    row = c.execute("SELECT * FROM auth_user_for_login(%s, %s)", (tenant, username)).fetchone()
    stored = row["user_password_hash"] if row else auth.DUMMY_HASH
    if not auth.verify_password(password, stored) or not row or row["user_status"] != "active":
        print(f"login refused for tenant {tenant}", file=sys.stderr, flush=True)
        raise Refuse(401, "invalid tenant, username or password")
    token = auth.new_token()
    set_context(row["user_tenant"], row["user_role"], row["user_id"])
    c.execute("INSERT INTO sessions(token_hash, user_id, expires_at) VALUES (%s, %s, now() + make_interval(secs => %s))",
              (auth.token_hash(token), row["user_id"], SESSION_HOURS * 3600.0))
    audit("login")
    commit()
    return jsonify(token=token, tenant=row["user_tenant"], role=row["user_role"], username=username,
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


# ---- Triage --------------------------------------------------------------------------------------

@app.get("/api/alerts")
def alerts():
    tenant = hospital_scope(*HOSPITAL_READ, "vendor_admin")
    # last_handoff: the latest handoff as "from -> to: note", so the dashboard can show it (v0.7.1).
    q = ("SELECT alerts.*, (SELECT from_owner || ' -> ' || to_owner || ': ' || COALESCE(NULLIF(note, ''), 'no note') "
         "FROM handoffs h WHERE h.alert_id = alerts.id ORDER BY h.id DESC LIMIT 1) AS last_handoff "
         "FROM alerts WHERE tenant=%s")
    args = [tenant]
    for f in ("status", "owner"):
        if request.args.get(f):
            q += f" AND {f}=%s"
            args.append(request.args[f])
    rows = db().execute(q + " ORDER BY id DESC LIMIT 200", args).fetchall()
    return jsonify([dict(r) for r in rows])


@app.post("/api/alerts/<int:i>/ack")
def ack(i):
    hospital_scope("hospital_admin", "l1", "l2")
    _alert_or_404(i)
    c = db()
    c.execute("UPDATE alerts SET status='ack', ack_at=%s WHERE id=%s AND status='new'", (now(), i))
    commit()
    return jsonify(ok=True)


@app.post("/api/alerts/<int:i>/verdict")
def verdict(i):
    hospital_scope("hospital_admin", "l2")
    body = _body(required=True)
    v = body.get("verdict")
    if v not in ("tp", "fp", "unclear"):
        raise Refuse(400, "verdict must be tp, fp or unclear")
    note = _text(body, "note", 500)  # optional closing note, kept with the alert
    _alert_or_404(i)
    c = db()
    c.execute("UPDATE alerts SET verdict=%s, status='closed', ack_at=COALESCE(ack_at,%s), "
              "resolution=COALESCE(NULLIF(%s,''), resolution) WHERE id=%s", (v, now(), note, i))
    audit("alert.verdict", f"alert {i}: {v}")
    commit()
    return jsonify(ok=True)


@app.get("/api/analysts")
def analysts():
    hospital_scope(*HOSPITAL_READ)
    return jsonify(analysts=ANALYSTS)


@app.post("/api/alerts/<int:i>/handoff")
def handoff(i):
    """Pass an open alert to another analyst. The owner changes and the handoff is kept in history."""
    hospital_scope("hospital_admin", "l1", "l2")
    body = _body(required=True)
    to = _text(body, "to_owner")
    note = _text(body, "note", 500)
    if to not in ANALYSTS:
        raise Refuse(400, f"to_owner must be one of: {', '.join(ANALYSTS)}")
    row = _alert_or_404(i)
    if row["status"] == "closed":
        raise Refuse(409, "alert is closed")
    if to == row["owner"]:
        raise Refuse(400, f"alert is already owned by {to}")
    c = db()
    c.execute("INSERT INTO handoffs(alert_id,at,from_owner,to_owner,note,tenant) VALUES(%s,%s,%s,%s,%s,%s)",
              (i, now(), row["owner"], to, note, row["tenant"]))
    c.execute("UPDATE alerts SET owner=%s WHERE id=%s", (to, i))
    audit("alert.handoff", f"alert {i} to {to}")
    commit()
    return jsonify(ok=True, from_owner=row["owner"], to_owner=to)


@app.get("/api/alerts/<int:i>/handoffs")
def handoffs(i):
    hospital_scope(*HOSPITAL_READ, "vendor_admin")
    _alert_or_404(i)
    rows = db().execute("SELECT at, from_owner, to_owner, note FROM handoffs WHERE alert_id=%s ORDER BY id", (i,)).fetchall()
    return jsonify([dict(r) for r in rows])


# ---- Metrics and exit criteria -----------------------------------------------------------------

def _metrics(tenant=None):
    """Counts for one hospital (tenant given) or for all of them (tenant None). Row-level security applies too."""
    c = db()
    p = {"t": tenant}
    scope = "(%(t)s::text IS NULL OR tenant = %(t)s)"  # NULL means no filter

    def one(sql):
        return c.execute(sql.format(s=scope), p).fetchone()[0]

    tp = one("SELECT COUNT(*) FROM alerts WHERE verdict='tp' AND {s}")
    fp = one("SELECT COUNT(*) FROM alerts WHERE verdict='fp' AND {s}")
    planted = one("SELECT COUNT(DISTINCT attack_id) FROM events WHERE attack_id IS NOT NULL AND {s}")
    caught = one("SELECT COUNT(DISTINCT attack_id) FROM alerts WHERE attack_id IS NOT NULL AND {s}")
    mtta = one("SELECT CAST(AVG(EXTRACT(EPOCH FROM (CAST(ack_at AS timestamp) - CAST(created AS timestamp)))) "
               "AS DOUBLE PRECISION) FROM alerts WHERE ack_at IS NOT NULL AND {s}")
    weekly = []
    for r in c.execute("SELECT to_char(CAST(created AS timestamp), 'IYYY-\"W\"IW') AS week, "
                       "COUNT(*) FILTER (WHERE verdict='tp') AS tp, COUNT(*) FILTER (WHERE verdict='fp') AS fp "
                       "FROM alerts WHERE verdict IN ('tp','fp') AND " + scope + " GROUP BY week ORDER BY week", p):
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
    if target is None:
        gate("review", "not_measured", "set FP_TARGET to the false-positive ceiling the team agrees")
    elif not m["labeled_alerts"]:
        gate("review", "not_measured", "no alerts labeled tp or fp yet")
    else:
        rate = m["false_positive_rate"]
        gate("review", "pass" if rate <= target else "fail",
             f"false-positive rate {rate:.1%} against target {target:.1%}")
    return out


@app.get("/api/exit-criteria")
def exit_criteria():
    tenant = hospital_scope(*HOSPITAL_READ, "vendor_admin")
    m = _metrics(tenant)
    gates = _gate_results(m, tenant)
    return jsonify(gates=gates, all_pass=all(g["status"] == "pass" for g in gates), fp_target=_fp_target())


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
        made_ids = _store_events(c, evs)
        c.commit()
        _notify_new(c, made_ids)
    finally:
        c.close()
    return jsonify(events=len(evs), alerts_created=len(made_ids))


@app.post("/api/autolabel")
def autolabel():
    """Lab shortcut: label alerts from planted ground truth. Real triage uses manual verdicts."""
    _require_vendor()
    c = _lab_connection()
    try:
        c.execute("UPDATE alerts SET verdict=CASE WHEN attack_id IS NOT NULL THEN 'tp' ELSE 'fp' END WHERE verdict IS NULL AND source='builtin'")
        c.commit()
    finally:
        c.close()
    return jsonify(ok=True)


@app.post("/api/reset")
def reset():
    _require_vendor()
    c = _lab_connection()
    try:
        c.execute("TRUNCATE events, alerts, handoffs RESTART IDENTITY")
        c.commit()
    finally:
        c.close()
    return jsonify(ok=True)


@app.get("/")
def home():
    return send_from_directory("static", "index.html")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
