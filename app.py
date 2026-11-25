"""Cybrot SOC Core - prototype: ingest -> detect -> triage queue (owner + response step) -> metrics -> exit criteria."""
import hashlib, hmac, json, os, re, secrets, sys, threading, time, urllib.error, urllib.request
from datetime import datetime, timezone
import psycopg
from flask import Flask, g, request, jsonify, send_from_directory
import detect, generate

# PostgreSQL connection string. Set DATABASE_URL in every real deployment. The default is for local development only.
DEFAULT_DATABASE_URL = "postgresql://soc:soc@localhost:5432/soc"
ANALYSTS = os.environ.get("ANALYSTS", "analyst1,analyst2,analyst3").split(",")
# Lab-only endpoints (synthetic data, demo load, reset). Set LAB_ENDPOINTS=0 in any
# environment where real logs or real analysts' work could be in the database.
LAB_ENDPOINTS = os.environ.get("LAB_ENDPOINTS", "1") == "1"
LAB_PATHS = {"/api/demo", "/api/autolabel", "/api/reset"}
# Operator token for every /api/ call (Authorization: Bearer <token>). Required for any shared deployment.
# Hospital ingest keys (below) can only send events; they cannot read or change anything.
API_TOKEN = os.environ.get("SOC_API_TOKEN", "")
# Playbook hook (v0.7): every new alert is POSTed as JSON to this URL, e.g. a Shuffle webhook. Empty = off.
PLAYBOOK_TIMEOUT = float(os.environ.get("PLAYBOOK_TIMEOUT", "3"))
TENANT_ID_RE = re.compile(r"[a-z0-9][a-z0-9-]{1,62}")
app = Flask(__name__, static_folder="static")

GATE_NAMES = {
    "foundation": "Logs flow end to end",
    "detection": "All planted attacks detected",
    "response": "Every alert has an owner and a response step",
    "review": "False-positive rate within the agreed target",
}

# "user" is a reserved word in PostgreSQL, so the column is quoted wherever it appears.
SCHEMA = """
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
CREATE TABLE IF NOT EXISTS alerts(id BIGSERIAL PRIMARY KEY, created TEXT, event_ts TEXT, tenant TEXT, rule TEXT,
  rule_version TEXT, severity TEXT, summary TEXT, dkey TEXT, owner TEXT, step TEXT, status TEXT DEFAULT 'new',
  ack_at TEXT, verdict TEXT, attack_id TEXT, source TEXT DEFAULT 'builtin', detail TEXT);
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS detail TEXT;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS resolution TEXT;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS rule_version TEXT;
CREATE TABLE IF NOT EXISTS handoffs(id BIGSERIAL PRIMARY KEY, alert_id BIGINT, at TEXT, from_owner TEXT,
  to_owner TEXT, note TEXT);
ALTER TABLE handoffs ADD COLUMN IF NOT EXISTS tenant TEXT;
CREATE INDEX IF NOT EXISTS ho_idx ON handoffs(alert_id);
CREATE TABLE IF NOT EXISTS tenants(id TEXT PRIMARY KEY, name TEXT NOT NULL,
  created TEXT NOT NULL DEFAULT to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS'));
INSERT INTO tenants(id, name) VALUES ('default', 'Default (lab)') ON CONFLICT DO NOTHING;
CREATE TABLE IF NOT EXISTS ingest_keys(id BIGSERIAL PRIMARY KEY, tenant TEXT NOT NULL REFERENCES tenants(id),
  label TEXT NOT NULL DEFAULT '', key_hash TEXT NOT NULL UNIQUE,
  created TEXT NOT NULL DEFAULT to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS'), revoked_at TEXT);
"""

_schema_ready = set()  # database URLs whose schema has been checked in this process


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


def connect():
    """Open a new connection and make sure the schema exists. Read the URL at call time."""
    url = os.environ.get("DATABASE_URL", DEFAULT_DATABASE_URL)
    c = psycopg.connect(url, row_factory=_row_factory)
    if url not in _schema_ready:
        c.execute(SCHEMA)
        c.commit()
        _schema_ready.add(url)
    return c


def db():
    """One connection per request. It is closed when the request ends (see _close_db)."""
    if "db" not in g:
        g.db = connect()
    return g.db


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


def raise_alert(c, tenant, rule, sev, summary, key, event_ts, attack_id=None, source="builtin",
                detail="", step=None):
    dup = c.execute("SELECT 1 FROM alerts WHERE rule=%s AND tenant=%s AND dkey=%s AND event_ts>=%s",
                    (rule, tenant, key, detect._ago(event_ts, 10))).fetchone() if event_ts else None
    if dup:
        return None
    n = c.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
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


def _supplied_token():
    supplied = (request.headers.get("Authorization") or "").removeprefix("Bearer ").strip()
    if not supplied and request.path.startswith("/api/ingest/"):
        supplied = request.args.get("token", "")
    return supplied


def _is_ingest_request():
    return request.method == "POST" and (request.path == "/api/events" or request.path.startswith("/api/ingest/"))


def _key_tenant(token):
    """The hospital an active ingest key belongs to, or None. Only the SHA-256 hash of a key is stored."""
    if not token:
        return None
    h = hashlib.sha256(token.encode()).hexdigest()
    row = db().execute("SELECT tenant FROM ingest_keys WHERE key_hash=%s AND revoked_at IS NULL", (h,)).fetchone()
    return row["tenant"] if row else None


@app.before_request
def gate_api():
    """Who may call /api/:
    - A hospital ingest key can only POST events or Wazuh alerts. Its tenant comes from the key, never from the request.
    - Everything else needs SOC_API_TOKEN, when that is set.
    - With SOC_API_TOKEN unset (lab only), the API is open.
    Wazuh's built-in integration cannot send headers, so /api/ingest/* also accepts ?token=."""
    g.tenant_lock = None
    if not request.path.startswith("/api/"):
        return None
    supplied = _supplied_token()
    if _is_ingest_request():
        tenant = _key_tenant(supplied)
        if tenant:
            g.tenant_lock = tenant
            return None
    if not API_TOKEN:
        return None
    if not hmac.compare_digest(supplied, API_TOKEN):
        return jsonify(error="unauthorized"), 401
    return None


@app.before_request
def gate_lab_endpoints():
    if not LAB_ENDPOINTS and request.path in LAB_PATHS:
        return jsonify(error="lab endpoint disabled (LAB_ENDPOINTS=0)"), 404


def _store_events(c, evs):
    """Store events and run the detection rules. Returns the new alert ids. The caller commits."""
    made_ids = []
    for e in sorted(evs, key=lambda x: x["ts"]):
        e.setdefault("attack_id", None)
        for k in ("user", "host", "ip", "patient", "detail", "source"):
            e.setdefault(k, "")
        for k in ("destination", "data_classification", "destination_approved", "src_zone", "dst_zone",
                  "boundary_violation", "approved_change"):
            e.setdefault(k, None)
        c.execute('INSERT INTO events(ts,tenant,source,type,"user",host,ip,patient,detail,attack_id, '
                  'destination,data_classification,destination_approved,src_zone,dst_zone,boundary_violation,approved_change) '
                  "VALUES(%(ts)s,%(tenant)s,%(source)s,%(type)s,%(user)s,%(host)s,%(ip)s,%(patient)s,%(detail)s,%(attack_id)s, "
                  "%(destination)s,%(data_classification)s,%(destination_approved)s,%(src_zone)s,%(dst_zone)s,%(boundary_violation)s,%(approved_change)s)", e)
        hit = detect.evaluate(c, e)
        if hit:
            i = raise_alert(c, e["tenant"], *hit[:3], hit[3], e["ts"], e["attack_id"])
            if i:
                made_ids.append(i)
    return made_ids


@app.post("/api/events")
def ingest():
    body = request.get_json(force=True)
    evs = body if isinstance(body, list) else [body]
    lock = g.get("tenant_lock")
    if lock:
        # An ingest key is bound to one hospital. Events for any other hospital are refused, not moved.
        if any(e.get("tenant") not in (None, "", lock) for e in evs):
            return jsonify(error="event tenant does not match this ingest key"), 403
        for e in evs:
            e["tenant"] = lock
    c = db()
    made_ids = _store_events(c, evs)
    c.commit()
    _notify_new(c, made_ids)
    return jsonify(events=len(evs), alerts_created=len(made_ids))


@app.post("/api/ingest/wazuh")
def ingest_wazuh():
    """Accepts a Wazuh integration (webhook) alert and drops it in the same triage queue."""
    a = request.get_json(force=True)
    rule = a.get("rule") or {}
    rid = str(rule.get("id", "0"))
    lvl = int(rule.get("level", 3))
    sev = "critical" if lvl >= 12 else "high" if lvl >= 10 else "medium" if lvl >= 7 else "low"
    agent = (a.get("agent") or {}).get("name", "unknown")
    # A hospital ingest key decides the tenant. Without a key, the query or the agent group is used (operator only).
    tenant = g.get("tenant_lock") or request.args.get("tenant") or (a.get("agent") or {}).get("group", "default")
    detail = detect.wazuh_detail(a)
    # Same rule on the same host but a different file/process is a different alert.
    key = f"{agent}|{detail}" if detail else agent
    c = db()
    i = raise_alert(c, tenant, f"WAZUH:{rid}", sev, f"{rule.get('description', 'Wazuh alert')} ({agent})",
                    key, a.get("timestamp", now())[:19], None, "wazuh",
                    detail=detail, step=detect.wazuh_step(rid, lvl))
    c.commit()
    _notify_new(c, [i] if i else [])
    return jsonify(alert_id=i)


@app.get("/api/tenants")
def list_tenants():
    rows = db().execute("SELECT id, name, created FROM tenants ORDER BY id").fetchall()
    return jsonify([dict(r) for r in rows])


@app.post("/api/tenants")
def create_tenant():
    body = request.get_json(force=True) or {}
    tid = (body.get("id") or "").strip()
    if not TENANT_ID_RE.fullmatch(tid):
        return jsonify(error="id must be 2 to 63 lowercase letters, digits or hyphens, starting with a letter or digit"), 400
    name = (body.get("name") or tid).strip()[:120]
    c = db()
    if c.execute("SELECT 1 FROM tenants WHERE id=%s", (tid,)).fetchone():
        return jsonify(error="tenant already exists"), 409
    c.execute("INSERT INTO tenants(id, name) VALUES(%s, %s)", (tid, name))
    c.commit()
    return jsonify(id=tid, name=name), 201


@app.get("/api/tenants/<tid>/keys")
def list_keys(tid):
    """Key metadata only. The key itself is shown once, when it is created."""
    rows = db().execute("SELECT id, label, created, revoked_at FROM ingest_keys WHERE tenant=%s ORDER BY id", (tid,)).fetchall()
    return jsonify([dict(r) for r in rows])


@app.post("/api/tenants/<tid>/keys")
def create_key(tid):
    c = db()
    if not c.execute("SELECT 1 FROM tenants WHERE id=%s", (tid,)).fetchone():
        return jsonify(error="tenant not found"), 404
    body = request.get_json(force=True, silent=True) or {}
    label = (body.get("label") or "").strip()[:80]
    key = secrets.token_urlsafe(32)
    cur = c.execute("INSERT INTO ingest_keys(tenant, label, key_hash) VALUES(%s, %s, %s) RETURNING id",
                    (tid, label, hashlib.sha256(key.encode()).hexdigest()))
    kid = cur.fetchone()["id"]
    c.commit()
    return jsonify(id=kid, tenant=tid, label=label, key=key,
                   note="Store this key now. It is not shown again."), 201


@app.post("/api/keys/<int:kid>/revoke")
def revoke_key(kid):
    c = db()
    cur = c.execute("UPDATE ingest_keys SET revoked_at=COALESCE(revoked_at, %s) WHERE id=%s RETURNING id", (now(), kid))
    if not cur.fetchone():
        return jsonify(error="key not found"), 404
    c.commit()
    return jsonify(ok=True)


@app.get("/api/alerts")
def alerts():
    # last_handoff: the latest handoff as "from -> to: note", so the dashboard can show it (v0.7.1).
    q = ("SELECT alerts.*, (SELECT from_owner || ' -> ' || to_owner || ': ' || COALESCE(NULLIF(note, ''), 'no note') "
         "FROM handoffs h WHERE h.alert_id = alerts.id ORDER BY h.id DESC LIMIT 1) AS last_handoff "
         "FROM alerts WHERE 1=1")
    args = []
    for f in ("tenant", "status", "owner"):
        if request.args.get(f):
            q += f" AND {f}=%s"
            args.append(request.args[f])
    rows = db().execute(q + " ORDER BY id DESC LIMIT 200", args).fetchall()
    return jsonify([dict(r) for r in rows])


@app.post("/api/alerts/<int:i>/ack")
def ack(i):
    c = db()
    c.execute("UPDATE alerts SET status='ack', ack_at=%s WHERE id=%s AND status='new'", (now(), i))
    c.commit()
    return jsonify(ok=True)


@app.post("/api/alerts/<int:i>/verdict")
def verdict(i):
    body = request.get_json(force=True) or {}
    v = body.get("verdict")
    if v not in ("tp", "fp", "unclear"):
        return jsonify(error="verdict must be tp, fp or unclear"), 400
    note = (body.get("note") or "").strip()[:500]  # optional closing note, kept with the alert
    c = db()
    c.execute("UPDATE alerts SET verdict=%s, status='closed', ack_at=COALESCE(ack_at,%s), "
              "resolution=COALESCE(NULLIF(%s,''), resolution) WHERE id=%s", (v, now(), note, i))
    c.commit()
    return jsonify(ok=True)


@app.get("/api/analysts")
def analysts():
    return jsonify(analysts=ANALYSTS)


@app.post("/api/alerts/<int:i>/handoff")
def handoff(i):
    """Pass an open alert to another analyst. The owner changes and the handoff is kept in history."""
    body = request.get_json(force=True) or {}
    to = (body.get("to_owner") or "").strip()
    note = (body.get("note") or "").strip()[:500]
    if to not in ANALYSTS:
        return jsonify(error=f"to_owner must be one of: {', '.join(ANALYSTS)}"), 400
    c = db()
    row = c.execute("SELECT owner, status, tenant FROM alerts WHERE id=%s", (i,)).fetchone()
    if not row:
        return jsonify(error="alert not found"), 404
    if row["status"] == "closed":
        return jsonify(error="alert is closed"), 409
    if to == row["owner"]:
        return jsonify(error=f"alert is already owned by {to}"), 400
    c.execute("INSERT INTO handoffs(alert_id,at,from_owner,to_owner,note,tenant) VALUES(%s,%s,%s,%s,%s,%s)",
              (i, now(), row["owner"], to, note, row["tenant"]))
    c.execute("UPDATE alerts SET owner=%s WHERE id=%s", (to, i))
    c.commit()
    return jsonify(ok=True, from_owner=row["owner"], to_owner=to)


@app.get("/api/alerts/<int:i>/handoffs")
def handoffs(i):
    rows = db().execute("SELECT at, from_owner, to_owner, note FROM handoffs WHERE alert_id=%s ORDER BY id", (i,)).fetchall()
    return jsonify([dict(r) for r in rows])


def _metrics(tenant=None):
    """Counts for one hospital (tenant given) or for all of them (tenant None)."""
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
    return jsonify(_metrics(request.args.get("tenant") or None))


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
    tenant = request.args.get("tenant") or None
    m = _metrics(tenant)
    gates = _gate_results(m, tenant)
    return jsonify(gates=gates, all_pass=all(g["status"] == "pass" for g in gates), fp_target=_fp_target())


@app.post("/api/demo")
def demo():
    """Load synthetic logs + planted attacks (lab only)."""
    generated = generate.generate()
    evs = generated if isinstance(generated, list) else [generated]
    c = db()
    made_ids = _store_events(c, evs)
    c.commit()
    _notify_new(c, made_ids)
    return jsonify(events=len(evs), alerts_created=len(made_ids))


@app.post("/api/autolabel")
def autolabel():
    """Lab shortcut: label alerts from planted ground truth. Real triage uses manual verdicts."""
    c = db()
    c.execute("UPDATE alerts SET verdict=CASE WHEN attack_id IS NOT NULL THEN 'tp' ELSE 'fp' END WHERE verdict IS NULL AND source='builtin'")
    c.commit()
    return jsonify(ok=True)


@app.post("/api/reset")
def reset():
    c = db()
    c.execute("TRUNCATE events, alerts, handoffs RESTART IDENTITY")
    c.commit()
    return jsonify(ok=True)


@app.get("/")
def home():
    return send_from_directory("static", "index.html")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
