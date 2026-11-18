"""Cybrot SOC Core - prototype: ingest -> detect -> triage queue (owner + response step) -> metrics."""
import os, sqlite3
from datetime import datetime, timezone
from flask import Flask, request, jsonify, send_from_directory
import detect, generate

DB = os.environ.get("SOC_DB", "soc.db")
ANALYSTS = os.environ.get("ANALYSTS", "analyst1,analyst2,analyst3").split(",")
# Lab-only endpoints (synthetic data, demo load, reset). Set LAB_ENDPOINTS=0 in any
# environment where real logs or real analysts' work could be in the database.
LAB_ENDPOINTS = os.environ.get("LAB_ENDPOINTS", "1") == "1"
LAB_PATHS = {"/api/demo", "/api/autolabel", "/api/reset"}
app = Flask(__name__, static_folder="static")

SCHEMA = """
CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY, ts TEXT, tenant TEXT, source TEXT, type TEXT,
  user TEXT, host TEXT, ip TEXT, patient TEXT, detail TEXT, attack_id TEXT);
CREATE INDEX IF NOT EXISTS ev_idx ON events(tenant, type, ts);
CREATE TABLE IF NOT EXISTS alerts(id INTEGER PRIMARY KEY, created TEXT, event_ts TEXT, tenant TEXT, rule TEXT,
  severity TEXT, summary TEXT, dkey TEXT, owner TEXT, step TEXT, status TEXT DEFAULT 'new',
  ack_at TEXT, verdict TEXT, attack_id TEXT, source TEXT DEFAULT 'builtin', detail TEXT);
"""


def db():
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    c.executescript(SCHEMA)
    # Migrate databases created before the 'detail' column existed.
    cols = {r["name"] for r in c.execute("PRAGMA table_info(alerts)")}
    if "detail" not in cols:
        c.execute("ALTER TABLE alerts ADD COLUMN detail TEXT")
    return c


def now():
    return datetime.now(timezone.utc).strftime(detect.FMT)


def raise_alert(c, tenant, rule, sev, summary, key, event_ts, attack_id=None, source="builtin",
                detail="", step=None):
    dup = c.execute("SELECT 1 FROM alerts WHERE rule=? AND tenant=? AND dkey=? AND event_ts>=?",
                    (rule, tenant, key, detect._ago(event_ts, 10))).fetchone() if event_ts else None
    if dup:
        return None
    n = c.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    owner = ANALYSTS[n % len(ANALYSTS)]
    step = step or detect.PLAYBOOK.get(rule, "Review the alert details and decide: escalate, fix, or close as benign.")
    cur = c.execute("INSERT INTO alerts(created,event_ts,tenant,rule,severity,summary,dkey,owner,step,attack_id,source,detail) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                    (now(), event_ts, tenant, rule, sev, summary, key, owner, step, attack_id, source, detail))
    return cur.lastrowid


@app.before_request
def gate_lab_endpoints():
    if not LAB_ENDPOINTS and request.path in LAB_PATHS:
        return jsonify(error="lab endpoint disabled (LAB_ENDPOINTS=0)"), 404


@app.post("/api/events")
def ingest():
    body = request.get_json(force=True)
    evs = body if isinstance(body, list) else [body]
    c = db()
    made = 0
    for e in sorted(evs, key=lambda x: x["ts"]):
        e.setdefault("attack_id", None)
        for k in ("user", "host", "ip", "patient", "detail", "source"):
            e.setdefault(k, "")
        c.execute("INSERT INTO events(ts,tenant,source,type,user,host,ip,patient,detail,attack_id) "
                  "VALUES(:ts,:tenant,:source,:type,:user,:host,:ip,:patient,:detail,:attack_id)", e)
        hit = detect.evaluate(c, e)
        if hit and raise_alert(c, e["tenant"], *hit[:3], hit[3], e["ts"], e["attack_id"]):
            made += 1
    c.commit()
    return jsonify(events=len(evs), alerts_created=made)


@app.post("/api/ingest/wazuh")
def ingest_wazuh():
    """Accepts a Wazuh integration (webhook) alert and drops it in the same triage queue."""
    a = request.get_json(force=True)
    rule = a.get("rule") or {}
    rid = str(rule.get("id", "0"))
    lvl = int(rule.get("level", 3))
    sev = "critical" if lvl >= 12 else "high" if lvl >= 10 else "medium" if lvl >= 7 else "low"
    agent = (a.get("agent") or {}).get("name", "unknown")
    tenant = request.args.get("tenant") or (a.get("agent") or {}).get("group", "default")
    detail = detect.wazuh_detail(a)
    # Same rule on the same host but a different file/process is a different alert.
    key = f"{agent}|{detail}" if detail else agent
    c = db()
    i = raise_alert(c, tenant, f"WAZUH:{rid}", sev, f"{rule.get('description', 'Wazuh alert')} ({agent})",
                    key, a.get("timestamp", now())[:19], None, "wazuh",
                    detail=detail, step=detect.wazuh_step(rid, lvl))
    c.commit()
    return jsonify(alert_id=i)


@app.get("/api/alerts")
def alerts():
    q, args = "SELECT * FROM alerts WHERE 1=1", []
    for f in ("tenant", "status", "owner"):
        if request.args.get(f):
            q += f" AND {f}=?"
            args.append(request.args[f])
    rows = db().execute(q + " ORDER BY id DESC LIMIT 200", args).fetchall()
    return jsonify([dict(r) for r in rows])


@app.post("/api/alerts/<int:i>/ack")
def ack(i):
    c = db()
    c.execute("UPDATE alerts SET status='ack', ack_at=? WHERE id=? AND status='new'", (now(), i))
    c.commit()
    return jsonify(ok=True)


@app.post("/api/alerts/<int:i>/verdict")
def verdict(i):
    v = (request.get_json(force=True) or {}).get("verdict")
    if v not in ("tp", "fp", "unclear"):
        return jsonify(error="verdict must be tp, fp or unclear"), 400
    c = db()
    c.execute("UPDATE alerts SET verdict=?, status='closed', ack_at=COALESCE(ack_at,?) WHERE id=?", (v, now(), i))
    c.commit()
    return jsonify(ok=True)


@app.get("/api/metrics")
def metrics():
    c = db()
    q = lambda s, a=(): c.execute(s, a).fetchone()[0]
    tp, fp = q("SELECT COUNT(*) FROM alerts WHERE verdict='tp'"), q("SELECT COUNT(*) FROM alerts WHERE verdict='fp'")
    planted = q("SELECT COUNT(DISTINCT attack_id) FROM events WHERE attack_id IS NOT NULL")
    caught = q("SELECT COUNT(DISTINCT attack_id) FROM alerts WHERE attack_id IS NOT NULL")
    mtta = c.execute("SELECT AVG(strftime('%s',ack_at)-strftime('%s',created)) FROM alerts WHERE ack_at IS NOT NULL").fetchone()[0]
    return jsonify(events=q("SELECT COUNT(*) FROM events"), alerts=q("SELECT COUNT(*) FROM alerts"),
                   by_severity={r[0]: r[1] for r in c.execute("SELECT severity, COUNT(*) FROM alerts GROUP BY severity")},
                   unacknowledged=q("SELECT COUNT(*) FROM alerts WHERE status='new'"),
                   unlabeled=q("SELECT COUNT(*) FROM alerts WHERE verdict IS NULL"),
                   false_positive_rate=round(fp / (tp + fp), 3) if tp + fp else None,
                   planted_attacks=planted, detected_attacks=caught,
                   detection_rate=round(caught / planted, 3) if planted else None,
                   mean_time_to_ack_s=round(mtta, 1) if mtta is not None else None)


@app.post("/api/demo")
def demo():
    """Load synthetic logs + planted attacks (lab only)."""
    r = app.test_client().post("/api/events", json=generate.generate())
    return r.get_json()


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
    c.executescript("DELETE FROM events; DELETE FROM alerts;")
    return jsonify(ok=True)


@app.get("/")
def home():
    return send_from_directory("static", "index.html")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
