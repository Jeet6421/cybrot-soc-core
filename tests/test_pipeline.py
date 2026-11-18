import json, os, sqlite3, tempfile
os.environ["SOC_DB"] = os.path.join(tempfile.mkdtemp(), "t.db")
import app as soc
c = soc.app.test_client()

FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "wazuh_92213_psscriptpolicy.json")


def wazuh_sample():
    with open(FIXTURE) as f:
        return json.load(f)


def test_demo_detects_all_planted_attacks():
    c.post("/api/reset")
    assert c.post("/api/demo").get_json()["alerts_created"] > 0
    m = c.get("/api/metrics").get_json()
    assert m["planted_attacks"] == 3 and m["detection_rate"] == 1.0
    rules = {a["rule"] for a in c.get("/api/alerts").get_json()}
    assert {"FAILED_LOGIN_BURST", "BULK_RECORD_ACCESS", "SUSPICIOUS_PROCESS"} <= rules


def test_every_alert_has_owner_and_step():
    for a in c.get("/api/alerts").get_json():
        assert a["owner"] and a["step"]


def test_lone_failed_login_does_not_alert():
    c.post("/api/reset")
    c.post("/api/events", json=[dict(ts="2026-11-18T11:00:00", tenant="t1", source="auth", type="auth_fail", user="dr.1", ip="10.0.0.5")])
    assert c.get("/api/metrics").get_json()["alerts"] == 0


def test_ack_verdict_and_fp_rate():
    c.post("/api/reset"); c.post("/api/demo")
    ids = [a["id"] for a in c.get("/api/alerts").get_json()]
    c.post(f"/api/alerts/{ids[0]}/ack")
    c.post(f"/api/alerts/{ids[0]}/verdict", json={"verdict": "tp"})
    c.post(f"/api/alerts/{ids[1]}/verdict", json={"verdict": "fp"})
    m = c.get("/api/metrics").get_json()
    assert m["false_positive_rate"] == 0.5 and m["mean_time_to_ack_s"] is not None


def test_wazuh_webhook_lands_in_queue():
    c.post("/api/reset")
    r = c.post("/api/ingest/wazuh?tenant=city-hospital", json={"rule": {"id": "5712", "level": 10, "description": "sshd brute force"},
                                                              "agent": {"name": "ehr-01"}, "timestamp": "2026-11-18T11:00:00.000+0000"})
    assert r.get_json()["alert_id"]
    a = c.get("/api/alerts?tenant=city-hospital").get_json()[0]
    assert a["severity"] == "high" and a["source"] == "wazuh" and a["owner"]


def test_real_wazuh_alert_has_detail_and_specific_step():
    c.post("/api/reset")
    aid = c.post("/api/ingest/wazuh?tenant=city-hospital", json=wazuh_sample()).get_json()["alert_id"]
    a = next(x for x in c.get("/api/alerts").get_json() if x["id"] == aid)
    assert a["rule"] == "WAZUH:92213" and a["severity"] == "critical"
    assert "__PSScriptPolicyTest_" in a["detail"]
    assert "PSScriptPolicyTest" in a["step"] and a["owner"]


def test_same_file_is_deduped_but_a_different_file_alerts():
    c.post("/api/reset")
    body = wazuh_sample()
    assert c.post("/api/ingest/wazuh?tenant=city-hospital", json=body).get_json()["alert_id"]
    assert c.post("/api/ingest/wazuh?tenant=city-hospital", json=body).get_json()["alert_id"] is None
    body["data"]["win"]["eventdata"]["targetFilename"] = "C:\\Users\\win10\\Downloads\\invoice.exe"
    assert c.post("/api/ingest/wazuh?tenant=city-hospital", json=body).get_json()["alert_id"]
    assert len(c.get("/api/alerts").get_json()) == 2


def test_lab_endpoints_can_be_disabled():
    soc.LAB_ENDPOINTS = False
    try:
        assert c.post("/api/reset").status_code == 404
        assert c.post("/api/demo").status_code == 404
        assert c.get("/api/metrics").status_code == 200
    finally:
        soc.LAB_ENDPOINTS = True


def test_old_database_gets_detail_column():
    path = os.path.join(tempfile.mkdtemp(), "old.db")
    old = sqlite3.connect(path)
    old.executescript("""CREATE TABLE alerts(id INTEGER PRIMARY KEY, created TEXT, event_ts TEXT, tenant TEXT, rule TEXT,
      severity TEXT, summary TEXT, dkey TEXT, owner TEXT, step TEXT, status TEXT DEFAULT 'new',
      ack_at TEXT, verdict TEXT, attack_id TEXT, source TEXT DEFAULT 'builtin');""")
    old.commit(); old.close()
    old_db = soc.DB
    soc.DB = path
    try:
        cols = {r["name"] for r in soc.db().execute("PRAGMA table_info(alerts)")}
        assert "detail" in cols
    finally:
        soc.DB = old_db
