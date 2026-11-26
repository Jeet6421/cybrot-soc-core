import json, os

import psycopg
import pytest

import app as soc
import migrate
from support import APP_PASSWORD, Api, CITY, ORTHO

FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "wazuh_92213_psscriptpolicy.json")

c = None


@pytest.fixture(autouse=True)
def _api(world):
    global c
    c = Api(world)


def wazuh_sample():
    with open(FIXTURE) as f:
        return json.load(f)


def test_demo_detects_all_planted_attacks():
    c.post("/api/reset")
    assert c.post("/api/demo").get_json()["alerts_created"] > 0
    city = c.get("/api/metrics").get_json()  # City: one planted attack (bruteforce)
    assert city["planted_attacks"] == 1 and city["detection_rate"] == 1.0
    ortho = Api(c.world, ORTHO).get("/api/metrics").get_json()  # Ortho: bulk access + suspicious process
    assert ortho["planted_attacks"] == 2 and ortho["detection_rate"] == 1.0
    rules = {a["rule"] for a in c.get("/api/alerts").get_json()} | \
        {a["rule"] for a in Api(c.world, ORTHO).get("/api/alerts").get_json()}
    assert {"FAILED_LOGIN_BURST", "BULK_RECORD_ACCESS", "SUSPICIOUS_PROCESS"} <= rules


def test_every_alert_has_owner_and_step():
    for a in c.get("/api/alerts").get_json():
        assert a["owner"] and a["step"]


def test_lone_failed_login_does_not_alert():
    c.post("/api/reset")
    c.post("/api/events", json=[dict(ts="2026-11-18T11:00:00", tenant=CITY, source="auth", type="auth_fail", user="dr.1", ip="10.0.0.5")])
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
    r = c.post("/api/ingest/wazuh", json={"rule": {"id": "5712", "level": 10, "description": "sshd brute force"},
                                          "agent": {"name": "ehr-01"}, "timestamp": "2026-11-18T11:00:00.000+0000"})
    assert r.get_json()["alert_id"]
    a = c.get("/api/alerts").get_json()[0]
    assert a["severity"] == "high" and a["source"] == "wazuh" and a["owner"]


def test_real_wazuh_alert_omits_raw_detail_but_keeps_specific_step():
    c.post("/api/reset")
    aid = c.post("/api/ingest/wazuh", json=wazuh_sample()).get_json()["alert_id"]
    a = next(x for x in c.get("/api/alerts").get_json() if x["id"] == aid)
    assert a["rule"] == "WAZUH:92213" and a["severity"] == "critical"
    assert "detail" not in a
    assert "PSScriptPolicyTest" in a["step"] and a["owner"]


def test_same_file_is_deduped_but_a_different_file_alerts():
    c.post("/api/reset")
    body = wazuh_sample()
    assert c.post("/api/ingest/wazuh", json=body).get_json()["alert_id"]
    assert c.post("/api/ingest/wazuh", json=body).get_json()["alert_id"] is None
    body["data"]["win"]["eventdata"]["targetFilename"] = "C:\\Users\\win10\\Downloads\\invoice.exe"
    assert c.post("/api/ingest/wazuh", json=body).get_json()["alert_id"]
    assert len(c.get("/api/alerts").get_json()) == 2


def test_lab_endpoints_can_be_disabled(monkeypatch):
    monkeypatch.setattr(soc, "LAB_ENDPOINTS", False)
    assert c.post("/api/reset").status_code == 404
    assert c.post("/api/demo").status_code == 404
    assert c.get("/api/metrics").status_code == 200


def test_old_database_gets_new_columns(scratch_db):
    # Old event and alert tables must gain the pilot-rule and identity fields in place.
    with psycopg.connect(scratch_db) as old:
        old.execute("""CREATE TABLE alerts(id BIGSERIAL PRIMARY KEY, created TEXT, event_ts TEXT, tenant TEXT, rule TEXT,
          severity TEXT, summary TEXT, dkey TEXT, owner TEXT, step TEXT, status TEXT DEFAULT 'new',
          ack_at TEXT, verdict TEXT, attack_id TEXT, source TEXT DEFAULT 'builtin')""")
        old.execute('''CREATE TABLE events(id BIGSERIAL PRIMARY KEY, ts TEXT, tenant TEXT, source TEXT, type TEXT,
          "user" TEXT, host TEXT, ip TEXT, patient TEXT, detail TEXT, attack_id TEXT)''')
    migrate.migrate(scratch_db, APP_PASSWORD)
    with psycopg.connect(scratch_db) as conn:
        cols = {r[0] for r in conn.execute(
            "SELECT column_name FROM information_schema.columns WHERE table_name='alerts'").fetchall()}
        event_cols = {r[0] for r in conn.execute(
            "SELECT column_name FROM information_schema.columns WHERE table_name='events'").fetchall()}
    assert {"detail", "resolution", "rule_version"} <= cols
    assert {"destination", "data_classification", "destination_approved", "src_zone", "dst_zone",
            "boundary_violation", "approved_change", "log_source_id"} <= event_cols


def test_every_api_call_needs_a_session_or_an_ingest_key(world):
    assert world.client.get("/api/metrics").status_code == 401
    assert world.client.get("/api/metrics", headers={"Authorization": "Bearer wrong"}).status_code == 401
    assert world.client.get("/api/metrics", headers=world.session(CITY, "viewer")).status_code == 200
    assert world.client.get("/").status_code == 200  # the dashboard page itself is public


def test_wazuh_ingest_accepts_key_in_query_only_on_ingest_paths(world):
    c.post("/api/reset")
    assert world.client.post("/api/ingest/wazuh", json=wazuh_sample()).status_code == 401
    r = world.client.post(f"/api/ingest/wazuh?token={world.ingest_token(CITY)}", json=wazuh_sample())
    assert r.status_code == 200 and r.get_json()["alert_id"]
    # A user session is not an ingest key, even in the query string.
    token = world.session(CITY, "hospital_admin")["Authorization"].split()[1]
    assert world.client.post(f"/api/ingest/wazuh?token={token}", json=wazuh_sample()).status_code == 403
    # Query-string keys are not accepted outside ingest.
    assert world.client.get(f"/api/metrics?token={world.ingest_token(CITY)}").status_code == 401
