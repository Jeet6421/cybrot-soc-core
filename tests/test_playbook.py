import json, os, sys, tempfile, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
os.environ.setdefault("SOC_DB", os.path.join(tempfile.mkdtemp(), "playbook.db"))
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import app as soc

c = soc.app.test_client()

ENC = "powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA"


def enc_event(host="ws-1"):
    return {"ts": "2026-11-25T10:00:00", "tenant": "city-hospital", "source": "t",
            "type": "process_start", "user": "u", "host": host, "detail": ENC}


def capture(monkeypatch):
    """Replace the background dispatch with a recorder so tests are deterministic."""
    sent = []
    monkeypatch.setattr(soc, "_dispatch", lambda url, payload: sent.append((url, payload)))
    return sent


def test_no_webhook_means_nothing_is_sent(monkeypatch):
    c.post("/api/reset")
    monkeypatch.delenv("PLAYBOOK_WEBHOOK", raising=False)
    sent = capture(monkeypatch)
    r = c.post("/api/events", json=[enc_event()])
    assert r.get_json()["alerts_created"] == 1
    assert sent == []


def test_new_alert_is_sent_with_owner_and_step(monkeypatch):
    c.post("/api/reset")
    monkeypatch.setenv("PLAYBOOK_WEBHOOK", "http://playbooks.invalid/hook")
    sent = capture(monkeypatch)
    c.post("/api/events", json=[enc_event()])
    assert len(sent) == 1
    url, payload = sent[0]
    assert url == "http://playbooks.invalid/hook"
    assert payload["event"] == "alert.created"
    alert = payload["alert"]
    assert alert["rule"] == "SUSPICIOUS_PROCESS" and alert["severity"] == "critical"
    assert alert["owner"] in soc.ANALYSTS and alert["step"]
    assert "token" not in json.dumps(payload).lower()


def test_duplicate_alert_is_not_sent_twice(monkeypatch):
    c.post("/api/reset")
    monkeypatch.setenv("PLAYBOOK_WEBHOOK", "http://playbooks.invalid/hook")
    sent = capture(monkeypatch)
    c.post("/api/events", json=[enc_event()])
    c.post("/api/events", json=[enc_event()])  # same rule, host and time: suppressed as a repeat
    assert len(sent) == 1


def test_wazuh_alert_is_sent(monkeypatch):
    c.post("/api/reset")
    monkeypatch.setenv("PLAYBOOK_WEBHOOK", "http://playbooks.invalid/hook")
    sent = capture(monkeypatch)
    r = c.post("/api/ingest/wazuh?tenant=city-hospital",
               json={"rule": {"id": "92213", "level": 12, "description": "Executable file dropped"},
                     "agent": {"name": "ws-9"}, "timestamp": "2026-11-25T10:00:00"})
    assert r.get_json()["alert_id"] is not None
    assert len(sent) == 1 and sent[0][1]["alert"]["rule"] == "WAZUH:92213"


def test_send_posts_json_to_a_receiver():
    got = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            body = self.rfile.read(int(self.headers["Content-Length"]))
            got.append((self.headers.get("Content-Type"), json.loads(body)))
            self.send_response(200)
            self.end_headers()

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        url = f"http://127.0.0.1:{server.server_port}/hook"
        assert soc._send(url, {"event": "alert.created", "alert": {"id": 7}}) is True
    finally:
        server.shutdown()
    assert got == [("application/json", {"event": "alert.created", "alert": {"id": 7}})]


def test_failed_delivery_returns_false_and_ingest_still_works(monkeypatch):
    c.post("/api/reset")
    # Nothing listens on port 1, so the connection is refused.
    assert soc._send("http://127.0.0.1:1/hook", {"x": 1}, timeout=1) is False
    monkeypatch.setenv("PLAYBOOK_WEBHOOK", "http://127.0.0.1:1/hook")
    r = c.post("/api/events", json=[enc_event("ws-failing")])
    assert r.status_code == 200 and r.get_json()["alerts_created"] == 1
