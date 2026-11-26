import pytest

import app as soc
from support import Api, CITY

c = None

ENC = "powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA"


@pytest.fixture(autouse=True)
def _api(world):
    global c
    c = Api(world)


def one_alert():
    """Reset, then raise exactly one alert. Returns the alert row."""
    c.post("/api/reset")
    c.post("/api/events", json=[{"ts": "2026-11-20T11:00:00", "tenant": CITY, "source": "t",
                                 "type": "process_start", "user": "u", "host": "ws-1", "detail": ENC}])
    return c.get(f"/api/alerts?tenant={CITY}").get_json()[0]


def other_analyst(owner):
    return next(a for a in soc.ANALYSTS if a != owner)


def test_handoff_changes_owner_and_keeps_history():
    a = one_alert()
    to = other_analyst(a["owner"])
    r = c.post(f"/api/alerts/{a['id']}/handoff", json={"to_owner": to, "note": "check the host"})
    assert r.status_code == 200 and r.get_json()["to_owner"] == to
    after = next(x for x in c.get("/api/alerts").get_json() if x["id"] == a["id"])
    assert after["owner"] == to
    hist = c.get(f"/api/alerts/{a['id']}/handoffs").get_json()
    assert len(hist) == 1
    assert hist[0]["from_owner"] == a["owner"] and hist[0]["to_owner"] == to
    assert "note" not in hist[0] and hist[0]["at"]


def test_alert_list_shows_latest_handoff_without_free_form_note():
    a = one_alert()
    to = other_analyst(a["owner"])
    c.post(f"/api/alerts/{a['id']}/handoff", json={"to_owner": to, "note": "check the host"})
    row = next(x for x in c.get("/api/alerts").get_json() if x["id"] == a["id"])
    assert row["last_handoff"] == f"{a['owner']} -> {to}"


def test_alert_list_marks_handoff_without_note():
    a = one_alert()
    to = other_analyst(a["owner"])
    c.post(f"/api/alerts/{a['id']}/handoff", json={"to_owner": to})
    row = next(x for x in c.get("/api/alerts").get_json() if x["id"] == a["id"])
    assert row["last_handoff"] == f"{a['owner']} -> {to}"


def test_alert_without_handoff_has_no_last_handoff():
    a = one_alert()
    row = next(x for x in c.get("/api/alerts").get_json() if x["id"] == a["id"])
    assert row["last_handoff"] is None


def test_handoff_refuses_unknown_owner():
    a = one_alert()
    r = c.post(f"/api/alerts/{a['id']}/handoff", json={"to_owner": "nobody"})
    assert r.status_code == 400


def test_handoff_refuses_same_owner():
    a = one_alert()
    r = c.post(f"/api/alerts/{a['id']}/handoff", json={"to_owner": a["owner"]})
    assert r.status_code == 400


def test_handoff_unknown_alert_is_404():
    one_alert()
    r = c.post("/api/alerts/999999/handoff", json={"to_owner": soc.ANALYSTS[0]})
    assert r.status_code == 404


def test_closed_alert_cannot_be_handed_off():
    a = one_alert()
    c.post(f"/api/alerts/{a['id']}/verdict", json={"verdict": "tp"})
    r = c.post(f"/api/alerts/{a['id']}/handoff", json={"to_owner": other_analyst(a["owner"])})
    assert r.status_code == 409


def test_verdict_note_is_not_exposed_in_alert_telemetry():
    a = one_alert()
    c.post(f"/api/alerts/{a['id']}/verdict", json={"verdict": "fp", "note": "PowerShell policy test file"})
    after = next(x for x in c.get("/api/alerts").get_json() if x["id"] == a["id"])
    assert after["verdict"] == "fp" and "resolution" not in after


def test_repeated_verdict_does_not_expose_resolution_note():
    a = one_alert()
    c.post(f"/api/alerts/{a['id']}/verdict", json={"verdict": "tp", "note": "confirmed"})
    c.post(f"/api/alerts/{a['id']}/verdict", json={"verdict": "tp"})
    after = next(x for x in c.get("/api/alerts").get_json() if x["id"] == a["id"])
    assert after["status"] == "closed" and "resolution" not in after


def test_analysts_endpoint_lists_owners():
    assert c.get("/api/analysts").get_json()["analysts"] == soc.ANALYSTS


def test_reset_clears_handoff_history():
    a = one_alert()
    c.post(f"/api/alerts/{a['id']}/handoff", json={"to_owner": other_analyst(a["owner"])})
    c.post("/api/reset")
    # The alert is gone with the reset, so its history is gone too.
    assert c.get(f"/api/alerts/{a['id']}/handoffs").status_code == 404
