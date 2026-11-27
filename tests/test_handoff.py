import pytest

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


TARGET = "analyst-l1"  # an active L1 analyst of the City hospital


def analyst_id(username):
    return next(a["user_id"] for a in c.get("/api/analysts").get_json()["analysts"] if a["username"] == username)


def test_handoff_changes_owner_and_keeps_history():
    a = one_alert()
    r = c.post(f"/api/alerts/{a['id']}/handoff", json={"to_actor_id": analyst_id(TARGET), "note": "check the host"})
    assert r.status_code == 200 and r.get_json()["to_owner"] == TARGET
    after = next(x for x in c.get("/api/alerts").get_json() if x["id"] == a["id"])
    assert after["owner"] == TARGET
    hist = c.get(f"/api/alerts/{a['id']}/handoffs").get_json()
    assert len(hist) == 1
    assert hist[0]["from_owner"] == a["owner"] and hist[0]["to_owner"] == TARGET
    assert "note" not in hist[0] and hist[0]["at"]


def test_alert_list_shows_latest_handoff_without_free_form_note():
    a = one_alert()
    c.post(f"/api/alerts/{a['id']}/handoff", json={"to_actor_id": analyst_id(TARGET), "note": "check the host"})
    row = next(x for x in c.get("/api/alerts").get_json() if x["id"] == a["id"])
    assert row["last_handoff"] == f"{a['owner']} -> {TARGET}"


def test_alert_list_marks_handoff_without_note():
    a = one_alert()
    c.post(f"/api/alerts/{a['id']}/handoff", json={"to_actor_id": analyst_id(TARGET)})
    row = next(x for x in c.get("/api/alerts").get_json() if x["id"] == a["id"])
    assert row["last_handoff"] == f"{a['owner']} -> {TARGET}"


def test_alert_without_handoff_has_no_last_handoff():
    a = one_alert()
    row = next(x for x in c.get("/api/alerts").get_json() if x["id"] == a["id"])
    assert row["last_handoff"] is None


def test_handoff_refuses_a_user_who_is_not_an_active_analyst():
    a = one_alert()
    assert c.post(f"/api/alerts/{a['id']}/handoff", json={"to_actor_id": 999999}).status_code == 400
    viewer_id = next(u["id"] for u in c.get("/api/users").get_json() if u["username"] == "viewer")
    assert c.post(f"/api/alerts/{a['id']}/handoff", json={"to_actor_id": viewer_id}).status_code == 400


def test_handoff_by_name_is_retired():
    a = one_alert()
    r = c.post(f"/api/alerts/{a['id']}/handoff", json={"to_owner": TARGET})
    assert r.status_code == 400 and "to_actor_id" in r.get_json()["error"]


def test_handoff_refuses_same_owner():
    a = one_alert()
    assert c.post(f"/api/alerts/{a['id']}/handoff", json={"to_actor_id": analyst_id(TARGET)}).status_code == 200
    assert c.post(f"/api/alerts/{a['id']}/handoff", json={"to_actor_id": analyst_id(TARGET)}).status_code == 400


def test_handoff_unknown_alert_is_404():
    one_alert()
    r = c.post("/api/alerts/999999/handoff", json={"to_actor_id": analyst_id(TARGET)})
    assert r.status_code == 404


def test_closed_alert_cannot_be_handed_off():
    a = one_alert()
    c.post(f"/api/alerts/{a['id']}/verdict", json={"verdict": "true_positive_malicious"})
    r = c.post(f"/api/alerts/{a['id']}/handoff", json={"to_actor_id": analyst_id(TARGET)})
    assert r.status_code == 409


def test_verdict_note_is_not_exposed_in_alert_telemetry():
    a = one_alert()
    c.post(f"/api/alerts/{a['id']}/verdict", json={"verdict": "false_positive", "note": "PowerShell policy test file"})
    after = next(x for x in c.get("/api/alerts").get_json() if x["id"] == a["id"])
    assert after["verdict"] == "false_positive" and "resolution" not in after


def test_repeated_verdict_does_not_expose_resolution_note():
    a = one_alert()
    c.post(f"/api/alerts/{a['id']}/verdict", json={"verdict": "true_positive_malicious", "note": "confirmed"})
    c.post(f"/api/alerts/{a['id']}/verdict", json={"verdict": "true_positive_malicious"})
    after = next(x for x in c.get("/api/alerts").get_json() if x["id"] == a["id"])
    assert after["status"] == "closed" and "resolution" not in after


def test_analysts_endpoint_lists_active_hospital_analysts():
    names = {a["username"] for a in c.get("/api/analysts").get_json()["analysts"]}
    assert {"admin", "analyst-l1", "analyst-l2"} <= names
    assert "viewer" not in names and "vendor" not in names


def test_reset_clears_handoff_history():
    a = one_alert()
    c.post(f"/api/alerts/{a['id']}/handoff", json={"to_actor_id": analyst_id(TARGET)})
    c.post("/api/reset")
    # The alert is gone with the reset, so its history is gone too.
    assert c.get(f"/api/alerts/{a['id']}/handoffs").status_code == 404
