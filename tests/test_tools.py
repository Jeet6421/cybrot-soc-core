import os, sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts"))
import attack_sim, load_test

import app as soc
from support import Api

c = None


@pytest.fixture(autouse=True)
def _api(world):
    global c
    c = Api(world)


# post() sends events and alerts as the City ingest key; get() reads as the City hospital admin.
post = lambda p, b: c.post(p, json=b).get_json()
get = lambda p: c.get(p).get_json()


def gates():
    return {g["id"]: g["status"] for g in get("/api/exit-criteria")["gates"]}


def test_attack_simulations_all_pass():
    c.post("/api/reset")
    results = attack_sim.run(post, get)
    assert len(results) == 4
    assert all(r["passed"] for r in results), results


def test_repeat_run_passes_after_alert_list_moves_on():
    # Regression: a second run used to fail once the first run's alerts fell out of the newest-200 list.
    c.post("/api/reset")
    assert all(r["passed"] for r in attack_sim.run(post, get))
    for i in range(250):  # push the first run's alerts out of the newest-200 window
        c.post("/api/ingest/wazuh", json={"rule": {"id": "5501", "level": 7, "description": "filler"},
                                          "agent": {"name": f"filler-{i}"}, "timestamp": "2026-11-20T10:00:00"})
    results = attack_sim.run(post, get)
    assert all(r["passed"] for r in results), results


def test_load_test_loses_no_events():
    c.post("/api/reset")
    r = load_test.run(post, get, n=1200, batch=250)
    assert r["sent"] == 1200 and r["stored"] == 1200 and r["lost"] == 0
    assert get("/api/metrics")["alerts"] == 0  # benign traffic must not raise alerts


def test_exit_criteria_start_not_measured(monkeypatch):
    c.post("/api/reset")
    monkeypatch.delenv("FP_TARGET", raising=False)
    g = gates()
    assert g == {"foundation": "not_measured", "detection": "not_measured",
                 "response": "not_measured", "review": "not_measured"}
    assert get("/api/exit-criteria")["all_pass"] is False


def test_exit_criteria_pass_after_simulations(monkeypatch):
    c.post("/api/reset")
    monkeypatch.setenv("FP_TARGET", "0.5")
    monkeypatch.setenv("MIN_LABELED_SAMPLE", "1")  # the simulation labels too few alerts per rule for the default 30
    attack_sim.run(post, get)
    post("/api/autolabel", {})
    g = gates()
    assert g["foundation"] == "pass"
    assert g["detection"] == "pass"
    assert g["response"] == "pass"
    assert g["review"] == "pass"
    assert get("/api/exit-criteria")["all_pass"] is True


def test_review_fails_when_false_positives_exceed_target(monkeypatch):
    c.post("/api/reset")
    monkeypatch.setenv("FP_TARGET", "0.10")
    monkeypatch.setenv("MIN_LABELED_SAMPLE", "1")
    attack_sim.run(post, get)
    post("/api/autolabel", {})
    first = get("/api/alerts")[0]["id"]
    c.post(f"/api/alerts/{first}/verdict", json={"verdict": "false_positive"})  # 1 fp out of 3 labeled = 33%
    assert gates()["review"] == "fail"


def test_weekly_false_positive_rate():
    c.post("/api/reset")
    attack_sim.run(post, get)
    post("/api/autolabel", {})
    first = get("/api/alerts")[0]["id"]
    c.post(f"/api/alerts/{first}/verdict", json={"verdict": "false_positive"})
    weeks = get("/api/metrics")["false_positive_rate_by_week"]
    assert len(weeks) >= 1
    assert sum(w["tp"] for w in weeks) == 2 and sum(w["fp"] for w in weeks) == 1
    assert all(0 <= w["false_positive_rate"] <= 1 for w in weeks)


def test_bad_fp_target_is_ignored(monkeypatch):
    monkeypatch.setenv("FP_TARGET", "ten percent")
    assert soc._fp_target() is None
