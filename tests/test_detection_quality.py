"""Detection quality: honest false-positive bounds, the tuning gate, grouping by (rule, log source), tenant
isolation, SOC visibility KPIs and the standard verdict vocabulary.

Alerts are seeded through the owner connection so each test controls the verdict and log source exactly.
Every rule name carries a random suffix so tests do not see each other's alerts.
"""
import uuid

import psycopg

from support import Api, CITY, ORTHO, ensure_asset


def _rule():
    return f"TEST_RULE_{uuid.uuid4().hex[:8]}"


def _log_source(world, tenant, name=None):
    with psycopg.connect(world.owner_url) as owner:
        return owner.execute("INSERT INTO log_sources(tenant, name, kind) VALUES (%s, %s, 'test') RETURNING id",
                             (tenant, name or f"src-{uuid.uuid4().hex[:8]}")).fetchone()[0]


def _seed(world, tenant, rule, rows):
    """rows: (verdict or None, log_source_id or None). Returns the new alert ids."""
    ids = []
    with psycopg.connect(world.owner_url) as owner:
        for verdict, source in rows:
            ids.append(owner.execute(
                "INSERT INTO alerts(created, event_ts, tenant, rule, rule_version, severity, summary, dkey, owner, "
                "step, source, log_source_id, verdict) VALUES ('2026-11-18T10:00:00', '2026-11-18T10:00:00', %s, %s, "
                "'1', 'high', 'seeded', %s, 'analyst', 'review', 'builtin', %s, %s) RETURNING id",
                (tenant, rule, uuid.uuid4().hex, source, verdict)).fetchone()[0])
    return ids


def _quality(world, tenant=CITY):
    body = Api(world, tenant, "hospital_admin").get("/api/detection-quality").get_json()
    return body


def _rows_for(body, rule):
    return [r for r in body["rules"] if r["rule_id"] == rule]


def test_ten_percent_coverage_with_no_observed_fp_is_not_eligible_and_bounds_stay_honest(world, monkeypatch):
    monkeypatch.setenv("FP_TARGET", "0.10")
    rule = _rule()
    _seed(world, CITY, rule, [("true_positive_malicious", None)] * 10 + [(None, None)] * 90)

    (row,) = _rows_for(_quality(world), rule)
    assert row["total_alerts"] == 100 and row["labeled_alerts"] == 10
    assert row["label_coverage"] == 0.1
    assert row["observed_fp_rate"] == 0.0            # looks clean on labels alone...
    assert row["fp_min"] == 0.0
    assert row["fp_max"] == 0.9                      # ...but 90 unreviewed alerts could all be false positives
    assert row["eligible_for_tuning"] is False
    assert row["fp_target_status"] == "not_eligible"
    assert any("label coverage 10%" in reason for reason in row["eligibility_reasons"])


def test_eligibility_needs_both_coverage_and_sample(world, monkeypatch):
    monkeypatch.setenv("FP_TARGET", "0.10")
    monkeypatch.setenv("MIN_LABEL_COVERAGE", "0.80")
    monkeypatch.setenv("MIN_LABELED_SAMPLE", "30")
    rule = _rule()
    # Full coverage, but only 10 decisive labels: the sample gate still blocks tuning.
    _seed(world, CITY, rule, [("true_positive_malicious", None)] * 10)
    (row,) = _rows_for(_quality(world), rule)
    assert row["label_coverage"] == 1.0 and row["eligible_for_tuning"] is False
    assert any("need 30" in reason for reason in row["eligibility_reasons"])


def test_fully_labeled_group_is_judged_against_target(world, monkeypatch):
    monkeypatch.setenv("FP_TARGET", "0.10")
    monkeypatch.setenv("MIN_LABELED_SAMPLE", "1")
    rule = _rule()
    _seed(world, CITY, rule, [("true_positive_malicious", None)] * 9 + [("false_positive", None)])
    (row,) = _rows_for(_quality(world), rule)
    assert row["eligible_for_tuning"] is True
    assert row["observed_fp_rate"] == 0.1 and row["fp_min"] == row["fp_max"] == 0.1
    assert row["fp_target_status"] == "within_target"          # 10% is exactly on the target


def test_observed_rate_counts_benign_true_positives_as_not_false_positive(world, monkeypatch):
    monkeypatch.setenv("MIN_LABELED_SAMPLE", "1")
    rule = _rule()
    _seed(world, CITY, rule, [("true_positive_benign", None), ("false_positive", None), ("inconclusive", None)])
    (row,) = _rows_for(_quality(world), rule)
    assert row["labeled_alerts"] == 2                          # inconclusive is reviewed, not labeled
    assert row["observed_fp_rate"] == 0.5
    assert row["fp_min"] == round(1 / 3, 3) and row["fp_max"] == round(2 / 3, 3)


def test_groups_by_rule_and_log_source_with_unattributed_alerts_separate(world):
    rule = _rule()
    first = _log_source(world, CITY, "edr-a")
    second = _log_source(world, CITY, "edr-b")
    _seed(world, CITY, rule, [("false_positive", first), (None, first), (None, first),
                              ("true_positive_malicious", second), ("true_positive_malicious", second),
                              ("inconclusive", None)])

    groups = {r["log_source"]: r for r in _rows_for(_quality(world), rule)}
    assert set(groups) == {"edr-a", "edr-b", "unattributed"}
    assert groups["edr-a"]["total_alerts"] == 3 and groups["edr-a"]["verdicts"]["unlabeled"] == 2
    assert groups["edr-b"]["total_alerts"] == 2 and groups["edr-b"]["labeled_alerts"] == 2
    assert groups["unattributed"]["total_alerts"] == 1 and groups["unattributed"]["log_source_id"] is None


def test_detection_quality_is_strictly_tenant_scoped(world):
    rule = _rule()
    city_source = _log_source(world, CITY, "city-src")
    ortho_source = _log_source(world, ORTHO, "ortho-src")
    _seed(world, CITY, rule, [("false_positive", city_source)] * 2)
    _seed(world, ORTHO, rule, [("true_positive_malicious", ortho_source)] * 5)

    city = _rows_for(_quality(world, CITY), rule)
    ortho = _rows_for(_quality(world, ORTHO), rule)
    assert [r["total_alerts"] for r in city] == [2] and {r["tenant_id"] for r in city} == {CITY}
    assert [r["total_alerts"] for r in ortho] == [5] and {r["tenant_id"] for r in ortho} == {ORTHO}
    assert all(r["log_source"] == "city-src" for r in city)


def test_visibility_kpis_count_assets_unknown_hosts_and_refusals(world):
    before = Api(world, CITY, "hospital_admin").get("/api/soc-visibility").get_json()
    ensure_asset(world, CITY, f"vis-edr-{uuid.uuid4().hex[:6]}", mode="edr_managed")
    ensure_asset(world, CITY, f"vis-unm-{uuid.uuid4().hex[:6]}", mode="unmanaged")
    ensure_asset(world, CITY, f"vis-mri-{uuid.uuid4().hex[:6]}", asset_class="mri", mode="agentless_medical")
    after = Api(world, CITY, "hospital_admin").get("/api/soc-visibility").get_json()

    assert after["total_assets"] == before["total_assets"] + 3
    assert after["unmanaged_assets"] == before["unmanaged_assets"] + 1
    assert after["monitored_assets"] == after["total_assets"] - after["unmanaged_assets"]
    assert after["agentless_medical_assets"] == before["agentless_medical_assets"] + 1
    assert 0 <= after["edr_coverage"] <= 1
    assert after["unknown_or_unmanaged_assets"] == after["unmanaged_assets"] + after["unknown_hosts_seen"]


def test_cross_tenant_request_is_refused_and_counted_for_the_requesting_hospital(world):
    before = Api(world, CITY, "hospital_admin").get("/api/soc-visibility").get_json()
    refused = Api(world, CITY, "hospital_admin").get(f"/api/soc-visibility?tenant_id={ORTHO}")
    assert refused.status_code == 403
    after = Api(world, CITY, "hospital_admin").get("/api/soc-visibility").get_json()
    assert after["cross_tenant_or_unauthorized_attempts"] >= before["cross_tenant_or_unauthorized_attempts"] + 1


def test_verdict_vocabulary_is_standard_and_unlabeled_cannot_be_set(world):
    rule = _rule()
    (alert_id,) = _seed(world, CITY, rule, [(None, None)])
    l2 = Api(world, CITY, "l2")
    assert l2.post(f"/api/alerts/{alert_id}/verdict", json={"verdict": "tp"}).status_code == 400   # legacy label
    assert l2.post(f"/api/alerts/{alert_id}/verdict", json={"verdict": "fp"}).status_code == 400
    assert l2.post(f"/api/alerts/{alert_id}/verdict", json={"verdict": "unlabeled"}).status_code == 400
    assert l2.post(f"/api/alerts/{alert_id}/verdict", json={"verdict": "inconclusive"}).status_code == 200
    stored = Api(world, CITY, "hospital_admin").get(f"/api/alerts/{alert_id}").get_json()
    assert stored["verdict"] == "inconclusive"
