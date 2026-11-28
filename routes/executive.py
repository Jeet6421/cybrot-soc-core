"""Service tiers and the monthly traffic-light executive report (PR 17).

GET /api/executive-summary   RED / AMBER / GREEN for six things a hospital board asks about, in plain language.
GET /api/service-tier        the hospital's own tier, retention and the features it includes.
PUT /api/tenants/<tid>/service   vendor admin only: set a hospital's service tier and retention days.

The report holds counts, percentages and times only. It never carries event text, host names, IP addresses, user
names, rule names, log-source names or any other field that could hold patient data or a secret.
"""
from datetime import datetime, timedelta, timezone

from flask import Blueprint, jsonify

import hospital
import tiers

bp = Blueprint("executive", __name__)

REPORT_DAYS = 30
RED, AMBER, GREEN = "RED", "AMBER", "GREEN"
_RANK = {GREEN: 0, AMBER: 1, RED: 2}

# Thresholds. They are shown to the reader in `methodology`, so a board member can see why a light is the colour it is.
COVERAGE_GREEN, COVERAGE_AMBER = 0.90, 0.75          # share of agent-capable endpoints that have EDR
UNMANAGED_AMBER_SHARE = 0.10                         # unmanaged + unknown as a share of everything the SOC knows of
SLA_GREEN, SLA_AMBER = 0.95, 0.80                    # share of critical/high alerts handled inside their SLA
MTTD_GREEN_MIN, MTTD_AMBER_MIN = 15.0, 60.0          # minutes from the event to the alert
MTTR_GREEN_H, MTTR_AMBER_H = 4.0, 24.0               # hours from the alert to its verdict
DENIED_GREEN, DENIED_RED = 0, 10                     # refused requests in the period; any is AMBER, this many is RED
SLA_SEVERITIES = ("critical", "high")
TS_FORMAT = "%Y-%m-%dT%H:%M:%S"


def _soc():
    # app.py registers this blueprint after its helpers are defined, so importing it here at request time is safe.
    import app
    return app


def _pct(value):
    return None if value is None else round(value * 100, 1)


def worst(*statuses):
    return max(statuses, key=lambda status: _RANK[status])


def _section(key, title, status, headline, explanation, figures):
    return {"id": key, "title": title, "status": status, "headline": headline,
            "explanation": explanation, "figures": figures}


# ---- Pure assessments: numbers in, light and plain-language words out. No database, so they are easy to test. -------

def assess_edr_coverage(total, edr, unmanaged):
    """Of the assets that can run an agent (EDR-managed or unmanaged), how many have EDR. Medical equipment and network
    devices are watched without an agent, so they neither help nor hurt this number."""
    figures = {"total_assets": total, "edr_managed_assets": edr, "unmanaged_assets": unmanaged,
               "edr_coverage_percent": None}
    if total == 0:
        return _section("asset_edr_coverage", "Asset and EDR coverage", RED, "No assets are recorded",
                        "The SOC has no inventory of this hospital's devices, so it cannot say what it is protecting. "
                        "Add the hospital's assets first.", figures)
    eligible = edr + unmanaged
    if eligible == 0:
        return _section("asset_edr_coverage", "Asset and EDR coverage", GREEN, "Every device is watched",
                        "All recorded devices are medical equipment or network devices, which are watched without "
                        "an agent. No computers are missing protection.", figures)
    coverage = edr / eligible
    figures["edr_coverage_percent"] = _pct(coverage)
    status = GREEN if coverage >= COVERAGE_GREEN else AMBER if coverage >= COVERAGE_AMBER else RED
    words = {GREEN: "Computers are well protected", AMBER: "Some computers are not protected",
             RED: "Many computers are not protected"}[status]
    return _section("asset_edr_coverage", "Asset and EDR coverage", status, words,
                    f"{edr} of {eligible} computers that can run security software are covered "
                    f"({_pct(coverage)}%). Green is {COVERAGE_GREEN:.0%} or more, amber {COVERAGE_AMBER:.0%} or more.",
                    figures)


def assess_unmanaged(total, unmanaged, unknown):
    """Devices the SOC knows are unwatched, plus hosts it saw in logs that are not in the inventory at all."""
    count = unmanaged + unknown
    figures = {"unmanaged_assets": unmanaged, "unknown_hosts_seen": unknown, "unmanaged_or_unknown": count}
    if count == 0:
        return _section("unmanaged_unknown_assets", "Unmanaged and unknown devices", GREEN, "No blind spots found",
                        "Every device the SOC has seen is in the inventory and is being watched.", figures)
    share = count / (total + unknown)
    figures["share_percent"] = _pct(share)
    status = AMBER if share <= UNMANAGED_AMBER_SHARE else RED
    return _section("unmanaged_unknown_assets", "Unmanaged and unknown devices", status,
                    f"{count} device{'s' if count != 1 else ''} the SOC cannot fully see",
                    f"{unmanaged} recorded device{'s are' if unmanaged != 1 else ' is'} not monitored and {unknown} "
                    f"host{'s' if unknown != 1 else ''} appeared in the logs without being in the inventory. "
                    f"Amber is up to {UNMANAGED_AMBER_SHARE:.0%} of all devices, red is more.", figures)


def assess_sla(judged_breaches, unjudged):
    """judged_breaches: one bool per critical/high alert that can be judged (True means the SLA was missed)."""
    judged = len(judged_breaches)
    missed = sum(1 for breached in judged_breaches if breached)
    figures = {"critical_high_alerts": judged + unjudged, "judged": judged, "met_sla": judged - missed,
               "missed_sla": missed, "compliance_percent": None}
    if judged == 0 and unjudged == 0:
        return _section("sla_compliance", "Critical and high alert response times", GREEN,
                        "No critical or high alerts this month",
                        "No serious alerts were raised in the period, so there was nothing to respond late to.",
                        figures)
    if judged == 0:
        return _section("sla_compliance", "Critical and high alert response times", AMBER,
                        "Response times cannot be judged yet",
                        f"{unjudged} serious alert{'s' if unjudged != 1 else ''} closed without a recorded decision "
                        "time, so the SOC cannot show whether they were answered in time.", figures)
    compliance = (judged - missed) / judged
    figures["compliance_percent"] = _pct(compliance)
    status = GREEN if compliance >= SLA_GREEN else AMBER if compliance >= SLA_AMBER else RED
    words = {GREEN: "Serious alerts are answered in time", AMBER: "Some serious alerts were answered late",
             RED: "Serious alerts are often answered late"}[status]
    return _section("sla_compliance", "Critical and high alert response times", status, words,
                    f"{judged - missed} of {judged} critical and high alerts were handled inside their target time "
                    f"({_pct(compliance)}%). Green is {SLA_GREEN:.0%} or more, amber {SLA_AMBER:.0%} or more.",
                    figures)


def _mean(values):
    return sum(values) / len(values) if values else None


def assess_response_times(mttd_minutes, mttr_hours):
    """mean time to detect (minutes) and mean time to respond (hours), each a list of samples."""
    mttd, mttr = _mean(mttd_minutes), _mean(mttr_hours)
    figures = {"mttd_minutes": None if mttd is None else round(mttd, 1), "mttd_samples": len(mttd_minutes),
               "mttr_hours": None if mttr is None else round(mttr, 1), "mttr_samples": len(mttr_hours)}
    if mttd is None and mttr is None:
        return _section("detection_response_time", "Time to detect and time to respond", AMBER,
                        "Not enough data yet",
                        "No alerts in the period have both the times needed to measure how fast the SOC detects "
                        "and responds.", figures)
    mttd_status = AMBER if mttd is None else GREEN if mttd <= MTTD_GREEN_MIN else AMBER if mttd <= MTTD_AMBER_MIN else RED
    mttr_status = AMBER if mttr is None else GREEN if mttr <= MTTR_GREEN_H else AMBER if mttr <= MTTR_AMBER_H else RED
    status = worst(mttd_status, mttr_status)
    parts = []
    parts.append("Detection time could not be measured." if mttd is None else
                 f"On average an alert is raised {mttd:.0f} minute{'s' if round(mttd) != 1 else ''} after the event "
                 f"(green {MTTD_GREEN_MIN:.0f} or less, amber {MTTD_AMBER_MIN:.0f} or less).")
    parts.append("Response time could not be measured." if mttr is None else
                 f"On average an alert is decided {mttr:.1f} hour{'s' if round(mttr, 1) != 1 else ''} after it is "
                 f"raised (green {MTTR_GREEN_H:.0f} or less, amber {MTTR_AMBER_H:.0f} or less).")
    words = {GREEN: "The SOC detects and responds quickly", AMBER: "Detection or response is slower than it should be",
             RED: "Detection or response is too slow"}[status]
    return _section("detection_response_time", "Time to detect and time to respond", status, words,
                    " ".join(parts), figures)


def assess_denied(count):
    figures = {"refused_requests": count}
    if count <= DENIED_GREEN:
        return _section("unauthorized_attempts", "Unauthorized and cross-hospital attempts", GREEN,
                        "No refused access attempts",
                        "Nobody tried to reach data they were not allowed to see.", figures)
    status = RED if count >= DENIED_RED else AMBER
    return _section("unauthorized_attempts", "Unauthorized and cross-hospital attempts", status,
                    f"{count} access attempt{'s were' if count != 1 else ' was'} refused",
                    f"The platform refused {count} request{'s' if count != 1 else ''} for data or actions the caller "
                    f"was not allowed. Any is amber; {DENIED_RED} or more is red. Review them with your security "
                    "contact.", figures)


def assess_fp_review(target, groups):
    """groups: the status string of each rule-and-log-source group (fp_target_status). No rule names leave here."""
    figures = {"fp_target_percent": _pct(target), "groups": len(groups),
               "within_target": sum(1 for s in groups if s == "within_target"),
               "above_target": sum(1 for s in groups if s == "above_target"),
               "needs_more_review": sum(1 for s in groups if s not in ("within_target", "above_target"))}
    title = "False-alarm review readiness"
    if target is None:
        return _section("fp_review_readiness", title, AMBER, "No false-alarm target agreed",
                        "The team has not yet agreed how many false alarms are acceptable (FP_TARGET), so detection "
                        "quality cannot be judged.", figures)
    if not groups:
        return _section("fp_review_readiness", title, AMBER, "No alerts to review yet",
                        "There are no alerts yet, so the false-alarm rate cannot be judged.", figures)
    if figures["above_target"]:
        return _section("fp_review_readiness", title, RED, "Too many false alarms",
                        f"{figures['above_target']} of {len(groups)} groups of alerts raise more false alarms than "
                        f"the agreed {_pct(target)}%. They need tuning.", figures)
    if figures["within_target"] == len(groups):
        return _section("fp_review_readiness", title, GREEN, "False alarms are within the target",
                        f"All {len(groups)} groups of alerts are within the agreed {_pct(target)}%, even in the "
                        "worst case for alerts not yet reviewed.", figures)
    return _section("fp_review_readiness", title, AMBER, "More alert review is needed",
                    f"{figures['needs_more_review']} of {len(groups)} groups of alerts have too few reviewed alerts "
                    "to be judged against the target. Analysts should label more of them.", figures)


def overall(sections):
    status = worst(*(s["status"] for s in sections))
    red = sum(1 for s in sections if s["status"] == RED)
    amber = sum(1 for s in sections if s["status"] == AMBER)
    if status == GREEN:
        text = "All six areas are healthy."
    else:
        text = f"{red} area{'s' if red != 1 else ''} red and {amber} amber out of {len(sections)}."
    return status, text


# ---- Data gathering (one hospital; row-level security applies as well) ------------------------------------------------

def _alert_times(soc, tenant, since, now):
    """SLA outcomes and detect/respond times for alerts created in the period."""
    rows = soc.db().execute(
        "SELECT severity, created, event_ts, status, verdict_at FROM alerts "
        "WHERE tenant = %s AND created >= %s", (tenant, since.strftime(TS_FORMAT))).fetchall()
    judged, unjudged, mttd, mttr = [], 0, [], []
    for r in rows:
        try:
            created = hospital._utc(r["created"])
        except (TypeError, ValueError):
            continue
        if r["event_ts"]:
            try:
                mttd.append(max(0.0, (created - hospital._utc(r["event_ts"])).total_seconds()) / 60)
            except (TypeError, ValueError):
                pass
        if r["status"] == "closed" and r["verdict_at"] is not None:
            mttr.append(max(0.0, (hospital._utc(r["verdict_at"]) - created).total_seconds()) / 3600)
        if r["severity"] in SLA_SEVERITIES:
            _target, breached = hospital.sla_status(r["severity"], r["created"], r["status"], r["verdict_at"], now)
            if breached is None:
                unjudged += 1
            else:
                judged.append(bool(breached))
    return judged, unjudged, mttd, mttr


def build_report(soc, tenant, now=None):
    now = now or datetime.now(timezone.utc)
    since = now - timedelta(days=REPORT_DAYS)
    visibility = soc._soc_visibility(tenant)
    judged, unjudged, mttd, mttr = _alert_times(soc, tenant, since, now)
    # Read through a narrow SECURITY DEFINER function (db/schema.sql) that returns only a count for the hospital bound
    # to this request, so a viewer, whom row-level security keeps away from raw audit rows, still gets the number.
    denied = soc.db().execute("SELECT executive_refused_count(%s::text, %s::timestamptz) AS n",
                              (tenant, since)).fetchone()["n"]
    groups = [g["fp_target_status"] for g in soc._detection_quality(tenant)]
    sections = [
        assess_edr_coverage(visibility["total_assets"], visibility["edr_managed_assets"],
                            visibility["unmanaged_assets"]),
        assess_unmanaged(visibility["total_assets"], visibility["unmanaged_assets"], visibility["unknown_hosts_seen"]),
        assess_sla(judged, unjudged),
        assess_response_times(mttd, mttr),
        assess_denied(denied),
        assess_fp_review(soc._fp_target(), groups),
    ]
    status, text = overall(sections)
    return {
        "tenant_id": tenant,
        "period": {"days": REPORT_DAYS, "from": since.strftime(TS_FORMAT), "to": now.strftime(TS_FORMAT)},
        "overall": {"status": status, "summary": text},
        "sections": sections,
        "methodology": {
            "lights": "GREEN is healthy, AMBER needs attention, RED needs action now. The overall light is the "
                      "worst of the six.",
            "scope": f"the last {REPORT_DAYS} days for this hospital only; coverage figures are as of now",
            "privacy": "counts, percentages and times only: no patient data, host names, addresses, user names or "
                       "alert text",
            "thresholds": {
                "edr_coverage": {"green_at_least": COVERAGE_GREEN, "amber_at_least": COVERAGE_AMBER},
                "unmanaged_share": {"amber_up_to": UNMANAGED_AMBER_SHARE},
                "sla_compliance": {"green_at_least": SLA_GREEN, "amber_at_least": SLA_AMBER},
                "mttd_minutes": {"green_up_to": MTTD_GREEN_MIN, "amber_up_to": MTTD_AMBER_MIN},
                "mttr_hours": {"green_up_to": MTTR_GREEN_H, "amber_up_to": MTTR_AMBER_H},
                "refused_requests": {"red_at_least": DENIED_RED},
            },
        },
    }


# ---- Routes -------------------------------------------------------------------------------------------------------------

@bp.get("/api/executive-summary")
def executive_summary():
    soc = _soc()
    tenant = soc.hospital_scope("hospital_admin", "viewer", "vendor_admin")
    soc.require_feature(tenant, "executive_summary")
    report = build_report(soc, tenant)
    report["service_tier"] = soc.tenant_service_tier(tenant)
    soc._record_current_audit(
        soc.db(), action="executive_summary.read", resource_type="report",
        resource_classification="security_event", metadata={"service_tier": report["service_tier"]})
    soc.commit()
    return jsonify(report)


@bp.get("/api/service-tier")
def service_tier():
    soc = _soc()
    tenant = soc.hospital_scope(*soc.HOSPITAL_READ)
    row = soc.db().execute("SELECT service_tier, retention_days FROM tenants WHERE id = %s", (tenant,)).fetchone()
    if not row:
        raise soc.Refuse(404, "hospital not found")
    return jsonify(tenant_id=tenant, service_tier=row["service_tier"], retention_days=row["retention_days"],
                   features=tiers.features_for(row["service_tier"]),
                   response_actions={action: {"tier": pb.tier, "included": all(
                       tiers.allows(row["service_tier"], f) for f in pb.features)}
                       for action, pb in sorted(soc.playbooks.ALLOWLIST.items())})


@bp.put("/api/tenants/<tid>/service")
def set_service(tid):
    soc = _soc()
    soc._require_vendor()
    body = soc._body(required=True)
    if set(body) - {"service_tier", "retention_days"} or not body:
        raise soc.Refuse(400, "send service_tier and/or retention_days")
    tier = body.get("service_tier")
    days = body.get("retention_days")
    if "service_tier" in body and tier not in tiers.SERVICE_TIERS:
        raise soc.Refuse(400, f"service_tier must be one of: {', '.join(tiers.SERVICE_TIERS)}")
    if "retention_days" in body and not (tiers.valid_retention(days) and days <= 3650):
        raise soc.Refuse(400, f"retention_days must be a whole number from {tiers.MIN_RETENTION_DAYS} "
                              "(CERT-In Directions 2022) to 3650")
    c = soc.db()
    if not c.execute("SELECT 1 FROM tenants WHERE id = %s", (tid,)).fetchone():
        raise soc.Refuse(404, "hospital not found")
    if not c.execute("SELECT set_tenant_service(%s::text, %s::text, %s::integer)", (tid, tier, days)).fetchone()[0]:
        raise soc.Refuse(409, "this hospital's service cannot be changed (not active, or reserved)")
    row = c.execute("SELECT service_tier, retention_days FROM tenants WHERE id = %s", (tid,)).fetchone()
    soc._record_current_audit(
        c, action="tenant.service.update", resource_type="tenant", resource_id=tid,
        resource_classification="security_event",
        metadata={"service_tier": row["service_tier"], "retention_days": row["retention_days"]})
    soc.audit("tenant.service.update", f"{tid}: tier={row['service_tier']} retention={row['retention_days']}")
    soc.commit()
    return jsonify(id=tid, service_tier=row["service_tier"], retention_days=row["retention_days"])
