"""Service tiers (PR 17): which features a hospital's plan includes.

essential  - detection, triage, read-only enrichment (collect_triage_snapshot). The default.
advanced   - adds automated containment (maker-checker response approvals) and the monthly executive report.
enterprise - everything in advanced, plus medical-device containment on the hospital's own Suricata-monitored
             network when the site chooses to enable it (see FEATURE_MIN_TIER).

The tier is read from the hospital's own tenants row on every request, so a change takes effect at once. Only a
vendor admin can change it; a hospital cannot upgrade itself.
"""
import os

SERVICE_TIERS = ("essential", "advanced", "enterprise")
DEFAULT_TIER = "essential"
MIN_RETENTION_DAYS = 180          # CERT-In Directions 2022
DEFAULT_RETENTION_DAYS = 180

# The lowest tier that includes each feature.
FEATURE_MIN_TIER = {
    "automated_containment": "advanced",
    "medical_device_containment": "advanced",
    "executive_summary": "advanced",
}


def rank(tier):
    return SERVICE_TIERS.index(tier) if tier in SERVICE_TIERS else -1


def min_tier_for(feature):
    """The lowest tier with this feature. EXECUTIVE_SUMMARY_MIN_TIER can move the executive report to another tier."""
    if feature == "executive_summary":
        configured = os.environ.get("EXECUTIVE_SUMMARY_MIN_TIER", "").strip().lower()
        if configured in SERVICE_TIERS:
            return configured
    if feature not in FEATURE_MIN_TIER:
        raise KeyError(f"unknown feature {feature!r}")
    return FEATURE_MIN_TIER[feature]


def allows(tier, feature):
    """True when `tier` includes `feature`. An unknown tier includes nothing."""
    return rank(tier) >= 0 and rank(tier) >= rank(min_tier_for(feature))


def features_for(tier):
    return sorted(f for f in FEATURE_MIN_TIER if allows(tier, f))


def valid_retention(value):
    return isinstance(value, int) and not isinstance(value, bool) and value >= MIN_RETENTION_DAYS
