"""Hospital-specific telemetry (PR 16): the log source catalog, the threat taxonomy with severity SLAs, normalization
of Suricata IDS alerts from passive medical-device monitoring, and the clock-skew setting.

No Flask and no database here, so each piece can be tested on its own. app.py and routes/telemetry.py call these."""
import ipaddress
import os
import re
from datetime import datetime, timedelta, timezone

LOG_SOURCE_KINDS = ("wazuh", "suricata_ids", "ehr_his_audit", "ad_iam", "firewall_syslog", "edr", "custom")

THREAT_CATEGORIES = ("ransomware", "phishing", "credential_abuse_impossible_travel", "patient_record_snooping",
                     "medical_device_unexpected_egress", "unknown_network_asset", "tampering", "other")

# Minutes to act on an alert, by severity. A hospital's SOC is measured against these.
SLA_MINUTES = {"critical": 15, "high": 240, "medium": 1440, "low": 10080}

# The rules whose meaning is fixed. Wazuh and Suricata alerts have no fixed mapping, so their text decides.
RULE_CATEGORY = {
    "FAILED_LOGIN_BURST": "credential_abuse_impossible_travel",
    "BULK_RECORD_ACCESS": "patient_record_snooping",
    "OFFHOURS_ACCESS": "patient_record_snooping",
    "HC-END-001": "ransomware",
    "HC-END-004": "tampering",
    "HC-OPS-002": "tampering",
    "HC-AUD-001": "tampering",
    "HC-MED-004": "medical_device_unexpected_egress",
}
KEYWORD_CATEGORY = (("ransom", "ransomware"), ("phish", "phishing"), ("tamper", "tampering"))

# Suricata's alert priority (1 is the most severe) to this app's severity.
SURICATA_PRIORITY = {1: "high", 2: "medium", 3: "low"}
_OFFSET = re.compile(r"([+-]\d{2})(\d{2})$")


def categorize(rule, summary="", detail=""):
    """The threat category for an alert: the rule's own mapping first, then keywords in its text, else 'other'."""
    if rule in RULE_CATEGORY:
        return RULE_CATEGORY[rule]
    text = f"{summary} {detail}".lower()
    for word, category in KEYWORD_CATEGORY:
        if word in text:
            return category
    return "other"


def _utc(value):
    """A UTC-aware datetime from either a 'YYYY-MM-DDTHH:MM:SS' string (alerts.created) or a datetime (timestamptz)."""
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)


def sla_status(severity, created, status, verdict_at, now):
    """(target minutes, breached) for one alert. Times are UTC 'YYYY-MM-DDTHH:MM:SS' strings or None.
    An open alert is breached once now passes its deadline. A closed alert is breached when its verdict came after
    the deadline; a closed alert with no verdict time is not judged (None)."""
    target = SLA_MINUTES.get(severity)
    if target is None or not created:
        return None, None
    deadline = _utc(created) + timedelta(minutes=target)
    if status == "closed":
        if not verdict_at:
            return target, None
        return target, _utc(verdict_at) > deadline
    return target, now > deadline


def max_ntp_skew_seconds():
    """MAX_NTP_SKEW_SECONDS: how far a source's event times may drift from this server's clock. Default 5 (CERT-In
    expects clocks synchronised to a trusted NTP source)."""
    try:
        return float(os.environ.get("MAX_NTP_SKEW_SECONDS") or 5)
    except ValueError:
        return 5.0


def medical_networks(raw):
    """MEDICAL_NET_CIDRS: comma-separated CIDRs of the medical device networks monitored passively, e.g. 10.20.0.0/16."""
    nets = []
    for part in (raw or "").split(","):
        part = part.strip()
        if part:
            nets.append(ipaddress.ip_network(part, strict=False))
    return nets


def suricata_time(text):
    """Suricata timestamps look like 2026-11-28T09:20:00.123456+0000. Return the form with a colon in the offset."""
    if not isinstance(text, str) or not text.strip():
        raise ValueError("timestamp is missing")
    return _OFFSET.sub(r"\1:\2", text.strip())


def normalize_suricata(record, medical_nets):
    """One Suricata EVE record to the normalized event the ingest pipeline stores. Returns None for records that are
    not alerts (flow, stats and so on), so they are counted and ignored.

    Passive monitoring: the sensor only observes the medical VLAN, so the signal is what leaves it. A medical device
    sending to a public address is `medical_device_unexpected_egress`."""
    if not isinstance(record, dict) or record.get("event_type") != "alert":
        return None
    alert = record.get("alert") if isinstance(record.get("alert"), dict) else {}
    try:
        src = ipaddress.ip_address(record.get("src_ip"))
        dst = ipaddress.ip_address(record.get("dest_ip"))
    except ValueError:
        raise ValueError("src_ip and dest_ip must be IP addresses")
    sid = alert.get("signature_id")
    signature = str(alert.get("signature") or "unnamed signature")[:200]
    priority = alert.get("severity")
    severity = SURICATA_PRIORITY.get(priority, "medium")
    egress = any(src in net for net in medical_nets) and dst.is_global
    if egress:
        category = "medical_device_unexpected_egress"
        severity = "critical" if priority == 1 else "high"
    else:
        category = categorize("", signature, str(alert.get("category") or ""))
    event = {
        "ts": suricata_time(record.get("timestamp")),
        "source": "suricata",
        "type": "suricata_alert",
        "host": str(src),
        "ip": str(dst),
        "detail": f"{signature} | {record.get('proto', '')} port {record.get('dest_port', '')} | sid {sid}"[:500],
        "attack_id": None,
        "threat_category": category,
        "severity": severity,
        "signature": signature,
        "sid": sid,
    }
    if record.get("flow_id") is not None and sid is not None:
        event["source_event_id"] = f"{record['flow_id']}:{sid}"
    return event
