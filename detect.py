"""Detection rules. Each rule looks at the new event + recent history in the database
and returns (rule, severity, summary, dedupe_key) or None."""
import re
from datetime import datetime, timedelta

FMT = "%Y-%m-%dT%H:%M:%S"
SUSPICIOUS = ["mimikatz", "certutil -urlcache", "nc -e", "vssadmin delete shadows"]
# PowerShell accepts -e, -ec, -enc and -EncodedCommand (case-insensitive). Require a base64-looking
# payload after the flag so plain words like "-encoding" or "-e C:\path" don't match.
ENCODED_COMMAND = re.compile(r"(?i)\s-(e|ec|enc|encodedcommand)\s+[A-Za-z0-9+/]{16,}={0,2}")
OFFHOURS = (range(0, 6), range(22, 24))  # 22:00-05:59

# Report-priority P1 detections. These defaults are pilot thresholds/signatures, not
# production-ready hospital policy; see docs/DETECTION_RULES.md before enabling feeds.
HC_END_001_FILE_THRESHOLD = 50
HC_END_001_WINDOW_MINUTES = 5
HC_OPS_002_FAILURE_THRESHOLD = 3
HC_OPS_002_WINDOW_MINUTES = 24 * 60
FILE_ACTIVITY_TYPES = ("file_rename", "file_modify", "file_delete")
ENDPOINT_TAMPER_TYPES = {
    "security_agent_stopped", "security_agent_disabled", "security_agent_config_changed",
    "edr_configuration_changed",
}
AUDIT_TAMPER_TYPES = {
    "audit_log_cleared", "audit_service_stopped", "log_forwarding_disabled", "audit_config_changed",
}
SENSITIVE_CLASSIFICATIONS = {"phi", "patient_data", "sensitive"}
DETECTION_RULE_VERSIONS = {
    "HC-END-001": "0.1.0",
    "HC-END-004": "0.1.0",
    "HC-DLP-002": "0.1.0",
    "HC-OPS-002": "0.1.0",
    "HC-MED-004": "0.1.0",
    "HC-AUD-001": "0.1.0",
}


def rule_version(rule):
    return DETECTION_RULE_VERSIONS.get(rule, "prototype")

PLAYBOOK = {
    "FAILED_LOGIN_BURST": "Check source IP reputation, lock the targeted account, force password reset if login succeeded.",
    "BULK_RECORD_ACCESS": "Call the user's supervisor to confirm a care reason; suspend the account if unexplained.",
    "OFFHOURS_ACCESS": "Verify the user is on the night roster; close as benign if yes.",
    "SUSPICIOUS_PROCESS": "Isolate the host from the network, capture the process tree, start incident response.",
    "HC-END-001": "Check file activity and process ancestry; coordinate patient-safe containment with the hospital incident owner.",
    "HC-END-004": "Verify approved maintenance, restore endpoint protection or logging, and escalate suspected tampering.",
    "HC-DLP-002": "Validate the classification and destination; preserve transfer evidence and follow the hospital privacy incident process.",
    "HC-OPS-002": "Confirm backup job and change context; protect remaining recovery points and escalate destructive changes.",
    "HC-MED-004": "Validate the network policy and affected device with hospital IT and biomedical engineering; do not actively probe the device.",
    "HC-AUD-001": "Preserve available evidence, verify collector health, and restore audit forwarding through the approved change process.",
}

# Wazuh rule-specific steps, keyed by Wazuh rule id (the number after "WAZUH:").
WAZUH_PLAYBOOK = {
    "92213": ("Check the process that wrote the file (parent process and hash). If it is a PowerShell "
              "execution-policy test file (__PSScriptPolicyTest_*.ps1), close as benign. Otherwise isolate "
              "the host and start incident response."),
}

# Fallback for other Wazuh rules, by level (highest floor first).
WAZUH_LEVEL_STEP = [
    (12, "Isolate the host from the network, capture the process tree, start incident response."),
    (10, "Open the alert in Wazuh, confirm the activity with the host owner, escalate if it is unexplained."),
    (0, "Review the alert details and decide: escalate, fix, or close as benign."),
]


def wazuh_step(rid, lvl):
    if rid in WAZUH_PLAYBOOK:
        return WAZUH_PLAYBOOK[rid]
    for floor, text in WAZUH_LEVEL_STEP:
        if lvl >= floor:
            return text


def wazuh_detail(a):
    """The key facts from a Wazuh alert (file, process, command) so the analyst can triage without leaving the queue."""
    ed = ((a.get("data") or {}).get("win") or {}).get("eventdata") or {}
    parts = [ed.get("targetFilename"), ed.get("commandLine") or ed.get("image")]
    detail = " | ".join(p for p in parts if p)
    return (detail or a.get("full_log") or "")[:500]


def _ago(ts, minutes):
    return (datetime.strptime(ts, FMT) - timedelta(minutes=minutes)).strftime(FMT)


def evaluate(db, ev):
    t, ts, tenant = ev["type"], ev["ts"], ev["tenant"]
    if t == "auth_fail":
        n = db.execute("SELECT COUNT(*) FROM events WHERE tenant=%s AND ip=%s AND type='auth_fail' AND ts>=%s AND ts<=%s",
                       (tenant, ev["ip"], _ago(ts, 5), ts)).fetchone()[0]
        if n >= 5:
            return ("FAILED_LOGIN_BURST", "high", f"{n} failed logins from {ev['ip']} in 5 min", ev["ip"])
    elif t == "suricata_alert" and ev.get("sid") is not None:
        # PR 16: a Suricata signature hit. The category and severity were set by hospital.normalize_suricata.
        summary = f"{ev['signature']} from {ev['host']} to {ev['ip']}"
        return (f"SURICATA:{ev['sid']}", ev["severity"], summary, f"{ev['host']}|{ev['ip']}|{ev['sid']}",
                ev["threat_category"])
    elif t == "ehr_access":
        n = db.execute('SELECT COUNT(DISTINCT patient) FROM events WHERE tenant=%s AND "user"=%s AND type=\'ehr_access\' '
                       "AND ts>=%s AND ts<=%s", (tenant, ev["user"], _ago(ts, 10), ts)).fetchone()[0]
        if n >= 15:
            return ("BULK_RECORD_ACCESS", "high", f"{ev['user']} opened {n} patient records in 10 min", ev["user"])
        hour = int(ts[11:13])
        if any(hour in r for r in OFFHOURS):
            return ("OFFHOURS_ACCESS", "low", f"{ev['user']} accessed a record at {ts[11:16]}", ev["user"])
    elif t == "process_start":
        raw = ev.get("detail") or ""
        cmd = raw.lower()
        if any(s in cmd for s in SUSPICIOUS) or ENCODED_COMMAND.search(raw):
            return ("SUSPICIOUS_PROCESS", "critical", f"Suspicious process on {ev['host']}: {ev['detail'][:60]}", ev["host"])

    tenant = ev["tenant"]
    host = ev.get("host") or ev.get("ip") or ev.get("user") or "unknown"
    ts = ev["ts"]

    # Rapid file changes are a ransomware signal only when the source reports distinct paths.
    if t in FILE_ACTIVITY_TYPES and ev.get("host") and ev.get("detail"):
        n = db.execute(
            "SELECT COUNT(DISTINCT detail) FROM events WHERE tenant=%s AND host=%s "
            "AND type IN ('file_rename','file_modify','file_delete') AND ts>=%s AND ts<=%s",
            (tenant, ev["host"], _ago(ts, HC_END_001_WINDOW_MINUTES), ts),
        ).fetchone()[0]
        if n >= HC_END_001_FILE_THRESHOLD:
            return ("HC-END-001", "critical",
                    f"{n} distinct file changes on {ev['host']} in {HC_END_001_WINDOW_MINUTES} min", ev["host"])

    if t in ENDPOINT_TAMPER_TYPES and ev.get("approved_change") is not True:
        return ("HC-END-004", "high", f"Endpoint security control changed on {host}: {t}", host)

    classification = ev.get("data_classification")
    classification = classification.lower() if isinstance(classification, str) else ""
    if (t == "data_transfer" and classification in SENSITIVE_CLASSIFICATIONS
            and ev.get("destination_approved") is False):
        destination = ev.get("destination") or "unknown destination"
        return ("HC-DLP-002", "high", f"Sensitive data transfer to unapproved destination {destination}", host)

    if t in {"backup_repository_deleted", "backup_retention_changed"} and ev.get("approved_change") is not True:
        return ("HC-OPS-002", "high", f"Unapproved backup change on {host}: {t}", host)
    if t == "backup_job_failed" and ev.get("host"):
        n = db.execute(
            "SELECT COUNT(*) FROM events WHERE tenant=%s AND host=%s AND type='backup_job_failed' AND ts>=%s AND ts<=%s",
            (tenant, ev["host"], _ago(ts, HC_OPS_002_WINDOW_MINUTES), ts),
        ).fetchone()[0]
        if n >= HC_OPS_002_FAILURE_THRESHOLD:
            return ("HC-OPS-002", "high", f"{n} backup failures on {ev['host']} in 24 hours", ev["host"])

    if t in {"network_flow", "network_boundary_violation"} and ev.get("boundary_violation") is True:
        src, dst = ev.get("src_zone"), ev.get("dst_zone")
        if src and dst:
            return ("HC-MED-004", "high", f"Prohibited clinical network flow from {src} to {dst}", f"{src}|{dst}")

    if t in AUDIT_TAMPER_TYPES and ev.get("approved_change") is not True:
        return ("HC-AUD-001", "high", f"Security audit/logging control changed on {host}: {t}", host)
    return None
