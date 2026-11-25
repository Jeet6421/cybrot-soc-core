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

PLAYBOOK = {
    "FAILED_LOGIN_BURST": "Check source IP reputation, lock the targeted account, force password reset if login succeeded.",
    "BULK_RECORD_ACCESS": "Call the user's supervisor to confirm a care reason; suspend the account if unexplained.",
    "OFFHOURS_ACCESS": "Verify the user is on the night roster; close as benign if yes.",
    "SUSPICIOUS_PROCESS": "Isolate the host from the network, capture the process tree, start incident response.",
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
    return None
