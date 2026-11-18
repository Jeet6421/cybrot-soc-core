"""Synthetic clinic log generator with planted attacks (ground truth in attack_id)."""
import random, sys, json, urllib.request
from datetime import datetime, timedelta, timezone

FMT = "%Y-%m-%dT%H:%M:%S"
TENANTS = ["city-hospital", "ortho-clinic"]


def generate(normal=300, seed=7):
    r = random.Random(seed)
    now = datetime.now(timezone.utc).replace(tzinfo=None, microsecond=0)
    ev = []

    def add(ts, tenant, source, type_, user="", host="", ip="", patient="", detail="", attack=None):
        ev.append(dict(ts=ts.strftime(FMT), tenant=tenant, source=source, type=type_, user=user,
                       host=host, ip=ip, patient=patient, detail=detail, attack_id=attack))

    # normal day-time traffic
    base = now.replace(hour=11, minute=0, second=0) if 7 <= now.hour < 20 else now.replace(hour=11, minute=0, second=0)
    for i in range(normal):
        tn = r.choice(TENANTS)
        ts = base + timedelta(seconds=r.randint(0, 5400))
        u = f"dr.{r.randint(1, 12)}"
        k = r.random()
        if k < 0.7:
            add(ts, tn, "ehr", "ehr_access", user=u, patient=f"P{r.randint(1, 400):04d}", host="ehr-01")
        elif k < 0.85:
            add(ts, tn, "auth", "auth_ok", user=u, ip=f"10.0.0.{r.randint(2, 60)}", host="ehr-01")
        elif k < 0.93:  # a doctor mistypes a password: a few lone failures, must NOT alert
            add(ts, tn, "auth", "auth_fail", user=u, ip=f"10.0.0.{r.randint(2, 60)}", host="ehr-01")
        else:
            add(ts, tn, "endpoint", "process_start", user=u, host=f"ws-{r.randint(1, 9)}",
                detail=r.choice(["chrome.exe", "outlook.exe", "dicomviewer.exe", "excel.exe"]))
    # benign night shift access (can produce false positives on purpose)
    night = base.replace(hour=2, minute=10)
    for j in range(3):
        add(night + timedelta(minutes=j * 7), TENANTS[0], "ehr", "ehr_access", user="nurse.night1", patient=f"P{r.randint(1, 400):04d}", host="ehr-01")
    # planted attacks
    t0 = base + timedelta(minutes=20)
    for j in range(8):
        add(t0 + timedelta(seconds=j * 20), TENANTS[0], "auth", "auth_fail", user="admin", ip="203.0.113.50", host="vpn-01", attack="A1-bruteforce")
    add(t0 + timedelta(minutes=4), TENANTS[0], "auth", "auth_ok", user="admin", ip="203.0.113.50", host="vpn-01", attack="A1-bruteforce")
    t1 = base + timedelta(minutes=45)
    for j in range(20):
        add(t1 + timedelta(seconds=j * 9), TENANTS[1], "ehr", "ehr_access", user="dr.99", patient=f"P{300 + j:04d}", host="ehr-01", attack="A2-bulk-access")
    add(base + timedelta(minutes=60), TENANTS[1], "endpoint", "process_start", user="dr.4", host="ws-3",
        detail="powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA", attack="A3-suspicious-process")
    ev.sort(key=lambda e: e["ts"])
    return ev


if __name__ == "__main__":
    url = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:5000"
    data = json.dumps(generate()).encode()
    req = urllib.request.Request(url + "/api/events", data, {"Content-Type": "application/json"})
    print(urllib.request.urlopen(req).read().decode())
