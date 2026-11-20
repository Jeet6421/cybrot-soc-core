"""Scripted attack simulations (test plan step 3).

Posts three known attack patterns and checks that each one raises the expected alert, then checks that a
single failed login stays quiet. Lab use only: events are tagged with attack_id so the detection gate can
measure them. Do not run against an instance that holds real data.

Usage:
    python scripts/attack_sim.py http://localhost:5000 --token "$SOC_API_TOKEN"

Exit code 0 when every simulation passes, 1 otherwise. Standard library only.
"""
import argparse, json, os, secrets, sys, urllib.request
from datetime import datetime, timedelta, timezone

FMT = "%Y-%m-%dT%H:%M:%S"
TENANT = "city-hospital"
NEGATIVE_IP = "198.51.100.9"  # one failed login from here must NOT alert


def _base(now=None):
    # Daytime timestamps, so the off-hours rule stays quiet.
    return (now or datetime.now(timezone.utc)).replace(hour=11, minute=0, second=0, microsecond=0)


def scenarios(now=None, tag=None):
    """Return (name, expected_rule, attack_id, events) for each simulation.

    Each run gets its own tag in the IP, user and host. The app suppresses repeats of the same rule and key
    within 10 minutes, so a second run with the same keys would raise no new alerts.
    """
    tag = tag or secrets.token_hex(2)
    base = _base(now)
    ip = f"203.0.113.{int(tag, 16) % 250 + 1}"  # TEST-NET-3 range, unique per run

    def ev(t, **kw):
        return {"ts": t.strftime(FMT), "tenant": TENANT, "source": "sim", **kw}

    brute = [ev(base + timedelta(seconds=20 * i), type="auth_fail", user="admin", ip=ip,
                host="vpn-01", attack_id="SIM-bruteforce") for i in range(6)]
    bulk = [ev(base + timedelta(seconds=9 * i), type="ehr_access", user=f"dr.sim-{tag}", patient=f"S{i:04d}",
               host="ehr-01", attack_id="SIM-bulk-access") for i in range(16)]
    proc = [ev(base + timedelta(minutes=5), type="process_start", user=f"dr.sim-{tag}", host=f"ws-sim-{tag}",
               detail="powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA", attack_id="SIM-suspicious-process")]
    return [
        ("Failed-login burst", "FAILED_LOGIN_BURST", "SIM-bruteforce", brute),
        ("Bulk record access", "BULK_RECORD_ACCESS", "SIM-bulk-access", bulk),
        ("Suspicious process", "SUSPICIOUS_PROCESS", "SIM-suspicious-process", proc),
    ]


def _max_alert_id(get):
    return max((a["id"] for a in get("/api/alerts")), default=0)


def run(post, get, now=None):
    """post(path, body) and get(path) perform the calls. Returns one result per simulation.

    Only alerts created after this run started count. The alert list returns the newest 200 alerts,
    so an alert from an earlier run can drop out of the list and must not be relied on.
    """
    before = _max_alert_id(get)
    tag = secrets.token_hex(2)
    results = []
    for name, rule, aid, events in scenarios(now, tag):
        post("/api/events", events)
        alerts = get(f"/api/alerts?tenant={TENANT}")
        hit = any(a["id"] > before and a["rule"] == rule and a.get("attack_id") == aid for a in alerts)
        results.append({"scenario": name, "expected": rule, "passed": hit})

    # Negative control: a single failed login must not raise an alert.
    post("/api/events", [{"ts": _base(now).strftime(FMT), "tenant": TENANT, "source": "sim",
                          "type": "auth_fail", "user": "admin", "ip": NEGATIVE_IP, "host": "vpn-01"}])
    alerts = get(f"/api/alerts?tenant={TENANT}")
    noisy = any(a["id"] > before and NEGATIVE_IP in (a.get("summary") or "") for a in alerts)
    results.append({"scenario": "Single failed login stays quiet", "expected": None, "passed": not noisy})
    return results


def http_client(base_url, token):
    def call(method, path, body=None):
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = "Bearer " + token
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(base_url.rstrip("/") + path, data=data, headers=headers, method=method)
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read() or b"null")
    return (lambda p, b: call("POST", p, b)), (lambda p: call("GET", p))


def main(argv=None):
    ap = argparse.ArgumentParser(description="Run scripted attack simulations against SOC Core.")
    ap.add_argument("base_url", nargs="?", default="http://localhost:5000")
    ap.add_argument("--token", default=os.environ.get("SOC_API_TOKEN", ""))
    args = ap.parse_args(argv)
    post, get = http_client(args.base_url, args.token)
    results = run(post, get)
    for r in results:
        print(f"{'PASS' if r['passed'] else 'FAIL'}  {r['scenario']}")
    ok = all(r["passed"] for r in results)
    print("All simulations passed." if ok else "Some simulations failed.")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
