"""Load test (test plan step 2): send a known number of events and check none are lost.

Compares the stored event count before and after the run. Run it against an instance with no other traffic,
or the count will include that traffic. Standard library only.

Usage:
    python scripts/load_test.py http://localhost:5000 --events 5000 --batch 500 --token "$SOC_API_TOKEN"

Exit code 0 when every event sent was stored, 1 otherwise.
"""
import argparse, json, os, sys, time, urllib.request
from datetime import datetime, timedelta, timezone

FMT = "%Y-%m-%dT%H:%M:%S"
TENANT = "city-hospital"


def make_events(n, now=None):
    """Benign events only (logins and normal applications), so no alerts are raised during the load."""
    base = (now or datetime.now(timezone.utc)).replace(hour=11, minute=0, second=0, microsecond=0)
    out = []
    for i in range(n):
        ts = (base + timedelta(seconds=i)).strftime(FMT)
        if i % 2 == 0:
            out.append({"ts": ts, "tenant": TENANT, "source": "load", "type": "auth_ok",
                        "user": f"dr.{i % 12 + 1}", "ip": f"10.0.0.{i % 58 + 2}", "host": "ehr-01"})
        else:
            out.append({"ts": ts, "tenant": TENANT, "source": "load", "type": "process_start",
                        "user": f"dr.{i % 12 + 1}", "host": f"ws-{i % 9 + 1}", "detail": "chrome.exe"})
    return out


def run(post, get, n=1000, batch=250, now=None):
    """Send n events in batches. Returns counts, the loss, and throughput."""
    events = make_events(n, now)
    before = get("/api/metrics")["events"]
    sent = 0
    t0 = time.perf_counter()
    for start in range(0, n, batch):
        sent += post("/api/events", events[start:start + batch])["events"]
    seconds = time.perf_counter() - t0
    stored = get("/api/metrics")["events"] - before
    return {"sent": sent, "stored": stored, "lost": sent - stored,
            "seconds": round(seconds, 2), "events_per_second": round(sent / seconds, 1) if seconds else None}


def http_client(base_url, token):
    def call(method, path, body=None):
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = "Bearer " + token
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(base_url.rstrip("/") + path, data=data, headers=headers, method=method)
        with urllib.request.urlopen(req, timeout=120) as resp:
            return json.loads(resp.read() or b"null")
    return (lambda p, b: call("POST", p, b)), (lambda p: call("GET", p))


def main(argv=None):
    ap = argparse.ArgumentParser(description="Send events and check none are lost.")
    ap.add_argument("base_url", nargs="?", default="http://localhost:5000")
    ap.add_argument("--events", type=int, default=1000)
    ap.add_argument("--batch", type=int, default=250)
    ap.add_argument("--token", default=os.environ.get("SOC_API_TOKEN", ""))
    args = ap.parse_args(argv)
    post, get = http_client(args.base_url, args.token)
    r = run(post, get, args.events, args.batch)
    print(f"sent {r['sent']}, stored {r['stored']}, lost {r['lost']}")
    print(f"time {r['seconds']} s, {r['events_per_second']} events/s")
    ok = r["lost"] == 0 and r["stored"] == args.events
    print("PASS: no events lost." if ok else "FAIL: events were lost or not stored.")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
