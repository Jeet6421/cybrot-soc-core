import os, sys, tempfile
os.environ.setdefault("SOC_DB", os.path.join(tempfile.mkdtemp(), "shuffle.db"))
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "shuffle"))
import app as soc
import verify_alert as v

SECRET = "s3cret"
BODY = b'{"event": "alert.created", "alert": {"id": 1}}'
TS = "1000"
SIG = v.expected_signature(SECRET, TS, BODY)


def test_valid_request_verifies():
    assert v.verify(SECRET, TS, BODY, SIG, now=1000) is True


def test_receiver_agrees_with_the_sender_signature():
    # The sender (app.sign) and the receiver (verify_alert) must produce the same signature.
    assert soc.sign(SECRET, TS, BODY) == SIG


def test_wrong_secret_fails():
    assert v.verify("other", TS, BODY, SIG, now=1000) is False


def test_tampered_body_fails():
    assert v.verify(SECRET, TS, BODY.replace(b"1}", b"2}"), SIG, now=1000) is False


def test_timestamp_window():
    assert v.verify(SECRET, TS, BODY, SIG, now=1000 + 300) is True    # edge: allowed
    assert v.verify(SECRET, TS, BODY, SIG, now=1000 + 301) is False   # too old
    assert v.verify(SECRET, TS, BODY, SIG, now=1000 - 301) is False   # too far in the future


def test_missing_or_malformed_headers_fail():
    assert v.verify("", TS, BODY, SIG, now=1000) is False
    assert v.verify(SECRET, "", BODY, SIG, now=1000) is False
    assert v.verify(SECRET, "not-a-number", BODY, SIG, now=1000) is False
    assert v.verify(SECRET, TS, BODY, "", now=1000) is False


def test_dedupe_handles_an_event_once_within_the_ttl():
    log = v.DedupeLog(ttl=100)
    assert log.first_time("alert-1", now=0) is True
    assert log.first_time("alert-1", now=10) is False    # retry of the same event
    assert log.first_time("alert-2", now=10) is True     # a different alert is handled
    assert log.first_time("alert-1", now=200) is True    # forgotten after the ttl
