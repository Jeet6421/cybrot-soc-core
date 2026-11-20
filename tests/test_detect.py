import os, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import detect

# Base64 of "Write-Host 1a1e7d6d-1356-49ed-92b0-8e12836d94e6" (UTF-16LE), the Atomic Red Team T1059.001-15 payload.
LAB_PAYLOAD = "VwByAGkAdABlAC0ASABvAHMAdAAgADEAYQAxAGUANwBkADYAZAAtADEAMwA1ADYALQA0ADkAZQBkAC0AOQAyAGIAMAAtADgAZQAxADIAMwA2AGQAOQA0ADkAZQA2AA=="


def process(detail):
    return {"type": "process_start", "ts": "2026-11-20T10:00:00", "tenant": "city-hospital",
            "host": "SOC-WIN10", "detail": detail}


def rule_for(detail):
    r = detect.evaluate(None, process(detail))
    return r[0] if r else None


def test_lab_command_line_with_short_flag_is_suspicious():
    # The exact shape seen on SOC-WIN10 (Sysmon event 1), which the old "-enc " check missed.
    assert rule_for(f"powershell.exe -NoProfile -E {LAB_PAYLOAD}") == "SUSPICIOUS_PROCESS"


def test_all_encoded_command_flag_forms_are_suspicious():
    for flag in ["-e", "-ec", "-enc", "-EncodedCommand", "-ENCODEDCOMMAND"]:
        assert rule_for(f"powershell.exe -NoProfile {flag} {LAB_PAYLOAD}") == "SUSPICIOUS_PROCESS", flag


def test_existing_enc_simulation_still_suspicious():
    assert rule_for("powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA") == "SUSPICIOUS_PROCESS"


def test_plain_text_is_not_suspicious():
    assert rule_for("notepad.exe C:\\Users\\win10\\notes.txt") is None
    assert rule_for("git log -encoding utf8") is None
    assert rule_for("tool.exe -e C:\\temp\\file.txt") is None
    assert rule_for("chrome.exe --enable-features=abc") is None


def test_short_non_base64_argument_is_not_suspicious():
    # A flag followed by a short word is not an encoded payload.
    assert rule_for("powershell.exe -e short") is None
