"""Login protection (PR 14): TOTP enrolment and sign-in, anti-replay, lockout, rate limits and the MFA gate.

Each test creates its own user, so a lockout or rate limit in one test cannot reach another."""
import time
import uuid

import psycopg

import auth
from support import CITY, PASSWORD

SECRET_KEY = "test-secret-key-for-pr14"


def new_username(world):
    username = f"mfa-{uuid.uuid4().hex[:8]}"
    r = world.client.post("/api/users", json={"username": username, "email": f"{username}@example.test",
                                              "role": "l1", "password": PASSWORD},
                          headers=world.session(CITY, "hospital_admin"))
    assert r.status_code == 201, r.get_json()
    return username


def sign_in(world, username, password=PASSWORD, code=None):
    body = {"tenant": CITY, "username": username, "password": password}
    if code is not None:
        body["totp_code"] = code
    return world.client.post("/api/login", json=body)


def enrol(world, username, monkeypatch):
    """Turns MFA on for the user through the real endpoints. Returns the secret."""
    monkeypatch.setenv("SOC_SECRET_KEY", SECRET_KEY)
    token = sign_in(world, username).get_json()["token"]
    headers = {"Authorization": f"Bearer {token}"}
    setup = world.client.post("/api/mfa/setup", headers=headers)
    assert setup.status_code == 200, setup.get_json()
    secret = setup.get_json()["secret"]
    assert setup.get_json()["otpauth_uri"].startswith("otpauth://totp/")
    ok = world.client.post("/api/mfa/verify", json={"code": auth.totp(secret)}, headers=headers)
    assert ok.status_code == 200 and ok.get_json() == {"mfa_enabled": True}
    return secret


def high_priority_audit(world, username, action):
    with psycopg.connect(world.owner_url) as owner:
        return owner.execute(
            "SELECT count(*) FROM audit_events a JOIN users u ON u.id = a.actor_id "
            "WHERE u.tenant = %s AND u.username = %s AND a.action = %s AND a.metadata->>'priority' = 'high'",
            (CITY, username, action)).fetchone()[0]


# ---- TOTP enrolment and sign-in --------------------------------------------------------------------

def next_step(secret):
    """A code for the next 30-second step. Enrolment used the current step, so sign-in needs a later one."""
    return auth.totp(secret, at=time.time() + auth.TOTP_STEP)


def test_enrolment_then_sign_in_needs_a_code_and_a_code_works_once(world, monkeypatch):
    username = new_username(world)
    secret = enrol(world, username, monkeypatch)

    no_code = sign_in(world, username)
    assert no_code.status_code == 401 and no_code.get_json()["mfa_required"] is True

    used = next_step(secret)
    assert sign_in(world, username, code=used).status_code == 200
    replay = sign_in(world, username, code=used)
    assert replay.status_code == 401, "the same code must not work twice"


def test_enrolment_is_refused_once_mfa_is_on(world, monkeypatch):
    username = new_username(world)
    secret = enrol(world, username, monkeypatch)
    signed = sign_in(world, username, code=next_step(secret))
    assert signed.status_code == 200
    headers = {"Authorization": f"Bearer {signed.get_json()['token']}"}
    again = world.client.post("/api/mfa/setup", headers=headers)
    assert again.status_code == 409


def test_wrong_code_is_refused_with_the_same_message_as_a_wrong_password(world, monkeypatch):
    username = new_username(world)
    enrol(world, username, monkeypatch)
    wrong_code = sign_in(world, username, code="abcdef")
    wrong_password = sign_in(world, username, password="not the password", code="123456")
    assert wrong_code.status_code == wrong_password.status_code == 401
    assert wrong_code.get_json() == wrong_password.get_json()


def test_mfa_secret_is_stored_encrypted_not_as_base32(world, monkeypatch):
    username = new_username(world)
    secret = enrol(world, username, monkeypatch)
    with psycopg.connect(world.owner_url) as owner:
        stored = owner.execute("SELECT mfa_secret_enc FROM users WHERE username = %s", (username,)).fetchone()[0]
    assert stored and secret not in stored
    assert auth.decrypt_secret(stored, SECRET_KEY) == secret


def test_mfa_fails_closed_without_the_secret_key(world, monkeypatch):
    monkeypatch.delenv("SOC_SECRET_KEY", raising=False)
    r = world.client.post("/api/mfa/setup", headers=world.session(CITY, "viewer"))
    assert r.status_code == 503


# ---- Lockout ---------------------------------------------------------------------------------------

def test_five_wrong_passwords_lock_the_account_even_for_the_right_password(world):
    username = new_username(world)
    for _ in range(5):
        r = sign_in(world, username, password="wrong password here")
        assert r.status_code == 401
    locked = sign_in(world, username)
    assert locked.status_code == 423
    assert "locked" in locked.get_json()["error"]
    assert high_priority_audit(world, username, "auth.lockout") >= 1


def test_a_successful_sign_in_resets_the_failure_count(world):
    username = new_username(world)
    for _ in range(4):
        assert sign_in(world, username, password="wrong password here").status_code == 401
    assert sign_in(world, username).status_code == 200
    for _ in range(4):
        assert sign_in(world, username, password="wrong password here").status_code == 401
    assert sign_in(world, username).status_code == 200, "four failures after a success must not lock"


def test_wrong_codes_count_toward_the_lockout(world, monkeypatch):
    username = new_username(world)
    secret = enrol(world, username, monkeypatch)
    for _ in range(5):
        assert sign_in(world, username, code="abcdef").status_code == 401
    assert sign_in(world, username, code=auth.totp(secret)).status_code == 423
    assert high_priority_audit(world, username, "auth.mfa.fail") >= 1


# ---- Rate limit ------------------------------------------------------------------------------------

def test_login_rate_limit_returns_429_with_retry_after_and_other_users_are_unaffected(world, monkeypatch):
    monkeypatch.setenv("SOC_LOGIN_RATE_LIMIT", "3")
    username = new_username(world)
    other = new_username(world)
    for _ in range(3):
        assert sign_in(world, username, password="wrong password here").status_code == 401
    limited = sign_in(world, username)
    assert limited.status_code == 429
    assert int(limited.headers["Retry-After"]) > 0
    assert sign_in(world, other).status_code == 200


# ---- Privileged MFA gate ---------------------------------------------------------------------------

def test_privileged_account_without_mfa_is_confined_to_enrolment_when_required(world, monkeypatch):
    # The seeded admin is not enrolled, so the gate would refuse it too: create the account before the flag is on.
    username = f"adm-{uuid.uuid4().hex[:8]}"
    r = world.client.post("/api/users", json={"username": username, "email": f"{username}@example.test",
                                              "role": "hospital_admin", "password": PASSWORD},
                          headers=world.session(CITY, "hospital_admin"))
    assert r.status_code == 201
    monkeypatch.setenv("SOC_REQUIRE_PRIVILEGED_MFA", "1")
    headers = {"Authorization": f"Bearer {sign_in(world, username).get_json()['token']}"}
    assert world.client.get("/api/users", headers=headers).status_code == 403
    assert world.client.get("/api/me", headers=headers).status_code == 200


def test_non_privileged_account_is_not_affected_by_the_mfa_requirement(world, monkeypatch):
    username = new_username(world)  # role l1
    monkeypatch.setenv("SOC_REQUIRE_PRIVILEGED_MFA", "1")
    headers = {"Authorization": f"Bearer {sign_in(world, username).get_json()['token']}"}
    assert world.client.get("/api/alerts", headers=headers).status_code == 200
