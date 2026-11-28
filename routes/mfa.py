"""TOTP enrolment for the signed-in account (PR 14). The code check at sign-in lives in app.py's login().

POST /api/mfa/setup   starts enrolment: a new secret, returned once, with an otpauth:// URI for authenticator apps.
POST /api/mfa/verify  checks the first code and turns MFA on. Each time step is accepted once (anti-replay).

Both need a user session and fail closed (503) without SOC_SECRET_KEY. Once MFA is on, setup is refused, so a
stolen session cannot replace the second factor. Wrong codes count toward the account lockout."""
from flask import Blueprint, g, jsonify

import auth

bp = Blueprint("mfa", __name__)


def _soc():
    # app.py registers this blueprint after its own helpers are defined, so importing it here at request time is safe.
    import app
    return app


@bp.post("/api/mfa/setup")
def setup():
    soc = _soc()
    key = soc.mfa_key()
    uid = g.identity["actor_id"]
    c = soc.db()
    state = c.execute("SELECT * FROM auth_user_security(%s)", (uid,)).fetchone()
    if state["mfa_enabled"]:
        raise soc.Refuse(409, "MFA is already enabled for this account")
    secret = auth.new_totp_secret()
    c.execute("SELECT auth_mfa_store_pending(%s, %s)", (uid, auth.encrypt_secret(secret, key)))
    soc._auth_event(c, g.identity["tenant"], g.identity["role"], uid, "auth.mfa.setup", "allow")
    soc.commit()
    return jsonify(secret=secret, otpauth_uri=auth.provisioning_uri(g.identity["name"], secret))


@bp.post("/api/mfa/verify")
def verify():
    soc = _soc()
    key = soc.mfa_key()
    body = soc._body(required=True)
    code = body.get("code") if isinstance(body.get("code"), str) else ""
    uid = g.identity["actor_id"]
    tenant, role = g.identity["tenant"], g.identity["role"]
    c = soc.db()
    state = c.execute("SELECT * FROM auth_user_security(%s)", (uid,)).fetchone()
    if state["mfa_enabled"]:
        raise soc.Refuse(409, "MFA is already enabled for this account")
    if not state["mfa_secret_enc"]:
        raise soc.Refuse(409, "start enrolment with POST /api/mfa/setup first")
    if state["locked"]:
        raise soc.Refuse(423, f"account is locked after repeated failures; try again in {state['lock_seconds']} seconds")
    secret = auth.decrypt_secret(state["mfa_secret_enc"], key)
    if secret is None:
        raise soc.Refuse(503, "MFA secret cannot be read: SOC_SECRET_KEY does not match the key it was saved with")
    step = auth.verify_totp(secret, code, last_counter=state["mfa_last_counter"])
    if step is None:
        c.execute("SELECT locked, failed FROM auth_login_failed(%s, %s, %s)",
                  (uid, soc.LOCKOUT_FAILURES, soc.LOCKOUT_SECONDS))
        soc._auth_event(c, tenant, role, uid, "auth.mfa.fail", "deny", "enrolment")
        soc.commit()
        raise soc.Refuse(400, "the code is not valid")
    if not c.execute("SELECT auth_mfa_enable(%s, %s)", (uid, step)).fetchone()[0]:
        raise soc.Refuse(409, "MFA state changed while enrolling; start again with POST /api/mfa/setup")
    soc._auth_event(c, tenant, role, uid, "auth.mfa.verify", "allow", "enrolment")
    soc.commit()
    return jsonify(mfa_enabled=True)
