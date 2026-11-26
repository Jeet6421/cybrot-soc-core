"""Credential helpers for Phase 2: password hashing, TOTP (RFC 6238) and encryption of TOTP secrets at rest.

Standard library first. The one extra dependency is `cryptography`, used only for authenticated encryption
(Fernet: AES-128-CBC with HMAC-SHA256). Nothing here logs or returns a secret except where the caller asks."""
import base64, hashlib, hmac, re, secrets, struct, time

from cryptography.fernet import Fernet, InvalidToken

MIN_PASSWORD_LENGTH = 12
# scrypt cost: N=2^14, r=8, p=1 (about 16 MB of memory per hash). OWASP's minimum for scrypt is N=2^17 with r=8,
# but that costs about 128 MB per login. The cost below is a deliberate trade-off for the prototype VM.
SCRYPT_N, SCRYPT_R, SCRYPT_P = 2 ** 14, 8, 1
_SCRYPT_MAXMEM = 64 * 1024 * 1024
TOTP_STEP = 30
TOTP_DIGITS = 6


def _b64(raw):
    return base64.b64encode(raw).decode()


def _unb64(text):
    return base64.b64decode(text.encode())


def _scrypt(password, salt, n, r, p):
    return hashlib.scrypt(password.encode(), salt=salt, n=n, r=r, p=p, dklen=32, maxmem=_SCRYPT_MAXMEM)


def hash_password(password):
    """Returns 'scrypt$N$r$p$salt$hash'. Raises ValueError if the password is too short."""
    if not isinstance(password, str) or len(password) < MIN_PASSWORD_LENGTH:
        raise ValueError(f"password must be at least {MIN_PASSWORD_LENGTH} characters")
    salt = secrets.token_bytes(16)
    digest = _scrypt(password, salt, SCRYPT_N, SCRYPT_R, SCRYPT_P)
    return f"scrypt${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${_b64(salt)}${_b64(digest)}"


def _decode_hash_component(value):
    try:
        return bytes.fromhex(value)
    except ValueError:
        return _unb64(value)


def verify_password(password, stored):
    """True when the password matches the stored hash. Never raises on a malformed hash."""
    try:
        scheme, n, r, p, salt_b, digest_b = stored.split("$")
        if scheme != "scrypt":
            return False
        # PR #16 stored salt and digest as hex; the main branch's MFA helpers use base64.
        # Accept both encodings so existing accounts remain able to sign in after the merge.
        salt = _decode_hash_component(salt_b)
        expected = _decode_hash_component(digest_b)
        candidate = _scrypt(password, salt, int(n), int(r), int(p))
        return hmac.compare_digest(candidate, expected)
    except (ValueError, TypeError):
        return False


# A hash of a random password, checked when the username does not exist. Both paths then take the same time,
# so the response does not reveal which usernames exist.
DUMMY_HASH = hash_password(secrets.token_urlsafe(24))


def new_totp_secret():
    """20 random bytes, base32 encoded without padding (the format authenticator apps expect)."""
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def _hotp(secret_b32, counter, digits=TOTP_DIGITS):
    padded = secret_b32.upper() + "=" * (-len(secret_b32) % 8)
    key = base64.b32decode(padded)
    mac = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = mac[-1] & 0x0F
    code = (struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(code).zfill(digits)


def totp(secret_b32, at=None):
    """The 6-digit code for a time (seconds since epoch). Defaults to now."""
    at = time.time() if at is None else at
    return _hotp(secret_b32, int(at // TOTP_STEP))


def verify_totp(secret_b32, code, last_counter=None, at=None, window=1):
    """Checks a code against the time steps within `window` of now.
    Returns the matched time step, or None. A step at or before `last_counter` is refused, so one code works once."""
    at = time.time() if at is None else at
    now_step = int(at // TOTP_STEP)
    supplied = str(code or "").strip()
    if not supplied.isdigit() or len(supplied) != TOTP_DIGITS:
        return None
    for step in range(now_step - window, now_step + window + 1):
        if last_counter is not None and step <= last_counter:
            continue
        if hmac.compare_digest(_hotp(secret_b32, step), supplied):
            return step
    return None


def provisioning_uri(username, secret_b32, issuer="Cybrot SOC"):
    """otpauth:// URI that authenticator apps read (or show as a QR code)."""
    from urllib.parse import quote
    label = quote(f"{issuer}:{username}")
    return f"otpauth://totp/{label}?secret={secret_b32}&issuer={quote(issuer)}&digits={TOTP_DIGITS}&period={TOTP_STEP}"


def _fernet(secret_key):
    """Derives a valid Fernet key from any passphrase. SOC_SECRET_KEY must be set, and must be kept out of the database."""
    derived = base64.urlsafe_b64encode(hashlib.sha256(secret_key.encode()).digest())
    return Fernet(derived)


def encrypt_secret(plain, secret_key):
    return _fernet(secret_key).encrypt(plain.encode()).decode()


def decrypt_secret(token, secret_key):
    """Returns the plain secret, or None if the key is wrong or the data was changed."""
    try:
        return _fernet(secret_key).decrypt(token.encode()).decode()
    except (InvalidToken, ValueError, AttributeError):
        return None


def new_session_token():
    return secrets.token_urlsafe(32)


def token_hash(token):
    """Only this hash is stored. A database leak does not reveal usable tokens."""
    return hashlib.sha256(token.encode()).hexdigest()



# Identity constants and helpers used by the tenant/RBAC API in PR #16.
TENANT_ID_RE = re.compile(r"[a-z0-9][a-z0-9-]{1,62}")
USERNAME_RE = re.compile(r"[a-z0-9][a-z0-9._-]{2,39}")
PLATFORM_TENANT = "platform"
HOSPITAL_ROLES = ("hospital_admin", "l1", "l2", "viewer")
ROLES = HOSPITAL_ROLES + ("vendor_admin",)


def password_problem(password):
    """None when the password is acceptable, otherwise the reason."""
    if not isinstance(password, str) or len(password) < MIN_PASSWORD_LENGTH:
        return f"password must be at least {MIN_PASSWORD_LENGTH} characters"
    if len(password) > 256:
        return "password must be at most 256 characters"
    return None


# Compatibility name used by the tenant/RBAC API in PR #16.
new_token = new_session_token
