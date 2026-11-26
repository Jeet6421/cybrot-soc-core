"""Passwords and session tokens for SOC Core. Standard library only.

Passwords: scrypt with a random salt, stored as "scrypt$N$r$p$salt$hash". Session and ingest tokens are random;
only their SHA-256 hash is stored, so a database leak does not reveal a usable token.
"""
import hashlib, hmac, re, secrets

SCRYPT_N, SCRYPT_R, SCRYPT_P = 2 ** 14, 8, 1
SCRYPT_MAXMEM = 64 * 1024 * 1024
MIN_PASSWORD_LENGTH = 12
TENANT_ID_RE = re.compile(r"[a-z0-9][a-z0-9-]{1,62}")
USERNAME_RE = re.compile(r"[a-z0-9][a-z0-9._-]{2,39}")
PLATFORM_TENANT = "platform"  # the vendor's own tenant; vendor admins log in here, it holds no hospital data
HOSPITAL_ROLES = ("hospital_admin", "l1", "l2", "viewer")
ROLES = HOSPITAL_ROLES + ("vendor_admin",)


def hash_password(password):
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P,
                        maxmem=SCRYPT_MAXMEM, dklen=32)
    return f"scrypt${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${salt.hex()}${dk.hex()}"


def verify_password(password, stored):
    """True when the password matches the stored hash. Malformed hashes simply fail."""
    try:
        scheme, n, r, p, salt_hex, dk_hex = stored.split("$")
        if scheme != "scrypt":
            return False
        expected = bytes.fromhex(dk_hex)
        dk = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt_hex), n=int(n), r=int(r), p=int(p),
                            maxmem=SCRYPT_MAXMEM, dklen=len(expected))
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(dk, expected)


# Used when a username is unknown, so a failed login takes about as long as a real one.
DUMMY_HASH = hash_password(secrets.token_urlsafe(16))


def password_problem(password):
    """None when the password is acceptable, otherwise the reason."""
    if not isinstance(password, str) or len(password) < MIN_PASSWORD_LENGTH:
        return f"password must be at least {MIN_PASSWORD_LENGTH} characters"
    if len(password) > 256:
        return "password must be at most 256 characters"
    return None


def new_token():
    """A random bearer token. Shown to the caller once; only token_hash() of it is stored."""
    return secrets.token_urlsafe(32)


def token_hash(token):
    return hashlib.sha256(token.encode()).hexdigest()
