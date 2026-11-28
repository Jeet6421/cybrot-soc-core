"""Bootstrap and administration that runs as the OWNER role. Never exposed through the API.

Typical first setup (inside the compose network; see README):

    docker compose run --rm migrate python manage.py create-user platform vendor vendor_admin --email vendor@example.com
    docker compose run --rm migrate python manage.py create-tenant city-hospital "City Hospital"
    docker compose run --rm migrate python manage.py create-user city-hospital admin hospital_admin
    docker compose run --rm migrate python manage.py create-log-source city-hospital ehr-feed --kind wazuh
    docker compose run --rm migrate python manage.py create-ingest-key city-hospital ehr-feed --label wazuh-01

Passwords are read from a prompt and never appear in the command line or the shell history.
"""
import argparse, getpass, hashlib, os, sys

import psycopg

import auth, hospital

MIGRATE_ENV = "MIGRATE_DATABASE_URL"


def create_tenant(conn, tid, name):
    if not auth.TENANT_ID_RE.fullmatch(tid or ""):
        raise ValueError("tenant id must be 2 to 63 lowercase letters, digits or hyphens")
    if tid == auth.PLATFORM_TENANT:
        raise ValueError("'platform' is reserved for the vendor")
    if conn.execute("SELECT 1 FROM tenants WHERE id = %s", (tid,)).fetchone():
        raise ValueError("tenant already exists")
    conn.execute("INSERT INTO tenants(id, name) VALUES (%s, %s)", (tid, (name or tid).strip()[:120]))


def create_user(conn, tenant, username, role, password, email):
    if role not in auth.ROLES:
        raise ValueError(f"role must be one of: {', '.join(auth.ROLES)}")
    if (role == "vendor_admin") != (tenant == auth.PLATFORM_TENANT):
        raise ValueError("vendor_admin belongs to the 'platform' tenant; hospital roles belong to a hospital")
    if not auth.USERNAME_RE.fullmatch(username or ""):
        raise ValueError("username must be 3 to 40 lowercase letters, digits, dots, hyphens or underscores")
    email = (email or "").strip().lower()
    problem = auth.email_problem(email)
    if problem:
        raise ValueError(problem)
    problem = auth.password_problem(password)
    if problem:
        raise ValueError(problem)
    if not conn.execute("SELECT 1 FROM tenants WHERE id = %s", (tenant,)).fetchone():
        raise ValueError("tenant not found")
    if conn.execute("SELECT 1 FROM users WHERE lower(email) = %s", (email,)).fetchone():
        raise ValueError("email already belongs to an account")
    tenant_id = None if role == "vendor_admin" else tenant
    account_type = "vendor_support" if role == "vendor_admin" else "hospital_staff"
    if conn.execute("SELECT 1 FROM users WHERE tenant IS NOT DISTINCT FROM %s AND username = %s",
                    (tenant_id, username)).fetchone():
        raise ValueError("user already exists in this tenant")
    row = conn.execute("INSERT INTO users(tenant, username, email, role, account_type, password_hash) "
                       "VALUES (%s, %s, %s, %s, %s, %s) RETURNING id",
                       (tenant_id, username, email, role, account_type, auth.hash_password(password))).fetchone()
    return row[0]


def create_log_source(conn, tenant, name, kind=""):
    name = (name or "").strip()
    if not name or len(name) > 80:
        raise ValueError("log source name must be 1 to 80 characters")
    if not conn.execute("SELECT 1 FROM tenants WHERE id = %s", (tenant,)).fetchone():
        raise ValueError("tenant not found")
    kind = (kind or "").strip()
    if kind not in hospital.LOG_SOURCE_KINDS:
        raise ValueError("kind must be one of: " + ", ".join(hospital.LOG_SOURCE_KINDS))
    row = conn.execute("INSERT INTO log_sources(tenant, name, kind) VALUES (%s, %s, %s) RETURNING id",
                       (tenant, name, kind)).fetchone()
    return row[0]


def create_ingest_key(conn, tenant, log_source_name, label=""):
    """Returns the raw key. It is shown once; only its SHA-256 hash is stored."""
    row = conn.execute("SELECT id FROM log_sources WHERE tenant = %s AND name = %s AND disabled_at IS NULL",
                       (tenant, log_source_name)).fetchone()
    if not row:
        raise ValueError("log source not found for this tenant (or it is disabled)")
    key = auth.new_token()
    conn.execute("INSERT INTO ingest_keys(tenant, label, key_hash, log_source_id) VALUES (%s, %s, %s, %s)",
                 (tenant, (label or "")[:80], hashlib.sha256(key.encode()).hexdigest(), row[0]))
    return key


def _owner_connection():
    url = os.environ.get(MIGRATE_ENV, "")
    if not url:
        raise SystemExit(f"set {MIGRATE_ENV} (the owner role)")
    return psycopg.connect(url)


def main(argv=None):
    ap = argparse.ArgumentParser(description="SOC Core administration (owner role).")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("create-tenant"); p.add_argument("id"); p.add_argument("name", nargs="?", default="")
    p = sub.add_parser("create-user"); p.add_argument("tenant"); p.add_argument("username"); p.add_argument("role")
    p.add_argument("--email", required=True)
    p = sub.add_parser("create-log-source"); p.add_argument("tenant"); p.add_argument("name")
    p.add_argument("--kind", default="")
    p = sub.add_parser("create-ingest-key"); p.add_argument("tenant"); p.add_argument("log_source")
    p.add_argument("--label", default="")
    args = ap.parse_args(argv)
    try:
        with _owner_connection() as conn:
            if args.cmd == "create-tenant":
                create_tenant(conn, args.id, args.name)
                print(f"tenant {args.id} created")
            elif args.cmd == "create-user":
                password = getpass.getpass(f"password for {args.username} (12+ characters): ")
                if getpass.getpass("repeat password: ") != password:
                    raise ValueError("passwords do not match")
                uid = create_user(conn, args.tenant, args.username, args.role, password, args.email)
                print(f"user {args.username} ({args.role}) created with id {uid}")
            elif args.cmd == "create-log-source":
                sid = create_log_source(conn, args.tenant, args.name, args.kind)
                print(f"log source {args.name} created with id {sid}")
            elif args.cmd == "create-ingest-key":
                key = create_ingest_key(conn, args.tenant, args.log_source, args.label)
                print("ingest key (shown once; store it in the log source's config):")
                print(key)
            conn.commit()
    except (ValueError, psycopg.Error) as e:
        print(f"refused: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
