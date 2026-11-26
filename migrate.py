"""Create or update the database: tables, row-level security, grants and the runtime role soc_app.

Runs as the OWNER role (MIGRATE_DATABASE_URL). The app itself never runs this, and never runs DDL.
docker compose runs it once, in the 'migrate' service, before the app starts. It is idempotent.

    MIGRATE_DATABASE_URL=postgresql://soc:...@db:5432/soc  SOC_APP_PASSWORD=...  python migrate.py

The owner must be a superuser or have BYPASSRLS. The SECURITY DEFINER lookups in db/schema.sql (login,
session and ingest-key checks) read across tenants by design, and they run as the owner.
"""
import os, pathlib, sys

import psycopg
from psycopg import sql

SCHEMA_FILE = pathlib.Path(__file__).resolve().parent / "db" / "schema.sql"


def check_owner(conn):
    row = conn.execute("SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname = current_user").fetchone()
    if not row or not row[0]:
        raise RuntimeError("the migration role must be a superuser or have BYPASSRLS; "
                           "the SECURITY DEFINER lookups cannot read tenant data otherwise")


def migrate(owner_url, app_password):
    """Apply db/schema.sql and set the soc_app password. The caller chooses the owner URL."""
    if not app_password:
        raise ValueError("SOC_APP_PASSWORD is required: it is the password the app uses to connect as soc_app")
    with psycopg.connect(owner_url) as conn:
        check_owner(conn)
        conn.execute(SCHEMA_FILE.read_text())
        conn.execute(sql.SQL("ALTER ROLE soc_app PASSWORD {}").format(sql.Literal(app_password)))
        conn.commit()


def main(argv=None):
    owner_url = os.environ.get("MIGRATE_DATABASE_URL", "")
    if not owner_url:
        print("migrate: set MIGRATE_DATABASE_URL (the owner role)", file=sys.stderr)
        return 2
    try:
        migrate(owner_url, os.environ.get("SOC_APP_PASSWORD", ""))
    except (RuntimeError, ValueError, psycopg.Error) as e:
        print(f"migrate failed: {e}", file=sys.stderr)
        return 1
    print("migrate: schema, row-level security and grants applied; soc_app role ready")
    return 0


if __name__ == "__main__":
    sys.exit(main())
