import os, sys, uuid
from urllib.parse import urlsplit, urlunsplit

import psycopg
import pytest
from psycopg import sql

# Let the tests import app.py / auth.py / manage.py / migrate.py from the project root.
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

# The tests need a PostgreSQL server. The admin URL is the OWNER role: it creates databases and runs migrations.
# CI starts a postgres service with these defaults; locally, point TEST_ADMIN_URL at your server.
ADMIN_URL = os.environ.get("TEST_ADMIN_URL", "postgresql://soc:soc@localhost:5432/postgres")
HOSPITALS = ("city-hospital", "ortho-clinic")
HOSPITAL_ROLES = ("hospital_admin", "l1", "l2", "viewer")
USERNAME = {"hospital_admin": "admin", "l1": "analyst-l1", "l2": "analyst-l2", "viewer": "viewer", "vendor_admin": "vendor"}


def _base(url):
    return url.rsplit("/", 1)[0]


def create_database(prefix="soc_test"):
    """Create an empty database and return (owner URL, name). Caller drops it with drop_database()."""
    name = f"{prefix}_{uuid.uuid4().hex[:12]}"
    with psycopg.connect(ADMIN_URL, autocommit=True) as admin:
        admin.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(name)))
    return f"{_base(ADMIN_URL)}/{name}", name


def drop_database(name):
    with psycopg.connect(ADMIN_URL, autocommit=True) as admin:
        admin.execute(sql.SQL("DROP DATABASE IF EXISTS {} WITH (FORCE)").format(sql.Identifier(name)))


def app_url_for(owner_url):
    """The same database, as the runtime role soc_app. The app and most tests use this one."""
    p = urlsplit(owner_url)
    netloc = f"soc_app:{APP_PASSWORD}@{p.hostname}:{p.port or 5432}"
    return urlunsplit((p.scheme, netloc, p.path, p.query, p.fragment))


# One database for the whole test session, migrated by the owner role. The app then reads its connection
# string from DATABASE_URL (the soc_app role), and lab endpoints get the owner through LAB_DATABASE_URL.
import migrate  # noqa: E402  (needs ROOT on sys.path)
from support import APP_PASSWORD, PASSWORD  # noqa: E402

SESSION_OWNER_URL, _SESSION_DB_NAME = create_database()
migrate.migrate(SESSION_OWNER_URL, APP_PASSWORD)
os.environ["MIGRATE_DATABASE_URL"] = SESSION_OWNER_URL
os.environ["DATABASE_URL"] = app_url_for(SESSION_OWNER_URL)
os.environ["LAB_DATABASE_URL"] = SESSION_OWNER_URL


def pytest_sessionfinish(session, exitstatus):
    try:
        drop_database(_SESSION_DB_NAME)
    except Exception as e:  # never fail the run because cleanup failed
        print(f"could not drop test database {_SESSION_DB_NAME}: {type(e).__name__}", file=sys.stderr)


@pytest.fixture
def scratch_db():
    """A separate, empty database for one test, migrated as the owner. Yields the owner URL."""
    url, name = create_database("soc_scratch")
    yield url
    drop_database(name)


class World:
    """Seeded identities. Sessions are real: each comes from POST /api/login."""

    def __init__(self, client, tokens, keys, owner_url):
        self.client = client
        self._tokens = tokens  # {(tenant, role): token}; vendor under ("platform", "vendor_admin")
        self._keys = keys      # {tenant: raw ingest key}
        self.owner_url = owner_url

    def session(self, tenant, role):
        return {"Authorization": f"Bearer {self._tokens[(tenant, role)]}"}

    def vendor(self):
        return self.session("platform", "vendor_admin")

    def ingest(self, tenant):
        return {"Authorization": f"Bearer {self._keys[tenant]}"}

    def ingest_token(self, tenant):
        return self._keys[tenant]


@pytest.fixture(scope="session")
def world():
    import app as soc
    import manage

    with psycopg.connect(SESSION_OWNER_URL) as owner:
        manage.create_tenant(owner, "city-hospital", "City Hospital")
        manage.create_tenant(owner, "ortho-clinic", "Ortho Clinic")
        manage.create_user(owner, "platform", USERNAME["vendor_admin"], "vendor_admin", PASSWORD, "vendor@example.test")
        keys = {}
        for tenant in HOSPITALS:
            for role in HOSPITAL_ROLES:
                manage.create_user(owner, tenant, USERNAME[role], role, PASSWORD,
                                   f"{USERNAME[role]}+{tenant}@example.test")
            manage.create_log_source(owner, tenant, "ehr-feed", "wazuh")
            keys[tenant] = manage.create_ingest_key(owner, tenant, "ehr-feed", "test key")
            owner.commit()
        owner.commit()

    client = soc.app.test_client()
    tokens = {}
    logins = [("platform", USERNAME["vendor_admin"], "vendor_admin")] + [
        (t, USERNAME[r], r) for t in HOSPITALS for r in HOSPITAL_ROLES]
    for tenant, username, role in logins:
        r = client.post("/api/login", json={"tenant": tenant, "username": username, "password": PASSWORD})
        assert r.status_code == 200, (tenant, username, r.get_json())
        tokens[(tenant, role)] = r.get_json()["token"]
    return World(client, tokens, keys, SESSION_OWNER_URL)
