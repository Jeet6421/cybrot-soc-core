import os, sys, uuid

import psycopg
import pytest
from psycopg import sql

# Let the tests import app.py / detect.py / generate.py from the project root.
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

# The tests need a PostgreSQL server. The admin URL must be able to CREATE and DROP databases.
# CI starts a postgres service with these defaults; locally, point TEST_ADMIN_URL at your server.
ADMIN_URL = os.environ.get("TEST_ADMIN_URL", "postgresql://soc:soc@localhost:5432/postgres")


def _base(url):
    return url.rsplit("/", 1)[0]


def create_database(prefix="soc_test"):
    """Create an empty database and return its URL. Caller drops it with drop_database()."""
    name = f"{prefix}_{uuid.uuid4().hex[:12]}"
    with psycopg.connect(ADMIN_URL, autocommit=True) as admin:
        admin.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(name)))
    return f"{_base(ADMIN_URL)}/{name}", name


def drop_database(name):
    with psycopg.connect(ADMIN_URL, autocommit=True) as admin:
        admin.execute(sql.SQL("DROP DATABASE IF EXISTS {} WITH (FORCE)").format(sql.Identifier(name)))


# One database for the whole test session. app.connect() reads DATABASE_URL at call time,
# so it must be set before any test runs.
SESSION_DB_URL, _SESSION_DB_NAME = create_database()
os.environ["DATABASE_URL"] = SESSION_DB_URL


def pytest_sessionfinish(session, exitstatus):
    try:
        drop_database(_SESSION_DB_NAME)
    except Exception as e:  # never fail the run because cleanup failed
        print(f"could not drop test database {_SESSION_DB_NAME}: {type(e).__name__}", file=sys.stderr)


@pytest.fixture
def scratch_db():
    """A separate, empty database for one test. Yields its URL."""
    url, name = create_database("soc_scratch")
    yield url
    drop_database(name)
