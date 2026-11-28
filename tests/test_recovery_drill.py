"""The restore drill's verifier (scripts/recovery_drill.py) against a live database (PR 13).

The drill is meant for a restored copy. Here it runs against the test database, which proves the checks pass on
healthy data and fail when the data disagrees with the snapshot.
"""
import os
import sys
from pathlib import Path

import psycopg

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import recovery_drill  # noqa: E402


def _snapshot(world):
    with psycopg.connect(world.owner_url) as owner:
        return recovery_drill.snapshot(owner)


def test_verifier_passes_on_the_database_it_was_taken_from(world):
    snap = _snapshot(world)
    results = recovery_drill.verify(world.owner_url, os.environ["DATABASE_URL"], snap)
    failed = [r for r in results if not r[1]]
    assert not failed, failed
    names = {name for name, _, _ in results}
    assert any(n.startswith("isolation events") for n in names)
    assert "audit append-only triggers" in names and "partitions present" in names


def test_verifier_fails_when_rows_are_missing(world):
    snap = _snapshot(world)
    tenant = snap["tenants"][0]
    snap["counts"][tenant]["events"] += 1000
    results = recovery_drill.verify(world.owner_url, os.environ["DATABASE_URL"], snap)
    assert [r for r in results if r[0] == f"rows events tenant={tenant}"][0][1] is False


def test_verifier_fails_when_a_partition_is_missing(world):
    snap = _snapshot(world)
    snap["partitions"] = snap["partitions"] + ["events_p199901"]  # catalogued, but never created
    results = recovery_drill.verify(world.owner_url, os.environ["DATABASE_URL"], snap)
    assert [r for r in results if r[0] == "partitions present"][0][1] is False
