"""CERT-In retention: whole partitions are dropped only once they have passed the window, and the window is at
least 180 days (PR 13)."""
import psycopg
import pytest


def test_retention_below_180_days_is_refused_by_the_database(world):
    with psycopg.connect(world.owner_url) as owner:
        with pytest.raises(psycopg.errors.InvalidParameterValue):
            owner.execute("SELECT * FROM drop_expired_partitions(179)").fetchall()
        owner.rollback()


def test_partitions_cover_the_retention_window_and_the_next_months(world):
    with psycopg.connect(world.owner_url) as owner:
        owner.execute("SELECT ensure_time_partitions()").fetchone()
        months = owner.execute(
            "SELECT count(*) FROM partition_catalog WHERE parent = 'events' AND dropped_at IS NULL "
            "AND range_end > now() - interval '180 days' AND range_start <= now() + interval '2 months'").fetchone()[0]
        assert months >= 7  # the month of the 180-day cutoff through two months ahead


def test_expired_partition_is_dropped_and_recent_rows_survive(world):
    old = "events_p200001"
    with psycopg.connect(world.owner_url) as owner:
        owner.execute(f"DROP TABLE IF EXISTS public.{old}")
        owner.execute("DELETE FROM partition_catalog WHERE partition_name = %s", (old,))
        owner.execute(f"CREATE TABLE public.{old} PARTITION OF public.events "
                      "FOR VALUES FROM ('2000-01-01 00:00:00+00') TO ('2000-02-01 00:00:00+00')")
        owner.execute("INSERT INTO partition_catalog(parent, partition_name, range_start, range_end) "
                      "VALUES ('events', %s, '2000-01-01+00', '2000-02-01+00')", (old,))
        owner.execute("INSERT INTO events(ts, tenant, type, occurred_at, dedupe_key) "
                      "VALUES ('2000-01-15T00:00:00', 'city-hospital', 'old', '2000-01-15T00:00:00Z', 'retention-old')")
        recent_before = owner.execute(
            "SELECT count(*) FROM events WHERE occurred_at >= now() - interval '180 days'").fetchone()[0]
        owner.commit()

    with psycopg.connect(world.owner_url) as owner:
        dropped = owner.execute("SELECT partition_name, rows_dropped FROM drop_expired_partitions(180)").fetchall()
        owner.commit()
    assert (old, 1) in dropped
    with psycopg.connect(world.owner_url) as owner:
        assert owner.execute("SELECT to_regclass(%s) IS NULL", (f"public.{old}",)).fetchone()[0]
        recent_after = owner.execute(
            "SELECT count(*) FROM events WHERE occurred_at >= now() - interval '180 days'").fetchone()[0]
        assert recent_after == recent_before
        # Nothing still catalogued is entirely older than the cutoff.
        assert owner.execute("SELECT count(*) FROM partition_catalog WHERE dropped_at IS NULL "
                             "AND range_end <= now() - interval '180 days'").fetchone()[0] == 0
