"""Backup and restore verification (PR 13). See docs/STORAGE.md for the full drill.

snapshot: write what the database should contain, as JSON, from the owner role.
verify:   check a restored database against that snapshot and exit 1 on any failure:
          row counts per table and tenant, row-level security flags, unvalidated constraints, the partition catalog,
          the audit append-only triggers, and tenant isolation as the runtime role (soc_app).

    MIGRATE_DATABASE_URL=postgresql://soc:...@db/soc python scripts/recovery_drill.py snapshot > snapshot.json
    MIGRATE_DATABASE_URL=postgresql://soc:...@restored/soc DATABASE_URL=postgresql://soc_app:...@restored/soc \
        python scripts/recovery_drill.py verify snapshot.json [--exact]

Without --exact, a restored database may hold MORE rows than the snapshot (a point-in-time restore to a later
moment). It must never hold fewer. With --exact, the counts must match, which is what a quiesced drill can prove.
"""
import json
import os
import sys

import psycopg

# Table, the column that holds the tenant, and the snapshot key.
TENANT_TABLES = (
    ("events", "tenant"),
    ("alerts", "tenant"),
    ("assets", "tenant_id"),
    ("audit_events", "tenant_id"),
    ("response_jobs", "tenant_id"),
    ("log_sources", "tenant"),
)
# Read through the runtime role as a hospital admin of each tenant, to prove isolation after the restore.
ISOLATION_TABLES = ("events", "alerts", "assets", "log_sources")
ROLE_FOR_ISOLATION = "hospital_admin"


def snapshot(conn):
    tenants = [r[0] for r in conn.execute("SELECT id FROM tenants ORDER BY id").fetchall()]
    counts = {}
    for table, column in TENANT_TABLES:
        for tenant in tenants:
            counts.setdefault(tenant, {})[table] = conn.execute(
                f"SELECT count(*) FROM {table} WHERE {column} = %s", (tenant,)).fetchone()[0]
    rls = {}
    for table, _ in TENANT_TABLES:
        row = conn.execute("SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE relname = %s "
                           "AND relnamespace = 'public'::regnamespace", (table,)).fetchone()
        rls[table] = {"enabled": bool(row[0]), "forced": bool(row[1])} if row else None
    partitions = [r[0] for r in conn.execute(
        "SELECT partition_name FROM partition_catalog WHERE dropped_at IS NULL ORDER BY partition_name").fetchall()]
    triggers = [r[0] for r in conn.execute(
        "SELECT tgname FROM pg_trigger WHERE tgrelid = 'public.audit_events'::regclass AND NOT tgisinternal "
        "ORDER BY tgname").fetchall()]
    return {"format": 1, "tenants": tenants, "counts": counts, "rls": rls,
            "partitions": partitions, "audit_triggers": triggers}


def verify(owner_url, runtime_url, snap, exact=False):
    """Return a list of (check name, passed, detail). Each check is independent, so one failure does not hide others."""
    results = []

    def check(name, passed, detail=""):
        results.append((name, bool(passed), detail))

    with psycopg.connect(owner_url) as owner:
        current = snapshot(owner)
        for tenant, tables in snap["counts"].items():
            for table, expected in tables.items():
                actual = current["counts"].get(tenant, {}).get(table, 0)
                ok = actual == expected if exact else actual >= expected
                check(f"rows {table} tenant={tenant}", ok, f"expected {'=' if exact else '>='} {expected}, found {actual}")
        for table, flags in snap["rls"].items():
            check(f"rls {table}", current["rls"].get(table) == flags,
                  f"expected {flags}, found {current['rls'].get(table)}")
        invalid = owner.execute("SELECT conname, conrelid::regclass::text FROM pg_constraint "
                                "WHERE NOT convalidated").fetchall()
        check("constraints validated", not invalid, f"not validated: {invalid}")
        missing = [name for name in snap["partitions"] if owner.execute(
            "SELECT to_regclass(%s) IS NULL", ("public." + name,)).fetchone()[0]]
        check("partitions present", not missing, f"missing: {missing}")
        check("audit append-only triggers", current["audit_triggers"] == snap["audit_triggers"],
              f"expected {snap['audit_triggers']}, found {current['audit_triggers']}")

    # Tenant isolation as the runtime role: each tenant sees exactly its own rows, and never another tenant's.
    with psycopg.connect(runtime_url) as runtime:
        for tenant in snap["tenants"]:
            for table in ISOLATION_TABLES:
                runtime.execute("SELECT set_config('app.tenant_id', %s, false), "
                                "set_config('app.role', %s, false)", (tenant, ROLE_FOR_ISOLATION))
                visible = runtime.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
                own = snap["counts"].get(tenant, {}).get(table)
                if own is not None:
                    check(f"isolation {table} sees own rows tenant={tenant}",
                          visible >= own if not exact else visible == own,
                          f"expected {'=' if exact else '>='} {own}, visible {visible}")
                for other in snap["tenants"]:
                    if other == tenant:
                        continue
                    foreign = runtime.execute(f"SELECT count(*) FROM {table} WHERE tenant = %s"
                                              if table != "assets" else
                                              f"SELECT count(*) FROM {table} WHERE tenant_id = %s",
                                              (other,)).fetchone()[0]
                    check(f"isolation {table} hides tenant={other} from tenant={tenant}", foreign == 0,
                          f"{foreign} rows visible")
        runtime.rollback()
    return results


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if not argv or argv[0] not in ("snapshot", "verify"):
        print(__doc__, file=sys.stderr)
        return 2
    owner_url = os.environ.get("MIGRATE_DATABASE_URL", "")
    if not owner_url:
        print("set MIGRATE_DATABASE_URL to the owner role", file=sys.stderr)
        return 2
    if argv[0] == "snapshot":
        with psycopg.connect(owner_url) as conn:
            print(json.dumps(snapshot(conn), indent=2, sort_keys=True))
        return 0
    with open(argv[1], encoding="utf-8") as handle:
        snap = json.load(handle)
    runtime_url = os.environ.get("DATABASE_URL", "")
    if not runtime_url:
        print("set DATABASE_URL to the runtime role (soc_app) of the restored database", file=sys.stderr)
        return 2
    results = verify(owner_url, runtime_url, snap, exact="--exact" in argv)
    for name, passed, detail in results:
        print(f"{'PASS' if passed else 'FAIL'}  {name}  {detail}")
    failed = [r for r in results if not r[1]]
    print(f"{len(results) - len(failed)} passed, {len(failed)} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
