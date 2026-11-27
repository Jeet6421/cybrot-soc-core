"""Maker-checker approval, playbook allowlist, tenant and medical-device guardrails, and the Ansible executor.

Ansible is replaced by a fake runner. The fake checks what the real command would receive (one host in the
inventory, a private key with mode 0600, --limit set) and returns a PLAY RECAP.
"""
import dataclasses
import json
import stat
import uuid
from pathlib import Path

import psycopg
import pytest

import ansible_runner
import app as soc
import playbooks
import worker
from support import Api, CITY, ORTHO, failed_logins

RECAP_OK = "PLAY RECAP\nws-1 : ok=3 changed=1 unreachable=0 failed=0 skipped=0\n"
RECAP_FAILED = "PLAY RECAP\nws-1 : ok=1 changed=0 unreachable=0 failed=1 skipped=0\n"
RECAP_UNREACHABLE = "PLAY RECAP\nws-1 : ok=0 changed=0 unreachable=1 failed=0 skipped=0\n"


def owner_rows(world, sql, params=()):
    with psycopg.connect(world.owner_url) as owner:
        return owner.execute(sql, params).fetchall()


def job_row(world, job_id):
    return owner_rows(world, "SELECT status, attempts, approved_by, requested_by, result, errors, playbook_version, "
                             "target_host FROM response_jobs WHERE job_id=%s", (job_id,))[0]


def open_alert(world):
    Api(world, CITY, "l1").post("/api/events", json=failed_logins(CITY))
    return next(a["id"] for a in Api(world, CITY, "l1").get("/api/alerts").get_json() if a.get("status") != "closed")


def new_asset(world, tenant=CITY, asset_class="workstation", mode="edr_managed", ip=""):
    name = f"{asset_class[:4]}-{uuid.uuid4().hex[:8]}"
    created = Api(world, tenant, "hospital_admin").post("/api/assets", json={
        "device_name": name, "asset_class": asset_class, "monitoring_mode": mode, "ip_address": ip})
    assert created.status_code == 201, created.get_json()
    return name


def request_action(world, action, target, role="l1", alert_id=None):
    alert_id = alert_id or open_alert(world)
    return Api(world, CITY, role).post(f"/api/alerts/{alert_id}/response-approvals", json={
        "action": action, "target": target, "reason": "maker-checker test"}), alert_id


def approved_job(world, target=None, action="isolate_host"):
    target = target or new_asset(world)
    response, _ = request_action(world, action, target)
    assert response.status_code == 201, response.get_json()
    decided = Api(world, CITY, "l2").post(f"/api/response-approvals/{response.get_json()['id']}/decision",
                                          json={"decision": "approved"})
    assert decided.status_code == 200, decided.get_json()
    return decided.get_json()["job_id"]


# ---- maker-checker -------------------------------------------------------------------------------------------

def test_disruptive_action_is_pending_until_a_second_person_approves(world):
    target = new_asset(world)
    response, _ = request_action(world, "isolate_host", target, role="l1")
    body = response.get_json()
    assert response.status_code == 201 and body["job_status"] == "pending_approval"
    assert body["execution"] == "not_performed"
    status, approved_by = owner_rows(world, "SELECT status, approved_by FROM response_jobs WHERE job_id=%s",
                                     (body["job_id"],))[0]
    assert (status, approved_by) == ("pending_approval", None)


def test_l1_cannot_approve_a_disruptive_action(world):
    response, _ = request_action(world, "isolate_host", new_asset(world), role="l1")
    decision = Api(world, CITY, "l1").post(f"/api/response-approvals/{response.get_json()['id']}/decision",
                                           json={"decision": "approved"})
    assert decision.status_code == 403
    assert owner_rows(world, "SELECT status FROM response_jobs WHERE job_id=%s",
                      (response.get_json()["job_id"],))[0][0] == "pending_approval"


def test_requester_cannot_approve_their_own_action(world):
    response, _ = request_action(world, "isolate_host", new_asset(world), role="l2")
    decision = Api(world, CITY, "l2").post(f"/api/response-approvals/{response.get_json()['id']}/decision",
                                           json={"decision": "approved"})
    assert decision.status_code == 409
    assert owner_rows(world, "SELECT status FROM response_jobs WHERE job_id=%s",
                      (response.get_json()["job_id"],))[0][0] == "pending_approval"


def test_a_hospital_admin_can_approve_an_analysts_request_and_it_is_queued_once(world):
    target = new_asset(world)
    response, _ = request_action(world, "isolate_host", target, role="l1")
    approval_id = response.get_json()["id"]
    decided = Api(world, CITY, "hospital_admin").post(f"/api/response-approvals/{approval_id}/decision",
                                                      json={"decision": "approved"})
    assert decided.status_code == 200 and decided.get_json()["job_status"] == "queued"
    again = Api(world, CITY, "l2").post(f"/api/response-approvals/{approval_id}/decision",
                                        json={"decision": "approved"})
    assert again.status_code == 409
    status, approved_by, requested_by = owner_rows(
        world, "SELECT status, approved_by, requested_by FROM response_jobs WHERE job_id=%s",
        (response.get_json()["job_id"],))[0]
    assert status == "queued" and approved_by != requested_by


def test_a_rejected_action_never_queues(world):
    response, _ = request_action(world, "isolate_host", new_asset(world), role="l1")
    decision = Api(world, CITY, "l2").post(f"/api/response-approvals/{response.get_json()['id']}/decision",
                                           json={"decision": "rejected", "note": "not needed"})
    assert decision.status_code == 200 and decision.get_json()["job_status"] == "rejected"
    assert owner_rows(world, "SELECT status, approved_by FROM response_jobs WHERE job_id=%s",
                      (response.get_json()["job_id"],))[0] == ("rejected", None)


# ---- allowlist and input validation ----------------------------------------------------------------------------

def test_the_client_cannot_choose_a_playbook(world):
    target = new_asset(world)
    alert_id = open_alert(world)
    response = Api(world, CITY, "l1").post(f"/api/alerts/{alert_id}/response-approvals", json={
        "action": "isolate_host", "target": target, "reason": "try", "playbook": "../../etc/passwd"})
    assert response.status_code == 400


def test_unknown_actions_are_refused(world):
    response, _ = request_action(world, "run_shell", "ws-1")
    assert response.status_code == 400


@pytest.mark.parametrize("target", ["a;rm -rf /", "{{ 7*7 }}", "../../etc/passwd", "ws 1", "", "$(id)"])
def test_injection_shaped_targets_are_refused(world, target):
    response, _ = request_action(world, "isolate_host", target)
    assert response.status_code == 400


def test_loopback_cannot_be_blocked(world):
    response, _ = request_action(world, "block_ip", "127.0.0.1")
    assert response.status_code == 400


# ---- tenant and medical-device guardrails ---------------------------------------------------------------------

def test_a_host_of_another_hospital_is_refused(world):
    other = new_asset(world, tenant=ORTHO)
    response, _ = request_action(world, "isolate_host", other)
    assert response.status_code == 400
    assert owner_rows(world, "SELECT count(*) FROM response_jobs WHERE target_host=%s", (other,))[0][0] == 0


def test_disruptive_action_on_medical_equipment_is_refused_at_request(world):
    mri = new_asset(world, asset_class="mri", mode="agentless_medical")
    response, _ = request_action(world, "isolate_host", mri)
    assert response.status_code == 409
    assert "IEC 80001" in response.get_json()["error"]


def test_block_ip_on_a_medical_device_address_is_refused(world):
    ip = "10.99.7.44"
    new_asset(world, asset_class="ventilator", mode="agentless_medical", ip=ip)
    response, _ = request_action(world, "block_ip", ip)
    assert response.status_code == 409


def test_medical_equipment_added_after_approval_is_not_isolated(world):
    target = new_asset(world)
    response, _ = request_action(world, "isolate_host", target, role="l1")
    with psycopg.connect(world.owner_url) as owner:  # the inventory changes: the device is now a ventilator
        owner.execute("UPDATE assets SET asset_class='ventilator', monitoring_mode='agentless_medical' "
                      "WHERE tenant_id=%s AND device_name=%s", (CITY, target))
    decided = Api(world, CITY, "l2").post(f"/api/response-approvals/{response.get_json()['id']}/decision",
                                          json={"decision": "approved"})
    assert decided.status_code == 409
    assert owner_rows(world, "SELECT status FROM response_jobs WHERE job_id=%s",
                      (response.get_json()["job_id"],))[0][0] == "pending_approval"


def test_the_playbook_allowlist_is_pinned_by_digest():
    for pb in playbooks.ALLOWLIST.values():
        assert playbooks.verified_path(pb).is_file()
    tampered = dataclasses.replace(playbooks.ALLOWLIST["block_ip"], sha256="0" * 64)
    with pytest.raises(RuntimeError, match="approved digest"):
        playbooks.verified_path(tampered)


# ---- Ansible executor (fake runner) ----------------------------------------------------------------------------

class FakeAnsible:
    """Stands in for ansible-playbook. It records what the real command would have been given."""

    def __init__(self, code=0, out=RECAP_OK, err=""):
        self.code, self.out, self.err = code, out, err
        self.calls = []

    def __call__(self, cmd, env, cwd, timeout):
        workspace = Path(cwd)
        inventory = json.loads((workspace / "inventory.json").read_text())
        key = workspace / "ssh_key"
        self.calls.append({"cmd": cmd, "workspace": workspace, "hosts": sorted(inventory["all"]["hosts"]),
                           "key_mode": stat.S_IMODE(key.stat().st_mode), "key": key.read_bytes(),
                           "env": env})
        return self.code, self.out, self.err


@pytest.fixture
def ansible_dirs(tmp_path):
    creds = tmp_path / "creds"
    (creds / CITY).mkdir(parents=True)
    (creds / CITY / "ssh_key").write_bytes(b"-----KEY MATERIAL-----")
    work = tmp_path / "work"
    work.mkdir()
    return creds, work


def run_with(job_id, runner, creds, work, rounds=10):
    def dispatch(job):
        if job["job_id"] != job_id:
            return {"skipped": True}  # other jobs in the shared database are not this test's concern
        with soc.connect() as conn:
            return ansible_runner.run_job(job, conn=conn, runner=runner, cred_dir=str(creds),
                                          workspace_root=str(work))
    executors = {action: dispatch for action in playbooks.ALLOWLIST}
    for _ in range(rounds):
        with soc.connect() as conn:
            worker.run_once(conn, "worker-ansible", executors=executors, limit=100)
        if job_row_status(job_id) in ("succeeded", "dead"):
            break


def job_row_status(job_id):
    with soc.connect() as conn:
        return conn.execute("SELECT status FROM response_jobs WHERE job_id=%s", (job_id,)).fetchone()["status"]


def test_successful_run_records_result_writes_audit_and_removes_files(world, ansible_dirs):
    creds, work = ansible_dirs
    target = new_asset(world)
    job_id = approved_job(world, target=target)
    fake = FakeAnsible()
    run_with(job_id, fake, creds, work, rounds=1)

    recorded = [c for c in fake.calls]
    assert len(recorded) == 1, "the playbook must run exactly once for this job"
    call = recorded[0]
    assert call["hosts"] == [target]                       # only the verified host is in the inventory
    assert call["cmd"][call["cmd"].index("--limit") + 1] == target
    assert isinstance(call["cmd"], list) and "/bin/sh" not in call["cmd"]
    assert call["key"] == b"-----KEY MATERIAL-----" and call["key_mode"] == 0o600
    assert not call["workspace"].exists()                 # inventory, key and vars are gone after the run
    assert list(work.iterdir()) == []

    status, attempts, approved_by, requested_by, result, errors, version, _ = job_row(world, job_id)
    assert status == "succeeded" and attempts == 1 and errors == []
    assert approved_by != requested_by
    assert version == "1.0.0"
    assert result["recap"] == {"ok": 3, "changed": 1, "unreachable": 0, "failed": 0}
    assert "PLAY RECAP" not in json.dumps(result)         # raw output is never stored

    actions = [row[0] for row in owner_rows(world, "SELECT action FROM audit_events WHERE resource_id=%s "
                                                   "AND resource_type='response_job' ORDER BY audit_id",
                                            (str(job_id),))]
    for expected in ("response_job.request", "response_job.queue", "response_job.start", "response_job.finish"):
        assert expected in actions, expected
    finish = owner_rows(world, "SELECT outcome, metadata FROM audit_events WHERE resource_id=%s "
                               "AND action='response_job.finish'", (str(job_id),))[0]
    assert finish[0] == "allow" and finish[1]["result"] == "succeeded"


def test_failed_playbook_is_dead_lettered_with_its_error_and_files_are_removed(world, ansible_dirs):
    creds, work = ansible_dirs
    job_id = approved_job(world)
    run_with(job_id, FakeAnsible(code=2, out=RECAP_FAILED), creds, work, rounds=1)
    status, _, _, _, result, errors, _, _ = job_row(world, job_id)
    assert status == "dead" and result == {}
    assert len(errors) == 1 and "playbook exit 2" in errors[0]["error"]
    assert list(work.iterdir()) == []
    assert owner_rows(world, "SELECT outcome FROM audit_events WHERE resource_id=%s AND action='response_job.finish'",
                      (str(job_id),))[0][0] == "error"


def test_unreachable_host_is_retried_later(world, ansible_dirs):
    creds, work = ansible_dirs
    job_id = approved_job(world)
    run_with(job_id, FakeAnsible(code=4, out=RECAP_UNREACHABLE), creds, work, rounds=1)
    status, attempts, _, _, _, errors, _, _ = job_row(world, job_id)
    assert (status, attempts, len(errors)) == ("queued", 1, 1)
    assert list(work.iterdir()) == []


def test_missing_hospital_credentials_fail_safely(world, tmp_path):
    job_id = approved_job(world)
    fake = FakeAnsible()
    empty = tmp_path / "no-creds"
    empty.mkdir()
    run_with(job_id, fake, empty, tmp_path, rounds=1)
    assert fake.calls == []                                # nothing ran without a credential
    status, _, _, _, _, errors, _, _ = job_row(world, job_id)
    assert status == "dead" and "no SSH credential" in errors[0]["error"]


def test_medical_asset_is_refused_at_run_time_even_after_approval(world, ansible_dirs):
    creds, work = ansible_dirs
    target = new_asset(world)
    job_id = approved_job(world, target=target)
    with psycopg.connect(world.owner_url) as owner:
        owner.execute("UPDATE assets SET asset_class='mri', monitoring_mode='agentless_medical' "
                      "WHERE tenant_id=%s AND device_name=%s", (CITY, target))
    fake = FakeAnsible()
    run_with(job_id, fake, creds, work, rounds=1)
    assert fake.calls == []
    status, _, _, _, _, errors, _, _ = job_row(world, job_id)
    assert status == "dead" and "IEC 80001" in errors[0]["error"]


def test_a_host_that_is_not_an_asset_at_run_time_is_refused(world, ansible_dirs):
    creds, work = ansible_dirs
    target = new_asset(world)
    job_id = approved_job(world, target=target)
    with psycopg.connect(world.owner_url) as owner:
        owner.execute("DELETE FROM assets WHERE tenant_id=%s AND device_name=%s", (CITY, target))
    fake = FakeAnsible()
    run_with(job_id, fake, creds, work, rounds=1)
    assert fake.calls == []
    status, _, _, _, _, errors, _, _ = job_row(world, job_id)
    assert status == "dead" and "not an asset" in errors[0]["error"]
