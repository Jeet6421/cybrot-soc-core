"""Ansible executor for response jobs.

For each job the executor:
  1. checks the action's playbook against its pinned digest (playbooks.py);
  2. re-validates the target and resolves it inside the job's own hospital (resolve_job_target);
  3. refuses medical equipment (IEC 80001) and targets that are not assets of that hospital;
  4. creates a private workspace (mode 0700) holding ONLY that host's inventory, that hospital's SSH key, and a JSON
     file of extra-vars;
  5. runs ansible-playbook with an argument list (no shell), --limit set to the verified host;
  6. records the outcome from the PLAY RECAP counts, never the raw output (it can contain patient or account details);
  7. overwrites and removes the workspace in a finally block, so nothing is left behind after success or failure.
"""
import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

import playbooks
import worker
from worker import Permanent, Retryable

TIMEOUT = int(os.environ.get("ANSIBLE_TIMEOUT_SECONDS", "600"))
CREDENTIAL_DIR = Path(os.environ.get("ANSIBLE_CREDENTIAL_DIR", "/var/lib/soc/ansible-creds"))
WORKSPACE_DIR = Path(os.environ.get("ANSIBLE_WORKSPACE_DIR", "/var/lib/soc/ansible-work"))
RECAP = re.compile(r"ok=(\d+)\s+changed=(\d+)\s+unreachable=(\d+)\s+failed=(\d+)")


def default_runner(cmd, env, cwd, timeout):
    """Run the command with no shell. Returns (exit code, stdout, stderr)."""
    done = subprocess.run(cmd, env=env, cwd=cwd, capture_output=True, text=True, timeout=timeout, check=False)
    return done.returncode, done.stdout, done.stderr


def resolve_target(conn, job_id):
    row = conn.execute("SELECT resolve_job_target(%s) AS target", (job_id,)).fetchone()
    return row["target"]


def credential_file(tenant, cred_root=None):
    """The hospital's SSH key. The tenant id is validated and the resolved path must stay inside the credential root."""
    if not playbooks.valid_tenant(tenant):
        raise Permanent("invalid hospital identifier")
    root = Path(cred_root or CREDENTIAL_DIR).resolve()
    path = (root / tenant / "ssh_key").resolve()
    if root not in path.parents or not path.is_file():
        raise Permanent("no SSH credential is provisioned for this hospital")
    return path


def _write_private(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)


def shred_and_remove(path):
    """Overwrite each file with random bytes before unlinking it, then remove the directory."""
    path = Path(path)
    if not path.exists():
        return
    for item in path.rglob("*"):
        if item.is_file() and not item.is_symlink():
            try:
                size = item.stat().st_size
                with open(item, "r+b") as fh:
                    fh.write(os.urandom(size))
                    fh.flush()
                    os.fsync(fh.fileno())
            except OSError:
                pass
            item.unlink(missing_ok=True)
    shutil.rmtree(path, ignore_errors=True)


def run_job(job, *, conn, runner=default_runner, cred_dir=None, workspace_root=None):
    """Execute one approved job. Returns the result dict. Raises Permanent or Retryable (the worker records them)."""
    action = job["action_type"]
    try:
        pb = playbooks.playbook_for(action)
        host = playbooks.validate_target(action, job["target_host"])
    except playbooks.TargetRefused as e:
        raise Permanent(str(e))
    try:
        playbook_file = playbooks.verified_path(pb)
    except RuntimeError as e:
        raise Permanent(str(e))

    target = resolve_target(conn, job["job_id"])
    if pb.target == "host" and target is None:
        raise Permanent("target is not an asset of this hospital")
    if target is not None and target["medical"] and pb.tier == "disruptive":
        raise Permanent("blocked: disruptive action on medical equipment (IEC 80001)")

    key = credential_file(job["tenant_id"], cred_dir)

    root = Path(workspace_root or WORKSPACE_DIR)
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    workspace = Path(tempfile.mkdtemp(prefix=f"job-{job['job_id']}-", dir=root))
    os.chmod(workspace, 0o700)
    try:
        inventory = workspace / "inventory.json"
        _write_private(inventory, json.dumps({"all": {"hosts": {host: {"ansible_host": host}}}}).encode())
        extra_vars = workspace / "vars.json"
        _write_private(extra_vars, json.dumps({
            "soc_action": action, "soc_job_id": job["job_id"], "soc_tenant": job["tenant_id"],
            "soc_target": host, "soc_playbook_version": pb.version}).encode())
        keyfile = workspace / "ssh_key"
        _write_private(keyfile, key.read_bytes())
        home = workspace / "home"
        home.mkdir(mode=0o700)
        env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": str(home),
            "ANSIBLE_HOST_KEY_CHECKING": "True",
            "ANSIBLE_PRIVATE_KEY_FILE": str(keyfile),
            "ANSIBLE_LOCAL_TEMP": str(workspace / "tmp"),
            "ANSIBLE_NOCOLOR": "1",
            "ANSIBLE_RETRY_FILES_ENABLED": "False",
            "ANSIBLE_STDOUT_CALLBACK": "default",
        }
        cmd = ["ansible-playbook", "--inventory", str(inventory), "--limit", host,
               "--extra-vars", f"@{extra_vars}", str(playbook_file)]
        try:
            code, out, _err = runner(cmd, env=env, cwd=str(workspace), timeout=TIMEOUT)
        except subprocess.TimeoutExpired:
            raise Retryable("playbook timed out")

        matches = RECAP.findall(out or "")
        if not matches:
            raise Permanent(f"playbook produced no recap (exit {code})")
        ok, changed, unreachable, failed = (int(value) for value in matches[-1])
        if code == 0 and failed == 0 and unreachable == 0:
            return {"exit_code": code, "playbook_id": pb.playbook_id, "playbook_version": pb.version,
                    "playbook_digest": pb.sha256, "recap": {"ok": ok, "changed": changed,
                                                           "unreachable": unreachable, "failed": failed}}
        message = f"playbook exit {code}: ok={ok} changed={changed} unreachable={unreachable} failed={failed}"
        if unreachable and not failed:
            raise Retryable(message)
        raise Permanent(message)
    finally:
        shred_and_remove(workspace)


def executors(connect=None):
    """The action registry for the worker. Each job gets its own database connection for the target check."""
    connect = connect or worker.soc.connect

    def make(action):
        def run(job):
            with connect() as conn:
                return run_job(job, conn=conn)
        return run

    return {action: make(action) for action in playbooks.ALLOWLIST}
