# Ansible execution: deployment model and controls

Approved responses run as Ansible playbooks from the `worker` service. This document records how that is deployed and
which controls protect it. It applies to PR 11 and later.

## Deployment model (chosen)

- **Where it runs:** the `worker` container. It uses the same image as the app, with `ansible-core` pinned in
  `requirements.txt`. It connects to PostgreSQL as `soc_app` (no DDL, no owner rights).
- **Isolation per job:** each job gets its own workspace directory under `ANSIBLE_WORKSPACE_DIR`, mode 0700, on a
  `tmpfs` mount. The workspace holds only that job's inventory, that hospital's key, and a vars file. It is removed in
  a `finally` block after success, failure or timeout. Files are overwritten with random bytes before removal.
- **No shell:** `ansible-playbook` runs with an argument list. Nothing is interpolated into a shell string.
- **Least privilege:** the worker container is read-only, has all Linux capabilities dropped, sets
  `no-new-privileges`, and runs as UID 10001. Its only writable paths are `/tmp` and the workspace `tmpfs`.
- **Credentials:** one folder per hospital in the read-only named volume `ansible-creds`, at `<tenant>/ssh_key`. The
  app never writes to it. The tenant id is validated, and the resolved path must stay inside the credential root.
- **Why not a container per job:** a container per job needs the Docker socket, which is root on the host. Workspaces
  plus the restrictions above give per-job isolation without that exposure. If the site requires a container per job,
  the executor's `runner` is the single place to change.

## Target and inventory rules

- Analysts choose an **action**. The server maps it to one approved playbook (`playbooks.py`). Playbook paths, extra
  arguments and inline code are not accepted from clients.
- Targets are validated against strict patterns (host names, IP addresses, account names). Path separators, spaces,
  braces and shell characters are refused.
- The inventory for a job contains **one host**: the target after it is resolved inside the job's own hospital
  (`resolve_job_target`). `--limit` is set to that same host.
- Cross-hospital targets never resolve. The request, the approval, and the execution each check this.

## Medical-device safety (IEC 80001)

Disruptive containment is refused for any asset whose class is `mri`, `ct`, `x_ray`, `ultrasound`, `ventilator`,
`patient_monitor` or `infusion_pump`, or whose monitoring mode is `agentless_medical`. The check runs at three points:

1. when the response is requested (409),
2. when it is approved (409, the approval is not recorded),
3. when the worker is about to run it (the job is dead-lettered with the reason).

The second and third checks catch an inventory change made after the request.

## Maker-checker

- A disruptive action is created as `pending_approval`.
- Only a hospital admin or an L2 analyst can approve or reject it. An L1 analyst cannot.
- The requester can never approve their own request. The database enforces this with `requested_by <> approved_by`.
- Approval moves the job to `queued`. Rejection moves it to `rejected`. Neither can be reversed.

## Audit

Each step writes an `audit_events` row in the same transaction as the state change:

| Step | Action | Written by |
| --- | --- | --- |
| request | `response_approval.request`, `response_job.request` | app, same transaction |
| approval | `response_approval.decision`, `response_job.queue` | app, same transaction |
| rejection | `response_approval.decision`, `response_job.reject` | app, same transaction |
| start | `response_job.start` | `claim_response_jobs`, same transaction |
| finish | `response_job.finish` (outcome `allow` or `error`) | `finish_response_job`, same transaction |

The audit rows hold no raw playbook output, hostnames beyond the job reference, or key material.

## Results and errors

`response_jobs.result` keeps the exit code, playbook id and version and digest, and the PLAY RECAP counts. It never
keeps the raw output, which can include patient or account details. `response_jobs.errors` keeps short messages.

## Changing a playbook

A playbook is approved by its digest. To change one:

1. Edit the file under `ansible/playbooks/`, and bump the `version` in `playbooks.py`.
2. Compute the new digest: `sha256sum ansible/playbooks/<file>`, and set it in `ALLOWLIST`.
3. Get the change reviewed. The test `test_the_playbook_allowlist_is_pinned_by_digest` fails until the pin matches.

The shipped playbooks **fail on purpose** (`ansible.builtin.fail`). They contain no isolation, account or firewall
module, because those are specific to each site and product. A site replaces the failing task with its approved module
and then re-approves the change. A playbook that reports success without doing anything would tell an analyst a host
was contained when it was not.

## Provisioning a hospital's credentials

On the Docker host, populate the volume (outside the app):

```
docker run --rm -v soc-core_ansible-creds:/creds -v "$PWD/keys:/src:ro" alpine \
  sh -c 'mkdir -p /creds/city-hospital && cp /src/city-hospital.key /creds/city-hospital/ssh_key && chmod 0400 /creds/city-hospital/ssh_key'
```

The key should belong to a dedicated automation account with the minimum rights for the approved modules. Rotate it
through the same procedure.
