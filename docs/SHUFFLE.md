# Connecting Shuffle to SOC Core (playbooks)

SOC Core sends each new alert to `PLAYBOOK_WEBHOOK` as signed JSON. Shuffle receives the alert through a webhook
trigger, checks the signature, and runs a playbook. This guide covers installing Shuffle, locking it down,
connecting it, and testing the chain. Install steps follow Shuffle's official guide:
https://github.com/Shuffle/Shuffle/blob/master/.github/install-guide.md

## Before you start

- **Own VM.** Shuffle needs at least 4 GB of RAM and Docker. Install it on a separate VM from SOC Core, so a
  problem in Shuffle cannot stop the SOC pipeline. Check the RAM with `free -h`.
- **Pin a release.** Use a tagged Shuffle release, not `master`, on any system that matters. Find the latest tag at
  https://github.com/Shuffle/Shuffle/releases and check it out in step 1.
- **Read the production guide.** Shuffle's official guide says its default setup is not scalable and points to
  https://shuffler.io/docs/configuration for production settings.

## 1. Install Shuffle (on its own VM)

    git clone https://github.com/Shuffle/Shuffle
    cd Shuffle
    git checkout <release-tag>
    mkdir -p shuffle-database
    sudo chown -R 1000:1000 shuffle-database      # if this fails, run: sudo useradd opensearch, then retry
    sudo swapoff -a
    docker compose up -d
    sudo sysctl -w vm.max_map_count=262144        # needed by OpenSearch
    echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf   # keeps the setting after a reboot

Shuffle's web UI is then at `https://<shuffle-vm-ip>:3443`. Port 3001 serves HTTP.

## 2. Lock it down

- **Create the admin account yourself.** Shuffle has no default username or password. Use a strong, unique password.
- **Limit the network.** Allow only the admin machine and the SOC Core VM to reach the Shuffle ports. Example for the
  lab subnet, run on the Shuffle VM:

      sudo ufw allow from 192.168.56.0/24 to any port 3443 proto tcp
      sudo ufw enable

  In production, use the specific IP addresses, not a whole subnet.
- **Use a certificate SOC Core trusts.** SOC Core verifies the TLS certificate of the webhook. A self-signed certificate
  makes every delivery fail with a `URLError`. Use a certificate from your internal CA, or put Shuffle behind a
  reverse proxy with a trusted certificate. (If you must use a self-signed certificate, tell me and we will add
  support for a CA file.)
- **Keep the secret out of workflows as plain text.** Store `PLAYBOOK_SECRET` in Shuffle's secrets or variables if your
  version has them.

## 3. Create the webhook in Shuffle

1. Log in to Shuffle and create a new workflow for alerts.
2. Add a **Webhook** trigger. Copy the URL that Shuffle shows. Copy it from the UI rather than building it by hand,
   because the path depends on the Shuffle version.
3. Add a **Python** step (or your version's custom code step) that runs the check in section 4 first. The playbook
   actions come after that check, and a failed check stops the run.
4. Save the workflow and start it.

## 4. Check every request

`shuffle/verify_alert.py` in this repository holds the checks. It is covered by `tests/test_shuffle_verify.py`.
Paste the file into the Python step, then call:

    ok = verify(secret, headers["X-Cybrot-Timestamp"], raw_body, headers["X-Cybrot-Signature"])
    if ok and dedupe.first_time(headers["X-Cybrot-Event-Id"]):
        ...run the playbook...
    else:
        ...stop the run...

- `raw_body` must be the exact bytes SOC Core sent. If a step parses the JSON and sends it on again, the bytes change
  and the check fails. Test with one alert before you rely on it.
- The checks reject a request whose timestamp is more than 5 minutes away from the current time (replay protection).
- `DedupeLog` keeps its ids in memory, so it resets when the worker restarts. For production, store the ids in
  Shuffle's datastore, or check the alert id in SOC Core before acting.

## 5. Connect SOC Core

On the SOC Core VM, add these two lines to `.env` (the webhook URL from step 3, and the secret the Shuffle step uses):

    PLAYBOOK_WEBHOOK=<the webhook URL copied from Shuffle>
    PLAYBOOK_SECRET=<the same secret>

Then restart the container:

    docker compose up -d

Generate the secret on the VM with `python3 -c "import secrets; print(secrets.token_hex(32))"`, keep it out of chat and
tickets, and put the same value in Shuffle.

## 6. Test

1. Send one test alert, using the same `curl` command as in the earlier VM tests.
2. In Shuffle, check that the workflow ran, and that `verify` returned `True`.
3. Call `verify` with a wrong secret, or change a character in the body. It must return `False`, and the playbook
   must not run.
4. Send the same alert again. The second run must stop at the duplicate check.

## 7. Troubleshooting

| Symptom | Likely cause |
|---|---|
| `playbook webhook failed: HTTP 404` in `docker compose logs` | The URL is wrong, or the workflow is not running. Copy the URL again from Shuffle. |
| `playbook webhook failed: HTTP 401` or `403` | Shuffle rejected the request. Check any authentication set on the webhook trigger. |
| `playbook webhook failed: URLError` | SOC Core cannot reach Shuffle, or the certificate is not trusted. Check the network, then the certificate. |
| `verify` always returns `False` | The Shuffle step changed the raw body, the secret differs, or the VM clocks are more than 5 minutes apart. |
| Shuffle install stops at `docker compose up` | Check RAM (4 GB minimum), and that `vm.max_map_count` is set. |
