# Connecting Shuffle to SOC Core (playbooks)

SOC Core sends each new alert to `PLAYBOOK_WEBHOOK` as JSON. Shuffle receives the alert through a webhook
trigger and runs a playbook from it. This guide covers the SOC Core side, the signature check, and a test.
Shuffle itself is installed separately, on its own host or VM, following Shuffle's own documentation.

## 1. What SOC Core sends

Each request is an HTTPS-style POST with a JSON body:

    {"event": "alert.created",
     "alert": {"id": 12, "created": "...", "tenant": "city-hospital", "rule": "SUSPICIOUS_PROCESS",
               "severity": "critical", "summary": "...", "owner": "analyst1", "step": "...",
               "detail": "...", "attack_id": null, "source": "builtin"}}

Headers:

| Header | Meaning |
|---|---|
| `X-Cybrot-Event-Id` | `alert-<id>`. The same on every retry, so use it to drop duplicates. |
| `X-Cybrot-Timestamp` | Unix time in seconds when the request was sent. |
| `X-Cybrot-Signature` | `sha256=<hex>`, present only when `PLAYBOOK_SECRET` is set. |

Delivery: up to 3 attempts. Server errors and network errors are retried after 1 s and 2 s. A 4xx reply is not
retried. The request times out after `PLAYBOOK_TIMEOUT` seconds (default 3).

## 2. Set up the receiver in Shuffle

1. In Shuffle, create a new workflow for alerts.
2. Add a **webhook trigger** and copy its URL.
3. Add a **Python step** (or your Shuffle version's equivalent) that verifies the signature, then runs the playbook.
   The verification code is in section 3.
4. Put the URL in SOC Core's `.env`, together with a long random secret:

       PLAYBOOK_WEBHOOK=https://<shuffle-host>/api/v1/hooks/<webhook-id>
       PLAYBOOK_SECRET=<a long random value, e.g. from: python3 -c "import secrets; print(secrets.token_hex(32))">

   Generate the secret on the VM, keep it out of chat and tickets, and use the same value in Shuffle.
5. Restart SOC Core: `docker compose up -d`.

## 3. Verify the signature in Shuffle

Verification needs the exact bytes that SOC Core sent. If a Shuffle step parses the JSON and sends it on
again, the bytes change and the check will fail. Check the raw body before relying on it.

    import hashlib, hmac, time

    def verify(secret, timestamp, raw_body, signature):
        if abs(time.time() - int(timestamp)) > 300:      # reject old requests (replay protection)
            return False
        expected = "sha256=" + hmac.new(secret.encode(), f"{timestamp}.".encode() + raw_body,
                                        hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, signature)

Also drop a repeat when `X-Cybrot-Event-Id` has already been handled. Keep the ids for at least 24 hours.

## 4. Test it

1. Run one test event, as in the playbook test on the VM.
2. In Shuffle, check that the workflow started and that `verify(...)` returned `True`.
3. Change the secret in Shuffle, then send another event. The check should now return `False`, which shows
   the signature is being enforced. Put the correct secret back.

## 5. Troubleshooting

| Symptom | Likely cause |
|---|---|
| `playbook webhook failed: HTTP 404` in `docker compose logs` | The Shuffle URL is wrong or the workflow is not running. |
| `playbook webhook failed: HTTP 401` or `403` | Shuffle rejected the request. Check any auth set on the webhook trigger. |
| `playbook webhook failed: URLError` | SOC Core cannot reach the Shuffle host. Check the VM's network and DNS. |
| Verification always fails | The Shuffle step re-serialized the JSON, or the secret differs. Compare the raw body. |
