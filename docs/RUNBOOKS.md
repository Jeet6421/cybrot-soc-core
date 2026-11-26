# Runbooks

These procedures are for the people who run the SOC. Each step names the API route or screen it uses, and the role that may do it. Use the dashboard where it has a control; the API is the same action.

## 1. Onboard a hospital (reference: 100 beds)

Reference profile: one acute-care hospital, about 100 beds, with a radiology department, an ED, an ICU, and an IT team of three to five people.

1. **Create the hospital (vendor).** `POST /api/tenants` with `id` and `name`. The id is lowercase letters, digits and dashes.
2. **Create the users (hospital admin).** `POST /api/users` for each person: `hospital_admin` for the IT lead, `l1` and `l2` for analysts, `viewer` for managers. Give each person a unique password. Do not share accounts.
3. **Register log sources (hospital admin).** `POST /api/log-sources` once per feed, for example `ehr-wazuh`, `ad-logins`, `firewall`. Disable a feed you no longer use rather than deleting it.
4. **Inventory the assets (hospital admin).** `POST /api/assets` per device. Use the criteria below:
   - Clinical equipment (`mri`, `ct`, `x_ray`, `ultrasound`, `ventilator`, `patient_monitor`, `infusion_pump`) is **`agentless_medical`**. Never install an agent on it. The API refuses any other mode for these classes.
   - Workstations and servers in corporate networks are `edr_managed` when the agent is installed.
   - Network gear is `network_infra`. Anything else you cannot manage is `unmanaged`, with a note.
   - Set `criticality` (`low` to `critical`). Radiology and ICU devices are `critical`.
   Typical 100-bed inventory: about 6 to 12 imaging devices, 2 to 4 ventilators or monitoring hubs, about 80 to 120 workstations, 10 to 20 servers, and the network estate.
5. **Issue an ingest key per feed (hospital admin).** `POST /api/credentials` with `log_source_id`. The response shows the secret **once**. Copy it into the sender's configuration. Only its hash is stored; the list shows `key_prefix` only.
6. **Verify the data flow (hospital admin).** `GET /api/data-flow`. Confirm each source shows a recent `last_seen_event_ts`, `accepted_24h` is greater than zero, and `readiness.normalized` equals `readiness.checked`. A source that never arrives is a configuration fault, not a quiet day.

**Rotation (every 90 days, or at once after a suspected leak).** `POST /api/credentials/<id>/rotate` with `overlap_minutes`. Use 60 by default, so the sender can switch to the new key without a gap. Then `POST /api/credentials/<old id>/revoke` once the sender uses the new key. Use `overlap_minutes: 0` for a leak: the old key stops at once, and the sender will stop until you give it the new key.

## 2. Intra-tenant handoffs

A handoff passes an open alert to another active analyst **of the same hospital**.

1. Open the alert and choose **Hand off**. The dashboard lists active analysts from `GET /api/analysts`.
2. The request carries `to_actor_id` (the analyst's user id) and a note. The note says what the next owner should do.
3. The API refuses a target that is not an active `l1`, `l2` or `hospital_admin` of this hospital (400). The database enforces the same rule, so a direct write cannot bypass it.
4. A handoff to yourself, to a disabled user, or to a user of another hospital is refused.
5. The alert's owner and the handoff history update together. The history keeps the hospital, both users and the note.

`to_owner` (a name) is retired. Old clients receive 400 and should send `to_actor_id`.

## 3. Vendor break-glass (support access to hospital data)

The vendor cannot see a hospital's data without the hospital's approval. The flow has three steps:

1. **Request (vendor).** The vendor requests a grant for a hospital, with a scope (`alerts:read` by default), a ticket reference, and a time-to-live.
2. **Approve (hospital admin).** The hospital admin reviews the request and approves or rejects it. Approval is the only way a grant becomes active.
3. **Use and revoke.** The vendor reads within the scope until the grant expires. The hospital admin can revoke it at any time. Every read, approval and revocation is written to the audit trail.

Grants do not carry standing access: when the time-to-live passes, the grant stops working without any action. Review active grants in the audit trail at each support ticket's close.

## 4. Offboard a hospital

Offboarding moves a hospital through three states: `active`, then `offboarding`, then `archived`, then `purged`. Each step needs the one before it. The database refuses any other order.

**Step 1: start (hospital admin).** `POST /api/offboarding/start`. This:
- disables every user's login and advances their session version, so existing sessions stop;
- revokes every ingest key, so senders are refused (401);
- stops new writes for the hospital (409 on any change).

Once logins are disabled, nobody at the hospital can read the data. Take any handover copy before you start, or use the export in step 2.

**Step 2: export (vendor).** `POST /api/tenants/<id>/offboarding/export`. This returns the record counts and a SHA-256 digest of the export, and writes a `tenant.export` audit row. Hand the export to the hospital's compliance contact and keep the digest with it. Archive is refused until an export exists.

**Step 3: archive (vendor).** `POST /api/tenants/<id>/offboarding/archive`. The hospital's data is read-only and retained for the agreed period.

**Step 4: purge (vendor).** `POST /api/tenants/<id>/offboarding/purge`, only after the retention period and the hospital's written instruction. Purge removes events, alerts, handoffs, assets, log sources, keys and sessions, and anonymises users. The audit trail is kept: `tenant.offboarding.start`, `tenant.export`, `tenant.archive` and `tenant.purge` remain as the record of what happened. The tenant becomes `purged` and cannot be reused.

Check after each step: `GET /api/tenants` (vendor) shows the `lifecycle_state`. A hospital that is not `purged` must still meet the retention rules in its contract.
