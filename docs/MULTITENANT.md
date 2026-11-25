# Multi-tenant SOC Core (design)

Status: proposed. Target version: v1.0.

Each hospital runs its own SOC analysts and its own alert queue on one shared SOC Core. Hospitals' data must stay separate, and no hospital can read or change another hospital's data.

## Decisions

| Topic | Decision |
|---|---|
| Data isolation | One database. Every row carries a `tenant_id`. Every query is filtered by it, and tests prove the filter holds. |
| Login | Per-user accounts. Passwords hashed with scrypt (Python standard library). |
| Second factor | Required for every user. Time-based one-time codes (TOTP, RFC 6238), as used by standard authenticator apps. |
| Who sees alerts | Each hospital's own analysts. Cybrot platform admins manage hospitals and users, but do not read alert data by default. |
| Analysts | Per hospital, taken from that hospital's user accounts. Replaces the single global `ANALYSTS` list. |

## Gaps in v0.9 (from code review)

1. **The tenant comes from the request.** `?tenant=` on Wazuh ingest, and the Wazuh agent group, decide which hospital an alert belongs to. Any caller can write to, or read from, any hospital. This is the most serious gap.
2. **One shared API token.** Nobody is identified, so actions cannot be traced to a person.
3. **Settings and metrics are global.** The false-positive target, exit gates, analyst list and playbook webhook apply to all hospitals.
4. **Reset deletes everything**, for every hospital.
5. **One dashboard view for all.** There's no login and no per-hospital view.

## Roles

| Role | Scope | Can do |
|---|---|---|
| Platform admin (Cybrot) | All hospitals, no alert data | Create hospitals and users, set each hospital's settings and ingest keys |
| Hospital admin | Own hospital | Manage its users, ingest keys and settings |
| SOC analyst | Own hospital | View alerts, acknowledge, close with a verdict, hand off |
| Viewer | Own hospital | Read only |

Read-only access for Cybrot to hospital alerts is not included. It can be added later, with every access written to the audit log.

## Phases

### Phase 1: Tenant data and ingest security (closes gap 1)
- Add a `tenants` table. Add `tenant_id` to events, alerts and handoffs. Move existing data into a `default` tenant.
- Each hospital gets its own ingest key. The key is random and stored as a hash. Wazuh and event ingest authenticate with the key, and the tenant comes from the key, not from the request.
- Scope every query by tenant.
- Tests: a key for hospital A cannot read or change hospital B's data.
- Limit reset to lab mode and the platform admin.

### Phase 2: Users, roles and MFA (closes gap 2)
- Tables for users and memberships (user, hospital, role).
- Password login, then a TOTP code. Short-lived session tokens. Logout. Lock an account after repeated failures.
- Check the role on every endpoint. Tests for each role.
- Audit log: logins, MFA failures, acknowledgements, verdicts, handoffs, user and key changes. Each entry records who, what, when and which hospital.

### Phase 3: Per-hospital settings (closes gap 3)
- Analysts, false-positive target, exit gates, playbook webhook and playbook secret are set per hospital.
- Metrics are computed per hospital. The platform admin sees a list of hospitals and their status only.

### Phase 4: Dashboard
- Login and MFA screens.
- Each hospital sees only its own queue. Hospital admins manage their own users.
- Platform admin sees the hospital list and onboarding status.
- Hide the lab buttons outside lab mode.

### Phase 5: Operations and compliance (before any real patient data)
- HTTPS through a reverse proxy. Secrets kept out of the repository.
- Backups, with a restore test for each hospital's data.
- Retention periods agreed with each hospital's compliance team. The DPDP Act and CERT-In rules apply in India, and CERT-In requires certain logs to be kept in India.
- HIPAA review, penetration test, and an incident runbook.

## Open questions for the team
- Which hospitals join the pilot, and how many users does each have?
- How long should alerts and logs be kept?
- Hosting for the pilot: one VM, as now, or a cloud provider (which needs a Business Associate Agreement)?

## Not in this design
- Hospital-facing reports and PDF export.
- A hospital portal for patients.
- Billing and plan-based feature limits.
