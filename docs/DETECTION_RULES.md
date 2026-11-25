# Hospital SOC Detection Rules

This document records the first pilot implementation of the detection roadmap. The rules create alerts only. They do not isolate devices, change firewall policy, or modify clinical systems. The thresholds and event mappings are starting points for synthetic validation; each hospital must confirm telemetry, normal activity, exceptions, and clinical impact before production use.

## Pilot rules

| Rule | Priority | Severity | Required normalized event | Logic | Main tuning risk |
|---|---|---|---|---|---|
| HC-END-001 Ransomware-like file activity | P1 | Critical | `file_rename`, `file_modify`, or `file_delete`; `host`; distinct file path in `detail` | 50 or more distinct paths on one host within 5 minutes | Imaging, backup, and software deployment jobs can change many files. Review host baselines and raise or lower the threshold only after replay tests. |
| HC-END-004 Security tool tampering | P1 | High | `security_agent_stopped`, `security_agent_disabled`, `security_agent_config_changed`, or `edr_configuration_changed`; `host`; optional `approved_change` | Alert on a listed event unless the trusted source marks the change approved | Agent upgrades and maintenance. The approval marker must come from an approved change feed, not an analyst-supplied event field. |
| HC-DLP-002 Sensitive data to an unapproved destination | P1 | High | `data_transfer`; `data_classification`; `destination`; `destination_approved`; `host` or `user` | Alert when classification is `phi`, `patient_data`, or `sensitive` and destination approval is explicitly false | Classification and destination allowlists must be verified. Unknown classification or approval state does not alert and should be measured as a telemetry gap. |
| HC-OPS-002 Backup failure or deletion | P1 | High | `backup_job_failed`, `backup_repository_deleted`, or `backup_retention_changed`; `host`; optional `approved_change` | Alert on repository deletion or retention change unless approved; alert on 3 failed jobs for one host within 24 hours | Scheduled maintenance and transient storage faults. Correlate with the approved backup schedule and change feed. |
| HC-MED-004 Clinical network segmentation violation | P1 | High | `network_flow` or `network_boundary_violation`; `src_zone`; `dst_zone`; `boundary_violation` | Alert when the trusted network policy feed marks a flow as a boundary violation and both zones are present | Approved clinical integrations and emergency paths. Validate policy context with hospital IT and biomedical engineering. |
| HC-AUD-001 Security or audit log tampering | P1 | High | `audit_log_cleared`, `audit_service_stopped`, `log_forwarding_disabled`, or `audit_config_changed`; `host`; optional `approved_change` | Alert on a listed event unless the trusted source marks the change approved | Planned maintenance and collector migrations. Monitor collector health separately so loss of telemetry is visible. |

Rule identifiers and severity follow the supplied healthcare detection report. HC-END-001 uses an initial threshold of 50 paths in 5 minutes and HC-OPS-002 uses 3 failed jobs in 24 hours. These are prototype values, not validated hospital baselines. The active constants are in `detect.py`.

All six records are version `0.1.0`, status `pilot`, and priority `P1`. The rule owner is the hospital SOC detection owner and must be assigned during tenant onboarding. No ATT&CK mapping is added until the team validates a technique for the exact telemetry and behavior; a broad use-case label is not enough evidence for a mapping. The `rule_version` is persisted with each alert.

## Event contract

Every event still requires `ts`, `tenant`, `source`, and `type`. The ingest API now also stores these optional fields for the pilot rules:

- `destination`, `data_classification`, and `destination_approved` for data transfers.
- `src_zone`, `dst_zone`, and `boundary_violation` for clinical network flows.
- `approved_change` for backup, endpoint protection, and audit changes.
- Existing `host` and `detail` fields identify the affected system and file path.

Hospital-specific connectors must normalize their source events into this contract. Missing context should be reported as a coverage gap; it should not be guessed from free-text summaries. `approved_change`, `destination_approved`, and `boundary_violation` must be derived by trusted connector logic from an authoritative policy or change source.

## Validation and rollout

Each rule should have positive, negative, and boundary replay cases. Include approved maintenance, benign clinical workloads, missing fields, duplicate events, and events just below and above the threshold. Keep a versioned record of source mapping, owner, test results, false positives, exceptions, expiry, and approvals.

Deploy in alert-only mode to a limited pilot. Review alert volume, precision, test recall, log-source coverage, validation pass rate, mean time to detect, and processing load with the hospital SOC lead. Do not enable active containment for clinical or medical-device assets without approval from hospital IT and biomedical engineering. Roll back by reverting the rule version and connector mapping, then replay the saved positive and negative cases.

## Deferred catalogue items

The report's remaining rules need hospital-specific identity status, care-team context, asset inventories, approved vendor windows, application audit schemas, mail/cloud audit, database telemetry, or network baselines. They are not represented as detections until those fields and their authoritative sources are agreed. Existing `FAILED_LOGIN_BURST`, `BULK_RECORD_ACCESS`, `OFFHOURS_ACCESS`, and `SUSPICIOUS_PROCESS` remain prototype rules; they are not substitutes for the report's full IAM, EHR, endpoint, or audit use cases.
