# Wazuh side (not run or tested in the build sandbox - verify on your VM)

1. On the Ubuntu SOC VM: `sudo sysctl -w vm.max_map_count=262144`, install Docker + Compose.
2. Get Wazuh's official single-node Docker setup (github.com/wazuh/wazuh-docker, single-node folder),
   generate certs as its README says, then `docker compose up -d`.
3. Install a Wazuh agent on the Linux/Windows test VMs and confirm they show in the dashboard.
4. Copy `local_rules.xml` into the manager and test with `wazuh-logtest`.
   The Windows tuning rule (100200) is untested: run `wazuh-logtest` on
   `tests/fixtures/wazuh_92213_psscriptpolicy.json`'s event and confirm it is suppressed before relying on it.
5. Add `ossec_integration.xml` to `ossec.conf`, restart the manager. Alerts level 7+ now appear in SOC Core's queue.
6. Use one ingest key per hospital (or per Wazuh manager) and put it in the integration URL as `?token=<ingest key>`. The key decides the hospital; `tenant` in the URL is ignored.
