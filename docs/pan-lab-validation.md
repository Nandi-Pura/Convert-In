# PAN-OS lab validation

Optional validation targets an isolated `LOCAL_FIREWALL` running PAN-OS 11.1. It never commits, deploys, handles NAT, targets Panorama, or accepts credentials through the web UI.

## Evidence result

PAN-OS defines the candidate configuration as the running configuration plus inactive changes made after the last commit. A named candidate snapshot therefore differs from `running-config.xml`: it preserves pre-existing uncommitted work. Saving that snapshot does not activate changes. Activation requires a separate commit, which ConfigMorph forbids.

PAN-OS also documents loading a custom-named candidate snapshot. Revert operations replace settings in the current candidate configuration. Loading the saved pre-validation snapshot restores candidate state; it does not change running configuration unless an optional commit follows. ConfigMorph never issues that commit. `Revert to running configuration` is not an acceptable cleanup path because it discards changes made since the last commit.

The PAN-OS 11.1 XML API operational-command reference supplies these request bodies:

- Full candidate validation: `<validate><full></full></validate>`
- Save configuration: `<save><config><to>filename</to></config></save>`
- Load configuration: `<load><config><from>filename</from></config></load>`

The Configuration API separately documents `action=set` as candidate mutation and `action=get` as candidate retrieval. It does not publish the capability-specific local-firewall XPath and XML element payloads needed to convert `PanSetCommand`. Palo Alto instead documents discovery through the API Browser or `debug cli on` on an actual firewall. ConfigMorph does not infer those trees or send CLI strings to the XML API.

## Lifecycle contract

1. Read the device version. Stop before mutation unless it belongs to PAN-OS 11.1.
2. Retrieve the complete candidate configuration. This includes running state and all pre-existing uncommitted changes.
3. Save it to a generated named snapshot and verify snapshot creation.
4. Apply only provenance-checked ConfigMorph candidate mutations.
5. Run full validation and collect sanitized findings.
6. In unconditional cleanup, load the named pre-validation snapshot.
7. Retrieve candidate configuration again. Compare its canonical transport representation with the pre-validation representation.
8. Report `RESTORED` only on exact equality. Otherwise report `RESTORE_FAILED` or `RESTORE_UNVERIFIED`; never report live success.
9. Delete the temporary snapshot only after an official PAN-OS 11.1 operation is documented and tested.

Cleanup runs after PASS, WARNING, BLOCKING findings, apply failure, partial apply failure, validation failure, and connection failure after mutation may have started. A snapshot-save failure stops before mutation. Pre-existing candidate changes are preserved by restoring the saved candidate snapshot, never by reverting to running configuration.

## Cleanup and error model

Cleanup states: `NOT_REQUIRED`, `RESTORED`, `RESTORE_FAILED`, `RESTORE_UNVERIFIED`. PASS and WARNING require `RESTORED`. Reports include a SHA-256 snapshot-name identifier, snapshot creation, candidate mutation, preservation, restore attempt/success/verification, temporary snapshot disposition, and `commit_performed=false`. Snapshot names and contents never enter reports.

Distinct stage errors: `SNAPSHOT_SAVE_FAILED`, `CANDIDATE_APPLY_FAILED`, `VALIDATION_FAILED`, `RESTORE_FAILED`, `RESTORE_UNVERIFIED`, `VERSION_MISMATCH`, `CONNECTION_ERROR`.

Temporary names use `convert-in-validation-<UTC timestamp>-<128-bit random hex>.xml`. They contain no source filename, customer name, username, host, or secret. The retrieved official pages do not specify a complete filename grammar; the restricted alphanumeric, hyphen, period form is deliberate. Snapshot deletion remains undocumented in the reviewed references. A future live adapter must report `NOT_ATTEMPTED_UNDOCUMENTED` and may leave the sanitized snapshot only in the isolated lab until deletion receives authoritative evidence.

## Transport boundary

Allowed operation categories are `SHOW_VERSION`, `SAVE_CANDIDATE`, `APPLY_CANDIDATE`, `VALIDATE_FULL`, `LOAD_SNAPSHOT`, and `VERIFY_CANDIDATE`. Arbitrary operational-command passthrough is prohibited. Request shapes containing `commit`, `commit-all`, `commit-and-push`, `push`, or `deploy` are rejected.

`FCS_PAN_LAB_VALIDATION_ENABLED=true` and `FCS_PAN_LAB_ISOLATED=true` are both required. The host comes only from `FCS_PAN_LAB_HOST` and must match `FCS_PAN_LAB_HOST_ALLOWLIST`; user input cannot select it. `FCS_PAN_LAB_CA_BUNDLE` is reserved for trusted TLS verification. Credentials and insecure TLS switches remain absent.

## Current safety state

Live transport remains blocked with `VERSION_NOT_VERIFIED`. Save, load, validation, candidate retrieval, and candidate-versus-running semantics have PAN-OS 11.1 evidence. The reviewed public references do not establish these exact local-firewall mutation contracts:

- `/config/devices/entry[...]` device root and selected VSYS addressing;
- address and static address-group entry XPath and element forms;
- TCP/UDP service and service-group entry XPath and element forms;
- local `rulebase/security/rules` entry XPath and field/list element forms;
- legacy virtual-router static-route XPath, including explicit virtual-router selection, next-hop, interface, and metric forms;
- whether repeated `action=set` requests merge list members exactly as the structured renderer requires.

Authoritative closure requires captured PAN-OS 11.1 `LOCAL_FIREWALL` API Browser or debug output for every supported shape, then golden fixtures and fake-transport tests. Temporary snapshot deletion also remains undocumented, but does not weaken restore: snapshots remain in the isolated lab and are reported as `NOT_ATTEMPTED_UNDOCUMENTED`. No `PanXmlMutation` converter or network client exists. Standard CI uses fake lifecycle transports only.

## O.5 evidence capture

No lab runtime inputs were available during O.5 tooling work. No device connection or capture occurred. `python -m app.tools.pan_lab_capture` prepares one local evidence record and performs no network request. It requires the three opt-ins, an HTTPS origin, an existing CA bundle, and one fixed `--capture` value. The host is validated but never written. `evidence/pan11_1_lab/` is ignored in full; raw and normalized records require manual sanitization and review before any derived fixture enters Git.

Operator sequence:

1. Confirm an authorized, isolated PAN-OS 11.1.x `LOCAL_FIREWALL`; record model and VSYS inventory. Stop on any other version or active candidate editor.
2. Retrieve and retain the normalized candidate state. Save and verify `convert-in-o5-evidence-<timestamp>` before mutation.
3. Set `FCS_PAN_LAB_VALIDATION_ENABLED=true`, `FCS_PAN_LAB_ISOLATED=true`, and `FCS_PAN_LAB_EVIDENCE_CAPTURE=true`. Keep credentials in the operator's runtime only.
4. Run the helper for one fixed experiment, for example `python -m app.tools.pan_lab_capture --capture address --host https://pan-lab.example --ca-bundle C:\\path\\to\\lab-ca.pem`.
5. Capture exact API Browser or `debug cli on` output. Disable debug output after each CLI capture. Preserve paths unchanged. Record explicit payload fields separately from retrieved defaults.
6. For list fields, capture before/after state for one multi-member `action=set` and repeated one-member `action=set` calls. Record merge, replacement, append, duplicate, normalization, and ordering outcomes without inference.
7. Load the saved candidate snapshot. Compare normalized candidate state with the pre-capture state. Stop with `RESTORE_UNVERIFIED` on mismatch. Do not delete the snapshot; record `NOT_ATTEMPTED_UNDOCUMENTED`.
8. Redact hostname, serial, management IP, API key, username, MAC addresses, and real interface addresses. Mark a record `DEVICE_CAPTURED` only after review confirms PAN-OS 11.1.x, exact XPath/XML, response, method, and sanitization.

Allowed experiments: `address`, `address-group`, `service`, `service-group`, `security-rule`, `static-route`, and `list-semantics`. The helper has no arbitrary XML mode, API client, retry, commit, move, deployment, Panorama, NAT, or PAN-OS 12.1 path.

## Official PAN-OS 11.1 references

- `PANOS-11.1-MANAGE-BACKUPS`: [Manage Configuration Backups](https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-admin/firewall-administration/manage-configuration-backups)
- `PANOS-11.1-SAVE-CANDIDATE`: [Save and Export Firewall Configurations](https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-admin/firewall-administration/manage-configuration-backups/save-and-export-firewall-configurations)
- `PANOS-11.1-LOAD-SNAPSHOT`: [Revert Firewall Configuration Changes](https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-admin/firewall-administration/manage-configuration-backups/revert-firewall-configuration-changes)
- `PANOS-11.1-XML-API-OP`: [Run Operational Mode Commands (API)](https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-panorama-api/pan-os-xml-api-request-types/run-operational-mode-commands-api)
- `PANOS-11.1-XML-API-CONFIG`: [PAN-OS XML API Request Types and Actions](https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-panorama-api/pan-os-xml-api-request-types/configuration-api)
- `PANOS-11.1-XML-API-BROWSER`: [Use the API Browser](https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-panorama-api/get-started-with-the-pan-os-xml-api/explore-the-api/use-the-api-browser)
- `PANOS-11.1-XML-CLI-DISCOVERY`: [Use the CLI to Find XML API Syntax](https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-panorama-api/get-started-with-the-pan-os-xml-api/explore-the-api/use-the-cli-to-find-xml-api-syntax)
- `PANOS-11.1-CLI-VALIDATE`: [Commit Configuration Changes](https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-cli-quick-start/use-the-cli/commit-configuration-changes)
- `PANOS-11.1-CLI-LOAD-TEXT`: [Load Configuration Settings from a Text File](https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-cli-quick-start/use-the-cli/load-configurations)