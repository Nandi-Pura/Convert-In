# Unified workbench

The root route uses a compare-first migration workbench. A compact source and target context row leads to checkpoint assurance, investigation tabs, and a full-height three-pane comparison workspace. Configuration import accepts a local file or paste, limited to 100 MiB by UTF-8 byte length. Source and target profiles remain independent registry selections within one domain.

Investigation modes are **Semantic Diff**, **Raw Comparison**, **Findings**, **Migration Plan**, and **Evidence**. Raw Comparison presents source configuration, candidate target output, and entity-level migration status. Focus mode hides context and assurance rows without invoking browser fullscreen.

Line accounting uses unique source provenance anchors. READY anchors count as converted, review outcomes count as review required, blocked outcomes count as not supported, and all unanchored source lines count as unchanged or other. Safety precedence prevents duplicate accounting. The method is identified as `UNIQUE_PROVENANCE_ANCHORS_V1`; it does not claim complete source ranges where parsers expose only entity anchor lines.

## Entity safety

- **READY** firewall entities have renderer-attributed commands and may be copied.
- **REVIEW REQUIRED** and **BLOCKED** entities cannot be copied.
- NAT remains non-generated and non-copyable.
- **Copy Selected** and **Copy All READY** preserve dependency order.
- **Download Candidate** contains the complete evidence-gated PAN-OS candidate. It remains a candidate configuration requiring engineer review.
- IOS-XE 17.12.1 to Junos 23.4R2 runs bounded CP2 and rendering. Unmapped interfaces, VRFs, route policies, BGP, and OSPF remain non-copyable.

Source changes clear all results. Target changes clear target output, CP2, candidate, and copy state. Filters, search, and row expansion operate locally in the browser.

## Screenshots

- `docs/images/workbench-firewall.png`: synthetic FortiGate conversion review.
- `docs/images/workbench-iosxe.png`: synthetic IOS-XE analysis review.