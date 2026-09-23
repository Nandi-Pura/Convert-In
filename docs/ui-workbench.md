# Unified workbench

The root route uses one three-card workspace without a sidebar:

1. **Import Config** accepts a local file or JSON-transported paste, limited to 100 MiB by UTF-8 byte length.
2. **Select Platform** provides independent source and target vendor, platform, and version controls. Targets remain in the source domain.
3. **Configuration Comparison** presents source, normalized or target output, checkpoint status, and findings by entity.

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