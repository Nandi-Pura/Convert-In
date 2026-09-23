# Unified workbench

The root route uses one three-card workspace without a sidebar:

1. **Import Config** accepts a local file or pasted configuration, limited to 5 MiB.
2. **Select Platform** confirms the detected source and verified OS version. Firewall sources expose PAN-OS 11.1 conversion. Cisco IOS-XE 17.12.1 exposes analysis only.
3. **Configuration Comparison** presents source, normalized or target output, checkpoint status, and findings by entity.

## Entity safety

- **READY** firewall entities have renderer-attributed commands and may be copied.
- **REVIEW REQUIRED** and **BLOCKED** entities cannot be copied.
- NAT remains non-generated and non-copyable.
- **Copy Selected** and **Copy All READY** preserve dependency order.
- **Download Candidate** contains the complete evidence-gated PAN-OS candidate. It remains a candidate configuration requiring engineer review.
- IOS-XE rows expose CP0 and CP1 analysis only. No target, renderer, candidate, or copy action is implied.

Filters, search, and row expansion operate locally in the browser. Configuration processing remains local. The previous workflow remains at `/advanced`.

## Screenshots

- `docs/images/workbench-firewall.png`: synthetic FortiGate conversion review.
- `docs/images/workbench-iosxe.png`: synthetic IOS-XE analysis review.