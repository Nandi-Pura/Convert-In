# Firewall conversion matrix

All source and target choices continue through `FirewallConfig`, CP0, CP1, exact-target CP2, then the selected renderer. Same-vendor migration has no raw passthrough. No vendor-pair or version-pair translator exists.

| Source | ASA target | FortiGate target | PAN-OS target | SRX target |
|---|---|---|---|---|
| ASA | Generated or review | Generated or review | Generated or review | Generated or review |
| FortiGate | Generated or review | Generated or review | Generated or review | Generated or review |
| PAN-OS | Generated or review | Generated or review | Generated or review | Generated or review |
| SRX | Generated or review | Generated or review | Generated or review | Generated or review |

These outcomes describe architecture and accounting, not full support. Every normalized entity ends as generated, manual review, unsupported, or version not verified. A policy cannot become ready when a required dependency is not generated. Selecting a `VERSION_NOT_VERIFIED` exact target emits nothing. Each legacy renderer remains independently gated by its registered exact key.