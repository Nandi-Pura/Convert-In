# Firewall semantic coverage audit

Audit date: 2026-09-21. Release existence does not establish command semantics. The references in `docs/vendor-reference/` prove existing bounded renderer subsets, not every Q12 capability below. No Q12 row enables command emission. `REVIEW` means the normalized construct remains visible and requires engineer review.

| Capability | Vendor | Exact Version | Evidence State | Renderer State | User Outcome |
|---|---|---:|---|---|---|
| Interface/zone context | Cisco ASA | 9.24 | VERSION_NOT_VERIFIED | non-emitting | REVIEW |
| Disabled rules | Cisco ASA | 9.24 | VERSION_NOT_VERIFIED | non-emitting | REVIEW |
| ICMP | Cisco ASA | 9.24 | VERSION_NOT_VERIFIED | non-emitting | REVIEW |
| Source-port handling | Cisco ASA | 9.24 | VERSION_NOT_VERIFIED | non-emitting | REVIEW |
| Multiple service ranges | Cisco ASA | 9.24 | VERSION_NOT_VERIFIED | non-emitting | REVIEW |
| Nested groups | Cisco ASA | 9.24 | VERSION_NOT_VERIFIED | non-emitting | REVIEW |
| FQDN objects | Cisco ASA | 9.24 | VERSION_NOT_VERIFIED | non-emitting | REVIEW |
| Basic IPv6 objects | Cisco ASA | 9.24 | VERSION_NOT_VERIFIED | non-emitting | REVIEW |
| Logging semantics | Cisco ASA | 9.24 | VERSION_NOT_VERIFIED | non-emitting | REVIEW |
| Schedules/time-ranges | Cisco ASA | 9.24 | VERSION_NOT_VERIFIED | non-emitting | REVIEW |
| Static-route options | Cisco ASA | 9.24 | VERSION_NOT_VERIFIED | non-emitting | REVIEW |
| Interface/zone context | FortiOS | 7.6.4 | VERSION_NOT_VERIFIED | existing bounded policy context only | REVIEW |
| Disabled rules | FortiOS | 7.6.4 | VERSION_NOT_VERIFIED | existing bounded policy field only | REVIEW |
| ICMP | FortiOS | 7.6.4 | VERSION_NOT_VERIFIED | non-emitting | REVIEW |
| Source-port handling | FortiOS | 7.6.4 | VERSION_NOT_VERIFIED | non-emitting | REVIEW |
| Multiple service ranges | FortiOS | 7.6.4 | VERSION_NOT_VERIFIED | existing bounded destination ranges only | REVIEW |
| Nested groups | FortiOS | 7.6.4 | VERSION_NOT_VERIFIED | non-emitting | REVIEW |
| FQDN objects | FortiOS | 7.6.4 | VERSION_NOT_VERIFIED | non-emitting | REVIEW |
| Basic IPv6 objects | FortiOS | 7.6.4 | VERSION_NOT_VERIFIED | non-emitting | REVIEW |
| Logging semantics | FortiOS | 7.6.4 | VERSION_NOT_VERIFIED | non-emitting | REVIEW |
| Schedules/time-ranges | FortiOS | 7.6.4 | VERSION_NOT_VERIFIED | fixed `always` only | REVIEW |
| Static-route options | FortiOS | 7.6.4 | VERSION_NOT_VERIFIED | existing bounded IPv4 route only | REVIEW |
| Interface/zone context | PAN-OS | 11.1 | VERSION_NOT_VERIFIED | existing mapped policy context only | REVIEW |
| Disabled rules | PAN-OS | 11.1 | VERSION_NOT_VERIFIED | existing bounded policy field only | REVIEW |
| ICMP | PAN-OS | 11.1 | VERSION_NOT_VERIFIED | non-emitting | REVIEW |
| Source-port handling | PAN-OS | 11.1 | VERSION_NOT_VERIFIED | non-emitting | REVIEW |
| Multiple service ranges | PAN-OS | 11.1 | VERSION_NOT_VERIFIED | existing bounded destination ranges only | REVIEW |
| Nested groups | PAN-OS | 11.1 | VERSION_NOT_VERIFIED | non-emitting | REVIEW |
| FQDN objects | PAN-OS | 11.1 | VERSION_NOT_VERIFIED | existing bounded address field only | REVIEW |
| Basic IPv6 objects | PAN-OS | 11.1 | VERSION_NOT_VERIFIED | non-emitting | REVIEW |
| Logging semantics | PAN-OS | 11.1 | VERSION_NOT_VERIFIED | existing bounded policy fields only | REVIEW |
| Schedules/time-ranges | PAN-OS | 11.1 | VERSION_NOT_VERIFIED | non-emitting | REVIEW |
| Static-route options | PAN-OS | 11.1 | VERSION_NOT_VERIFIED | existing bounded legacy route only | REVIEW |
| Interface/zone context | Juniper SRX | 23.4R2 | VERSION_NOT_VERIFIED | existing mapped zone membership only | REVIEW |
| Disabled rules | Juniper SRX | 23.4R2 | VERSION_NOT_VERIFIED | non-emitting | REVIEW |
| ICMP | Juniper SRX | 23.4R2 | VERSION_NOT_VERIFIED | non-emitting | REVIEW |
| Source-port handling | Juniper SRX | 23.4R2 | VERSION_NOT_VERIFIED | non-emitting | REVIEW |
| Multiple service ranges | Juniper SRX | 23.4R2 | VERSION_NOT_VERIFIED | non-emitting | REVIEW |
| Nested groups | Juniper SRX | 23.4R2 | VERSION_NOT_VERIFIED | non-emitting | REVIEW |
| FQDN objects | Juniper SRX | 23.4R2 | VERSION_NOT_VERIFIED | non-emitting | REVIEW |
| Basic IPv6 objects | Juniper SRX | 23.4R2 | VERSION_NOT_VERIFIED | non-emitting | REVIEW |
| Logging semantics | Juniper SRX | 23.4R2 | VERSION_NOT_VERIFIED | non-emitting | REVIEW |
| Schedules/time-ranges | Juniper SRX | 23.4R2 | VERSION_NOT_VERIFIED | non-emitting | REVIEW |
| Static-route options | Juniper SRX | 23.4R2 | VERSION_NOT_VERIFIED | existing simple IPv4 next hop only | REVIEW |

## Existing renderer boundary

Existing Q8-Q10 capabilities retain their evidence IDs and tests. The audit does not revoke those bounded fields or treat them as proof for broader Q12 semantics. Adjacent versions inherit nothing. Unknown versions have no renderer registration.