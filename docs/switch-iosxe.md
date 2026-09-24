# Cisco IOS-XE switch domain

## Version profile

Q16 uses Cisco Catalyst 9300 with Cisco IOS XE Dublin 17.12.1. Reference `IOSXE-17.12.1-C9300-COMMANDS` records the official command reference and its explicit 17.12.1 applicability.

The source parser and target renderer cover VLAN creation and names, access ports, trunks, allowed VLAN lists and ranges, native VLAN, descriptions, administrative state, Port-Channel, LACP active or passive membership, and basic IPv4 SVI configuration.

The parser records unsupported switch semantics instead of dropping them. STP generation, QoS, access security, stacking, chassis virtualization, overlays, routing protocols, VRFs, and private VLANs remain outside Q16.

## Safety boundaries

- RouterConfig and SwitchConfig remain separate extraction paths.
- Cross-platform physical interfaces require a confirmed mapping scoped to both profiles, both exact versions, and the source entity ID.
- Same-profile conversion preserves the exact interface identity.
- CP2 emits only `EXACT` or `SUPPORTED` entities.
- Undefined VLAN, LAG, member-interface, or SVI dependencies block the affected entity.
- AOS-CX 10.15 remains `VERSION_NOT_VERIFIED`; no exact maintenance release was independently verified.