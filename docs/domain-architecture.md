# Domain architecture

Convert-In separates `FirewallConfig`, `RouterConfig`, and `SwitchConfig`. Vendor syntax enters a domain parser, then CP0 extraction accounting, CP1 reference validation, domain-specific CP2 compatibility, and an optional target renderer. No pairwise translators exist.

`RouterConfig` currently provides bounded structured models for interfaces, VRFs, static routes, prefix lists, route policies, OSPF, and BGP. `SwitchConfig` provides VLANs, ports, LAGs, SVIs, STP metadata, and ACL references. These are IR foundations only: no router or switch vendor parser, CP1/CP2 contract, renderer, or Quick Convert path is claimed.

The platform registry separates normalized vendor, platform, OS family, domain, explicit versions, parser, renderer, capabilities, and documentation IDs. Cisco IOS-XE/NX-OS, Aruba AOS-CX, Juniper Junos, and Huawei VRP router/switch entries intentionally have empty version sets until official version-specific evidence and fixtures exist.

Domain detection uses behavior-bearing syntax. Junos `security policies` or `security zones` indicates firewall capability; `protocols bgp` indicates router capability; `ethernet-switching` or VLAN syntax indicates switch capability. Ties remain ambiguous. Generic Junos interfaces never imply SRX.