# FortiGate to PAN-OS migration

ConfigMorph parses FortiOS configuration into the normalized `FirewallConfig` IR, applies a FortiGate source adapter, then uses the shared migration planner, PAN-OS renderer, semantic review, and validation workflow. Output is a candidate configuration. Engineer review remains mandatory.

## Supported candidate semantics

- Host/subnet, network, range, and FQDN addresses; static and nested address groups.
- TCP or UDP destination-port services and static service groups. Mixed TCP/UDP groups remain groups of distinct services.
- Firewall-policy source/destination contexts, addresses, services, allow/deny action, enabled state, effective parser order, and session-end logging.
- Simple static routes with a confirmed target interface and selected PAN virtual router.

Mappings explicitly bind each source interface/context to a target interface and zone. Suggestions never authorize generation. FortiGate zones retain their member-interface evidence; ambiguous topology remains manual review. VLAN interfaces may inform mappings, but the migration does not create PAN interfaces or subinterfaces.

## Review-only semantics

- IP-pool NAT without complete translated-address semantics.
- Policy interface-address PAT.
- One-to-one IPv4 VIP destination NAT and VIP port translation.
- Arbitrary VIP services, incomplete port-forward fields, load balancing, VIP groups, DNS translation, FQDN VIP, NAT46/NAT64, and ARP behavior.
- Central NAT. Policy `nat enable` is not treated as complete semantics when central NAT is enabled.

FortiOS 7.4/7.6 source semantics remain separate from PAN-OS target evidence. PAN-OS 11.1 DIPP, interface-address PAT, and one-to-one DNAT target semantics are documented. Port translation target semantics, deterministic ordering/placement, route outcome mapping, and complete VIP policy association remain blocked. No NAT candidate commands are emitted.
- IPS, antivirus, web filter, application control, SSL inspection, DNS filter, UTM, and profile groups. References are reported; profiles are not invented.
- Multiple VDOM flattening, FortiGate SD-WAN, policy routes, ECMP-specific behavior, and dynamic routing.
- Source-port restrictions, ICMP, SCTP, protocol-number, helper, and session-TTL service behavior.

Multiple VDOMs are not mapped automatically to one PAN vsys. SD-WAN members, health checks, and service rules are not used to infer routes. Review every compatibility record, mapping, normalized warning, generated command, and review-package validation result in an isolated PAN-OS lab before any separate deployment process. ConfigMorph has no device connection or deployment feature.