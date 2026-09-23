# Cisco ASA target renderer

## Target

The bounded target is Cisco Secure Firewall ASA **9.24(x)**. Registry key: `FIREWALL / CISCO / ASA / 9.24`. Adjacent releases inherit no support.

The renderer consumes normalized `FirewallConfig` after CP0, CP1, and target-specific CP2. Source vendor identity does not select renderer behavior. Output is a candidate only. Validation is application-level. No device connection, upload, activation, or deployment exists.

## Official references

- `ASA-9.24-ACCESS-OBJECTS`: [Objects for Access Control](https://www.cisco.com/c/en/us/td/docs/security/asa/asa924/configuration/firewall/asa-924-firewall-config/access-objects.html)
- `ASA-9.24-ACCESS-RULES`: [Access Rules](https://www.cisco.com/c/en/us/td/docs/security/asa/asa924/configuration/firewall/asa-924-firewall-config/access-rules.html)
- `ASA-9.24-STATIC-ROUTES`: [Static and Default Routes](https://www.cisco.com/c/en/us/td/docs/security/asa/asa924/configuration/general/asa-924-general-config/route-static.html)

## Emitted subset

- IPv4 host, subnet, and range network objects
- complete network object groups, including nested groups
- TCP or UDP service objects with one destination port or contiguous range
- complete service object groups, including nested groups

Names are preserved exactly. Unsupported names block emission; they are never silently changed. Identical IR and profile produce identical bytes in `candidate-asa-9.24.conf`.

## Review-only scope

ACLs and `access-group` bindings require an explicit target ACL name, direction, interface `nameif`, and placement model. Static routes require verified target `nameif` and routing context. Interfaces, security levels, addresses, contexts, IPv6, FQDN objects, source ports, ICMP, multiple disjoint ports, built-in reuse, NAT, VPN, and deployment emit no commands.

Only `EXACT` and `SUPPORTED` CP2 decisions with complete target evidence can emit. `PARTIAL`, `MANUAL_REVIEW`, `UNSUPPORTED`, and `VERSION_NOT_VERIFIED` remain visible and non-copyable.

## Command model

`AsaCommand` records source entity ID, configuration mode, object name, typed token operations, capability ID, and evidence references. The serializer accepts allowlisted tokens only. Source text never becomes a command fragment.