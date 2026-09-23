# FortiOS target renderer

## Target

The bounded target is Fortinet FortiGate running **FortiOS 7.6.4**. The registry key is `FIREWALL / FORTINET / FORTIGATE / 7.6.4`. Adjacent releases do not inherit support.

The renderer consumes `FirewallConfig` after CP0, CP1, and target-specific CP2. Source vendor identity does not select renderer behavior. Output is a candidate only. Validation is application-level; no FortiGate, FortiManager, API, SSH, upload, commit, or install operation exists.

## Official references

- `FORTIOS-7.6.4-ADDRESS`: [config firewall address](https://docs.fortinet.com/document/fortigate/7.6.4/cli-reference/306021697/config-firewall-address)
- `FORTIOS-7.6.4-ADDRGRP`: [config firewall addrgrp](https://docs.fortinet.com/document/fortigate/7.6.4/cli-reference/301511994/config-firewall-addrgrp)
- `FORTIOS-7.6.4-SERVICE-CUSTOM`: [config firewall service custom](https://docs.fortinet.com/document/fortigate/7.6.4/cli-reference/198499981/config-firewall-service-custom)
- `FORTIOS-7.6.4-SERVICE-GROUP`: [config firewall service group](https://docs.fortinet.com/document/fortigate/7.6.4/cli-reference/242456538/config-firewall-service-group)
- `FORTIOS-7.6.4-FIREWALL-POLICY`: [config firewall policy](https://docs.fortinet.com/document/fortigate/7.6.4/cli-reference/333889629/config-firewall-policy)
- `FORTIOS-7.6.4-STATIC-ROUTE`: [config router static](https://docs.fortinet.com/document/fortigate/7.6.4/cli-reference/200835411/config-router-static)

## Emitted subset

- IPv4 hosts and subnets as `set subnet <network> <netmask>`
- IPv4 ranges as `type iprange`, `start-ip`, and `end-ip`
- complete address groups
- TCP or UDP custom services with one or multiple destination-port ranges
- complete service groups
- simple IPv4 static routes with confirmed target device mapping and no source distance or metric
- ordered allow/deny policies with confirmed source and destination interface mappings, complete dependencies, deterministic candidate-local policy IDs, required `schedule always`, enabled/disabled state, and optional normalized comments

Policy IDs are deterministic local construction identifiers, not production allocations. Source order controls policy order. Generated names are never silently changed. Invalid or colliding names block emission. Interface mappings are context only; no interface or zone is created.

## Review-only scope

NAT, VIP/DNAT, central NAT, IPv6, FQDN and dynamic objects, built-in object reuse, source-port restrictions, ICMP and application semantics, logging, UTM/security profiles, VDOM/VRF, SD-WAN, route distance/metric, advanced next hops, interface creation, and target zone creation emit no commands. Missing mappings, references, evidence, or renderer capability also emit nothing.

Only `EXACT` and `SUPPORTED` CP2 decisions can emit. `PARTIAL`, `MANUAL_REVIEW`, `UNSUPPORTED`, and `VERSION_NOT_VERIFIED` remain accounted and non-copyable.

## Command model

`FortiOSCommand` records source entity ID, section, edit key, typed operations, capability ID, and evidence references. The centralized encoder rejects control characters and newline injection, escapes quotes and backslashes, preserves Unicode text, and never accepts source text as a command fragment. Sections are grouped once in dependency order. Identical IR, profile, and mappings produce identical bytes in `candidate-fortios-7.6.4.conf`.