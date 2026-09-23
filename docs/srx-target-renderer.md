# Juniper SRX target renderer

## Target and evidence

The bounded target is Juniper SRX running **Junos OS 23.4R2**. Registry key: `FIREWALL / JUNIPER / SRX / 23.4R2`. Adjacent releases inherit no capability. Firewall-specific evidence IDs cover the release, address books, applications, zones, security policies, and static routes in `docs/vendor-reference/junos.yaml`.

`JunosSrxRenderer` consumes normalized `FirewallConfig` through CP0, CP1, and target-specific CP2. It never reads source CLI. `JunosSrxCommand` records source lineage, hierarchy, arguments, capability, evidence, dependencies, and rendered set text. The renderer emits only `EXACT` or `SUPPORTED` entities with verified version, evidence, tests, and renderer support.

## Bounded output

- Global address book only: canonical IPv4 `/32` hosts, strict IPv4 prefixes, evidenced IPv4 ranges, and flat address sets.
- Custom applications only: TCP or UDP with one destination port or one destination-port range. No built-in application guessing.
- Flat application sets with complete emitted members.
- Security policies: one confirmed source zone, one confirmed destination zone, complete emitted address/application dependencies, source order, and `permit` or `deny`.
- Confirmed interface and zone mappings may establish policy context. Interface L3 addresses and host-inbound traffic are not generated. Zone membership remains non-emitting unless both source and target evidence gates pass.
- Simple global IPv4 static routes containing only destination prefix and next-hop address.
- Deterministic Junos set-style output. Candidate filename: `candidate-srx-23.4R2.set`.

Policy `any` uses the documented Junos predefined address/application value only when normalized input explicitly contains `any`. Names are not silently normalized. Tokens reject control characters; spaces, quotes, backslashes, and Unicode receive deterministic Junos quoting.

## Review-only scope

Nested sets, multiple destination-port ranges, source ports, ICMP, App-ID, ALG behavior, disabled policies, descriptions, logging, schedules, profiles, advanced actions, routing instances, interface-dependent routes, preference/metric options, IPv6, FQDN, dynamic addresses, screens, UTM, IDP, VPN, system configuration, HA, and dynamic routing do not emit.

NAT remains visible as `MANUAL_REVIEW`. Generated NAT command count is always zero. No live device, NETCONF, SSH, load, commit, rollback, manager, or deployment capability exists. Validation is application-level only; every candidate requires engineer review.