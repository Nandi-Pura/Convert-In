# CP1 Reference Integrity

CP1 runs after normalized IR creation, before compatibility planning and rendering. It answers whether modeled references are structurally resolvable. It does not score migration quality, simulate behavior, or claim target compatibility.

Pipeline: **CP0 Source Extraction Coverage → normalized IR → CP1 Reference Integrity → CP2 Target Compatibility / Evidence → renderer**.

## Findings and policy

Stable findings cover unresolved or mistyped references, duplicate or ambiguous names, self-reference, recursive group cycles, missing group members, interfaces, zones, addresses, services, invalid route values, and orphaned objects. `ERROR` findings are blocking. `WARNING` findings are inspectable but non-blocking. Unused address and service objects/groups are warnings. No integrity score exists.

Blocking findings suppress target emission for the source entity and its transitive normalized dependents. Other entities remain eligible for independent documentation, version, capability, and renderer gates. Candidate comments identify the omitted entity and bounded dependency path.

## Resolver and graph

One exact-name typed index covers addresses, address groups, services, service groups, interfaces, zones, policies, NAT, routes, and VPN entities. Resolution never silently crosses types. Names retain source case. Duplicate names are checked inside normalized namespaces. NetworkX provides deterministic cycle and transitive-dependent traversal; findings and SHA-256-prefix IDs use stable sorted inputs.

Built-ins are vendor-profile bounded: ASA address `any`, `any4`, `any6` and protocol services `ip`, `icmp`, `tcp`, `udp`; FortiGate normalized `any`. No broad magic-name list is used.

## Vendor limits

Cisco ASA and FortiGate normalized IR are supported. PAN-OS XML is not implemented for CP1 in Q3. ASA access-group binding, VPN dependencies, FortiGate VDOM-scoped resolution, and explicit route contexts are validated only when represented in IR; Q3 does not invent parser data. NAT remains review-only and never emits PAN-OS NAT commands.