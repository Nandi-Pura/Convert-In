# Version-aware support matrix

## Platform status

| Platform/domain | Source parser | CP0 | CP1 | Target renderer | CP2 | Workbench |
|---|---|---|---|---|---|---|
| Juniper SRX / firewall / Junos 23.4R2 | Set-style MVP | Yes | Yes | None | Bounded for PAN-OS 11.1 | Analysis; PAN conversion |
| Cisco IOS-XE 17.12.1 / router | Bounded subset | Yes | Yes | None | Bounded for Junos 23.4R2 | Analysis; Junos conversion |
| PAN-OS 11.1 / firewall | XML MVP | Current state | Current state | Bounded | Target-specific | Source analysis; target conversion |
| Cisco ASA / firewall | Bounded | Yes | Yes | ASA 9.24 bounded | PAN-OS 11.1 and ASA 9.24 bounded | Analysis; bounded conversion |
| FortiOS / firewall | Bounded | Yes | Yes | FortiOS 7.6.4 bounded | PAN-OS 11.1 and FortiOS 7.6.4 bounded | Analysis; bounded conversion |
| Cisco IOS/IOS-XE/NX-OS / switch | No; foundation | Model foundation | Foundation | No | No | No |
| Aruba AOS-CX / router or switch | No; profile foundation | Model foundation | Foundation | No | No | No |
| Juniper Junos 23.4R2 / router | No; target profile | Model foundation | Foundation | Bounded | Bounded | Target conversion |
| Juniper Junos / switch | No; foundation | Model foundation | Foundation | No | No | Analysis only |
| Huawei VRP / router or switch | No; profile foundation | Model foundation | Foundation | No | No | Analysis only |

Profile presence does not claim conversion support. PAN-OS 11.1, FortiOS 7.6.4, and Cisco ASA 9.24 are bounded firewall targets. The ASA target emits objects and services only; ACLs, bindings, routes, interfaces, and NAT remain review-only. Juniper SRX target rendering remains unimplemented. Junos 23.4R2 is the only router target renderer. No switch renderer exists.

SRX normalization covers set-style zones/interface membership, interface addresses, scoped address entries and sets, explicit TCP/UDP applications and application sets, basic security policy match/action/logging/order/inactive state, global static routes, and NAT recognition. Hierarchical syntax, host-inbound services, schedulers, routing instances, advanced application fields, and advanced policy actions are unparsed or source-unsupported. Address-book scope is preserved in vendor metadata; ambiguous duplicate names block CP1 rather than flattening silently. Zones remain explicit mappings. NAT always remains non-generated.

## Quick Convert Q1

CP0 Source Extraction Coverage is supported for the bounded ASA and FortiGate parser scopes. PAN-OS XML CP0 is not implemented. CP0 accounts parser extraction only; it does not expand or score target generation support.

CP1 Reference Integrity is supported for modeled Cisco ASA and FortiGate normalized entities. PAN-OS XML CP1 is not implemented in Q3. Unmodeled access-group, VPN, VDOM, and route-context dependencies remain explicit limitations rather than inferred semantics.

CP2 Semantic Compatibility is version-profiled for ASA 9.20/9.22/9.24 and FortiOS 7.4/7.6 to PAN-OS 11.1 `LOCAL_FIREWALL`. Objects, services, simple security policies, and static routes are field-dependent. Interfaces, zones, VPN, NAT, missing context, behavioral loss, and unverified versions remain non-generated. PAN-OS 12.1 does not inherit PAN-OS 11.1 evidence.

| Construct | Source parsing | CP1 | CP2 | PAN generation |
|---|---|---|---|---|
| Address/group | Bounded | Modeled references | Supported when type/member semantics evidenced | Bounded |
| Service/group | Bounded | Modeled references | Supported for evidenced TCP/UDP destination ports | Bounded |
| Security policy | Bounded | Addresses/services/zones | Field- and context-dependent | Bounded |
| Static route | Bounded | Interface reference | Context-dependent | Bounded |
| Interface/zone | Bounded | Membership | Manual mapping required | None |
| NAT/VPN | Bounded | Modeled references | Manual review/unsupported/version not verified | None |

Supported generation uses FortiOS 7.4/7.6 or Cisco ASA 9.20/9.22/9.24 as sources, normalized `FirewallConfig`, and PAN-OS 11.1 `LOCAL_FIREWALL` as the target. The generated subset is addresses, address groups, services, service groups, evidenced security policies, and evidenced static routes.

NAT, ambiguous target context, ambiguous interface/zone mapping, advanced semantics, and unverified versions remain review or non-generated. PAN-OS 12.1, Panorama, live mutation, commit, and deployment remain blocked.

States: **SYNTAX_VERIFIED**, **END_TO_END_VERIFIED**, **VERSION_NOT_VERIFIED**, **MANUAL_REVIEW**, **NOT_APPLICABLE**.

| Feature | ASA 9.20 | ASA 9.22 | ASA 9.24 | FortiOS 7.4 | FortiOS 7.6 | PAN-OS 11.1 | PAN-OS 12.1 |
|---|---|---|---|---|---|---|---|
| Addresses/groups | VERSION_NOT_VERIFIED | VERSION_NOT_VERIFIED | VERSION_NOT_VERIFIED | VERSION_NOT_VERIFIED | VERSION_NOT_VERIFIED | SYNTAX_VERIFIED | VERSION_NOT_VERIFIED |
| Services/groups | VERSION_NOT_VERIFIED | VERSION_NOT_VERIFIED | VERSION_NOT_VERIFIED | VERSION_NOT_VERIFIED | VERSION_NOT_VERIFIED | SYNTAX_VERIFIED | VERSION_NOT_VERIFIED |
| Security policy | SYNTAX_VERIFIED | SYNTAX_VERIFIED | SYNTAX_VERIFIED | SYNTAX_VERIFIED | SYNTAX_VERIFIED | END_TO_END_VERIFIED | IMPLEMENTED_NOT_VERIFIED |
| Static routes | VERSION_NOT_VERIFIED | VERSION_NOT_VERIFIED | VERSION_NOT_VERIFIED | VERSION_NOT_VERIFIED | VERSION_NOT_VERIFIED | SYNTAX_VERIFIED | VERSION_NOT_VERIFIED |
| Static source NAT | DOCUMENTED_NOT_IMPLEMENTED | VERSION_NOT_VERIFIED | VERSION_NOT_VERIFIED | NOT_APPLICABLE | NOT_APPLICABLE | DOCUMENTED_NOT_IMPLEMENTED | VERSION_NOT_VERIFIED |
| Dynamic IP-and-port | DOCUMENTED_NOT_IMPLEMENTED | VERSION_NOT_VERIFIED | VERSION_NOT_VERIFIED | NOT_APPLICABLE | NOT_APPLICABLE | DOCUMENTED_NOT_IMPLEMENTED | VERSION_NOT_VERIFIED |
| Interface-address PAT | NOT_APPLICABLE | NOT_APPLICABLE | NOT_APPLICABLE | DOCUMENTED_NOT_IMPLEMENTED | DOCUMENTED_NOT_IMPLEMENTED | DOCUMENTED_NOT_IMPLEMENTED | VERSION_NOT_VERIFIED |
| Static destination NAT | NOT_APPLICABLE | NOT_APPLICABLE | NOT_APPLICABLE | DOCUMENTED_NOT_IMPLEMENTED | DOCUMENTED_NOT_IMPLEMENTED | DOCUMENTED_NOT_IMPLEMENTED | VERSION_NOT_VERIFIED |
| Destination port translation | NOT_APPLICABLE | NOT_APPLICABLE | NOT_APPLICABLE | DOCUMENTED_NOT_IMPLEMENTED | DOCUMENTED_NOT_IMPLEMENTED | DOCUMENTED_NOT_IMPLEMENTED | VERSION_NOT_VERIFIED |
| Identity NAT | DOCUMENTED_NOT_IMPLEMENTED | VERSION_NOT_VERIFIED | VERSION_NOT_VERIFIED | DOCUMENTED_NOT_IMPLEMENTED | DOCUMENTED_NOT_IMPLEMENTED | DOCUMENTED_NOT_IMPLEMENTED | VERSION_NOT_VERIFIED |
| Twice NAT | DOCUMENTED_NOT_IMPLEMENTED | VERSION_NOT_VERIFIED | VERSION_NOT_VERIFIED | DOCUMENTED_NOT_IMPLEMENTED | DOCUMENTED_NOT_IMPLEMENTED | DOCUMENTED_NOT_IMPLEMENTED | VERSION_NOT_VERIFIED |
| IP-pool SNAT | NOT_APPLICABLE | NOT_APPLICABLE | NOT_APPLICABLE | DOCUMENTED_NOT_IMPLEMENTED | DOCUMENTED_NOT_IMPLEMENTED | DOCUMENTED_NOT_IMPLEMENTED | VERSION_NOT_VERIFIED |
| Central NAT | NOT_APPLICABLE | NOT_APPLICABLE | NOT_APPLICABLE | DOCUMENTED_NOT_IMPLEMENTED | DOCUMENTED_NOT_IMPLEMENTED | DOCUMENTED_NOT_IMPLEMENTED | VERSION_NOT_VERIFIED |
| VDOM / SD-WAN / profiles | NOT_APPLICABLE | NOT_APPLICABLE | NOT_APPLICABLE | DOCUMENTED_NOT_IMPLEMENTED | DOCUMENTED_NOT_IMPLEMENTED | NOT_APPLICABLE | NOT_APPLICABLE |

The matrix describes individual evidence, not device validation. PAN-OS 11.1 local security-policy generation requires explicit placement and exports a separate, non-executed Configuration API move intent. PAN-OS 11.1 DIPP, interface-address PAT, and one-to-one DNAT target match/translation/route semantics are documented independently. Port translation target semantics remain unverified. No NAT capability passes ordering, deterministic placement, route outcome mapping, renderer, and full end-to-end gates. PAN-OS 12.1 remains blocked independently.

## v0.2.0-alpha.1 release scope

| Target profile | Candidate generation | Review-only / blocked |
|---|---|---|
| PAN-OS 11.1 `LOCAL_FIREWALL` | Addresses/groups, services/groups, security policies, separate ordering intent, supported static routes | All NAT subtypes; advanced source semantics |
| PAN-OS 12.1 | None where target paths remain unverified | Limited; `VERSION_NOT_VERIFIED` |
| Panorama | None | Blocked; device-group and pre/post-rulebase paths unimplemented |

NAT entities remain visible with specific review reasons. No NAT candidate command is emitted.

PAN-OS 11.1 syntax evidence does not imply XML API mutation evidence. Public Configuration API documentation identifies `action=set` but does not publish exact local-firewall XPath and element payloads for the six emitted capability families. Live candidate mutation therefore remains `VERSION_NOT_VERIFIED` pending PAN-OS 11.1 device API Browser or debug evidence. No partial capability subset is enabled.

O.5 adds local, ignored evidence-record preparation only. No PAN-OS 11.1 device capture was available; every required XML mapping and list-member experiment remains `UNVERIFIED`. No `PanXmlMutation` or network transport is enabled.

Run `python -m app.tools.doc_coverage` for development-time evidence counts and registry errors.