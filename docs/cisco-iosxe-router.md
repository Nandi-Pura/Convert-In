# Cisco IOS-XE router analysis

Q6 supports parser and assurance analysis for Cisco IOS XE Dublin `17.12.1`. Adjacent releases remain `VERSION_NOT_VERIFIED`. Strong detection requires `Cisco IOS XE Software, Version 17.12.1`; otherwise explicit source/version selection is required.

## Scope

The deterministic context parser normalizes hostname metadata, physical/loopback/subinterfaces, descriptions, primary/secondary IPv4 addresses, admin state, VRF definitions and interface membership, common IPv4 static routes, prefix-list sequence/action/prefix/ge/le, route-map terms and bounded prefix-list matches, OSPF process/router ID/network wildcard/area, and BGP process/router ID/IPv4 neighbors/remote AS/description/update source/route-map/network.

Each semantic entity carries a source line. OSPF wildcard masks remain explicit; they are not guessed into prefixes. Address-family IPv4 context remains separate during parsing.

## Assurance

CP0 reports `NORMALIZED`, `RECOVERED`, `UNPARSED`, `SOURCE_UNSUPPORTED`, and `IGNORED_NON_SEMANTIC`. Interface blocks, route lines, prefix-list entries, route-map terms, OSPF processes, and BGP neighbors are semantic units.

CP1 uses router-specific typed indexes. It validates interface/route to VRF, route to interface, route-map to prefix-list, and BGP neighbor to route-map/update-source. Missing references block dependent entities. IDs and findings are deterministic.

## Limits

MPLS, EIGRP, IS-IS, multicast, QoS, PBR, advanced BGP address families, advanced OSPF fields, tracking/IP SLA, tunnels, complete MP-BGP, and complete OSPF remain source-unsupported or unparsed. No CP2 applies because no router target exists. No router renderer, Quick Convert source, deployment, or cross-vendor router conversion exists.