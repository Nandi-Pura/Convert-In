# Firewall NAT translation framework

## State

The framework is complete; NAT command emission is not enabled. Every normalized NAT rule receives subtype accounting and a conservative compatibility decision. Renderers emit zero NAT commands until one exact source/target/version capability has complete syntax, match, translation, route-lookup, ordering, placement, mapping, and test evidence.

## Normalized contract

`NatRule` retains original and translated source, destination, and service tuples; ingress and egress context; source and destination zones; translation type and target; identity state; source order; provenance; vendor extensions. The planner selects capability evidence by NAT subtype rather than one broad NAT flag.

`NatRulePlacement` records `TOP`, `BOTTOM`, `BEFORE`, or `AFTER`. Relative placement requires a safe anchor. `NatRouteOutcome` separates the NAT pre-translation destination zone from the security-policy post-translation destination zone. Duplicate route outcomes and invalid context names are rejected.

## Evidence gate

Emission requires every dimension below:

1. exact source-version semantics
2. exact target-version match semantics
3. exact target-version translation semantics
4. exact target command syntax
5. destination route-lookup semantics
6. deterministic ordering
7. deterministic placement
8. confirmed target mappings
9. renderer implementation and tests

Incomplete evidence produces `VERSION_NOT_VERIFIED`, `MANUAL_REVIEW`, or `UNSUPPORTED`. The normalized NAT rule remains in compatibility, review, validation, and report accounting.

## Current target outcome

| Target | Exact Version | Renderer State | User Outcome |
|---|---:|---|---|
| Cisco ASA | 9.24 | NAT non-emitting | REVIEW |
| FortiOS | 7.6.4 | NAT non-emitting | REVIEW |
| PAN-OS | 11.1 | NAT non-emitting | REVIEW |
| Juniper SRX | 23.4R2 | NAT non-emitting | REVIEW |

No adjacent version inherits this state. No renderer may infer a target command from source syntax or a release note.