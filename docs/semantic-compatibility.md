# Semantic Compatibility (CP2)

CP2 runs after normalized IR and CP1, before rendering. It answers whether each understood source entity can preserve operational intent on the selected target/version. It is not syntax conversion, a score, or inferred confidence.

## States

- `EXACT`: directly equivalent semantics; deterministic emission allowed.
- `SUPPORTED`: documented structural transformation preserves intent; deterministic emission allowed.
- `PARTIAL`: behavioral meaning would be omitted; emission blocked by default.
- `MANUAL_REVIEW`: intent is understood, but required context is not safely derivable; emission blocked.
- `UNSUPPORTED`: current target scope cannot represent the intent; emission blocked.
- `VERSION_NOT_VERIFIED`: source semantics, target semantics, target syntax, renderer, tests, or selected-version evidence is incomplete; emission blocked.

## Decision contract

Each normalized entity receives a deterministic SHA-256-prefix decision ID based on source entity ID, target vendor/version, management mode, status, and renderer capability ID. Decisions record source and target semantics, preserved and lost semantics, required context, reasons, CP1 findings, source/target documentation references, renderer support, and tests.

Existing version capability profiles are the single capability registry. No adjacent version inherits evidence. Source documentation, target semantic documentation, target CLI syntax evidence, renderer support, and tests must all be present for normal emission.

## Loss and context policy

Loss affecting packet processing blocks emission: addresses, zones, services, actions, enabled state, schedule, identity/application constraints, NAT behavior, ordering, or routing context. Cosmetic metadata may be omitted only when explicitly classified. Required context includes target zone/interface mapping, virtual router, VSYS, management mode, and rule placement.

CP1 blockage changes the entity decision to `MANUAL_REVIEW` and links blocking CP1 finding IDs. CP0 `UNPARSED` and `SOURCE_UNSUPPORTED` constructs do not receive fabricated CP2 decisions.

## Bounded scope

Address/group, TCP/UDP service/group, simple security-policy, and static-route transformations are evaluated for PAN-OS 11.1 `LOCAL_FIREWALL`. Interfaces and zones require mappings. NAT and VPN remain non-generated. PAN-OS 12.1 and Panorama remain blocked. Group flattening, target interface fabrication, NAT rendering, deployment, runtime network access, and AI judgment are absent.