# Migration

## Workbench workflow

**Import → Analyze → Mapping → Migration → Review → Validation → Export**

Import accepts a local file or pasted configuration. Analyze creates the normalized model, findings, compatibility accounting, and bounded visualization. Mapping records explicit target interfaces, zones, virtual router, and security-rule placement. Migration exposes compatibility evidence and candidate generation. Review compares source and target semantics per entity. Validation runs application-level checks and reports PAN-OS lab status separately. Export produces the allowlisted review package only after blocking findings are resolved.

The sticky source/target context remains visible across post-analysis views. Generated, manual-review, unsupported, and version-not-verified states remain explicit. NAT remains `MANUAL_REVIEW`; no NAT commands are emitted.

## Architecture

`vendor parser → FirewallConfig IR → compatibility/planner → confirmed mappings → PAN command DTOs → serializer → candidate/report`

Migration code consumes normalized IR only. It does not parse source syntax. A central pair registry selects the Cisco ASA or FortiGate source adapter and the single PAN-OS renderer. Every normalized entity receives one `EXACT`, `SUPPORTED`, `PARTIAL`, `MANUAL_REVIEW`, or `UNSUPPORTED` compatibility record. Omitted entities therefore remain visible in the report.

`MigrationPlan` is internal planner state. Q23 converts it through one explicit contract boundary to `MigrationPlanArtifact` v1, then serializes `migration/migration-plan.json`. The `convert-in.migration-plan/v1` artifact records version context, mappings, entity decisions, known dependencies, evidence references, blocked items, advisories, counts, and a deterministic `sha256:` fingerprint. Canonical serialization uses sorted JSON keys and stable collection ordering. It contains no source configuration, timestamps, credentials, or workstation paths.

The artifact represents review-only migration intent. It is versioned, evidence-bounded, non-executable, and available even when candidate rendering is blocked. It does not authorize unsupported candidate generation or alter renderer evidence gates.

Semantic Diff v2 consumes normalized IR and CP2 evidence to account for source properties as `PRESERVED`, `CHANGED`, `LOST`, or `REVIEW`. Unknown behavior remains `REVIEW`; command absence never establishes loss. The deterministic `migration/semantic-diff.json` artifact works without candidate output. See [semantic-diff.md](semantic-diff.md).

The [migration evidence pack](evidence-pack.md) aggregates current artifacts for offline review without changing semantic results. Raw source configuration remains excluded; analysis-only projects are supported.

[Project persistence](project-persistence.md) records source identity, exact profiles, mappings, reviews, and artifact revisions. Project Export includes source configuration for resumption and must be handled as sensitive data.

FortiGate scope and limitations are documented in [fortigate-to-pan.md](fortigate-to-pan.md).

## ASA to PAN-OS scope

For PAN-OS 11.1 local firewalls, the renderer emits set commands for validated objects, services, security-rule fields, and simple static routes. Security rules require explicit target placement. Their source-effective order is preserved in a separate `security-rule-ordering.json` intent artifact using the documented Configuration API move mechanism. The artifact is not CLI syntax, is not executed, and requires engineer review.

ASA `access-group` attachment, direction, ACL order/remarks, source-port constraints, and protocol fidelity are retained. Inbound ingress context comes from the attachment. Destination context is derived only by connected/static-route longest-prefix matching; evidence appears in compatibility output. Unattached, outbound, any-destination, multi-zone, unresolved, and ambiguous policies remain review-only. Interfaces are mapping-only. Zone creation is not automatic.

NAT is accounted subtype-by-subtype: static source, dynamic IP-and-port, interface-address PAT, static destination, destination port translation, identity, twice NAT, IP-pool SNAT, and central NAT. PAN-OS 11.1 DIPP, interface-address PAT, and one-to-one destination NAT have independent target match, translation, and route-lookup evidence. NAT destination zones use the original/pre-NAT destination route lookup. Security-policy destination zones use the post-NAT destination route lookup while policy addresses remain pre-NAT. These zones are not interchangeable. Ordering, deterministic placement, route outcome mapping, and renderer verification still block all NAT candidate commands. PAN-OS 12.1 and Panorama NAT remain independently blocked.

## Mapping and naming

Workspace-local `migration/mappings.json` stores target mode, `vsys` (default `vsys1`), device group, virtual router, and interface/zone mappings. Suggested zones are separate from `confirmed`; suggestions never authorize generation. Routes accept a confirmed mapping by source interface or source context.

Names deterministically replace unsupported punctuation with `_`, preserve Unicode word characters, cap candidates at 63 characters, and add `_2`, `_3`, etc. on case-insensitive collisions. Reports retain source/target names, reason, and collision status. Values containing whitespace, quotes, or backslashes are PAN-OS quoted and escaped; control characters are blocked.

## Validation and review

Generation validates the structured plan plus the emitted subset: recognized context, IP/netmask values, and port syntax. This is application-level syntax validation, **not validation by PAN-OS**. Critical parse errors block all candidate output. Unresolved references and group cycles block affected entities. Potential shadowing remains advisory; policy order is never changed.

Generated files are always **Candidate Configuration — Engineer Review Required**:

- `migration/candidate-pan-os.set`
- `migration/migration-report.json`
- `migration/compatibility.json`
- `migration/mappings.json`
- `migration/migration-plan.json`
- `migration/semantic-diff.json` when generated
- `migration/security-rule-ordering.json` when security rules are generated

`nat-rule-ordering.json` is not produced because no NAT definition currently passes the evidence gate.

Review all manual-review/unsupported findings, mappings, normalized parser warnings, names, command references, topology, and behavior on an isolated PAN-OS lab system before any separate deployment process. This application has no deployment capability.

The Phase H semantic review queue, persisted engineer decisions, stale-decision invalidation, staged validation, and final package are documented in [review.md](review.md). Final package export is blocked by validation failures; candidate inspection remains available.

The Validation view separates application validation from PAN-OS lab validation. The current lab transport remains disabled/not verified. It does not commit, deploy, or change candidate-generation scope.