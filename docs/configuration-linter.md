# Configuration linter

The configuration linter performs deterministic static checks against normalized firewall, router, and switch IR. It does not parse vendor syntax, render candidate configuration, modify source data, assign risk scores, or apply remediation.

## Contract

`migration/lint-findings.json` uses `convert-in.lint-findings/v1`. Its fingerprint is SHA-256 over canonical compact JSON excluding the fingerprint. Finding IDs and ordering depend only on normalized semantics and CP1 findings.

Severities:

- `INFO`: modeled condition worth recording.
- `WARNING`: deterministic advisory requiring engineer review.
- `BLOCKING`: deterministic ConfigMorph integrity problem. It does not claim production failure.

CP1 remains authoritative for conversion blocking. The linter adapts CP1 findings for presentation without changing CP0, CP1, or CP2 state.

## Rules

Firewall checks cover duplicate and unused address/service objects, orphan and empty groups, disabled policies, broad any scope, CP1 references, deterministic address overlap, and conservative policy-shadow candidates.

Switch checks cover unreferenced VLANs, explicit empty trunk sets, empty LAGs, conflicting LAG membership, disabled interfaces, and CP1 VLAN/LAG/SVI integrity findings.

Router checks cover exact duplicate static routes, empty or unused prefix lists, unused route policies, constrained static-route self-conflicts, and CP1 route-policy or reference gaps.

## Limits

Shadow candidates require complete modeled policy context, equal action, strict order, and coverage on every modeled match dimension. Logging, vendor extensions, missing zones, unknown actions, and other incomplete context suppress the finding. The linter performs no routing reachability analysis and makes no vulnerability or deployment-safety claim. Suggested actions are informational; engineers make every change.