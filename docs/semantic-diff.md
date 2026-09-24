# Semantic diff

Semantic Diff v2 accounts for each modeled source property using normalized IR, CP2 decisions, explicit mappings, renderer metadata, and review state. It never derives semantic equivalence from source or target command text.

## Classifications

- `PRESERVED`: property-level CP2 evidence confirms equivalent modeled meaning.
- `CHANGED`: an explicit target transformation or confirmed rename retains an entity while changing its value.
- `LOST`: CP2 explicitly identifies an unsupported source semantic. Missing commands alone never establish loss.
- `REVIEW`: equivalence remains unproven, including `MANUAL_REVIEW`, `VERSION_NOT_VERIFIED`, unresolved mappings, incomplete context, and non-emitting NAT.

Entity state uses `REVIEW`, `LOST`, `CHANGED`, then `PRESERVED` precedence. An entity without property evidence is `REVIEW`. Workflow states such as Ready, Review, and Blocked remain separate.

## Artifact

`workspace/<project-id>/migration/semantic-diff.json` uses `convert-in.semantic-diff/v2`. One contract covers firewall, switch, and router entities. Records include source lineage, CP2 decision ID, source and known target identities, property values, evidence IDs, reasons, required actions, and related IDs.

Canonical compact JSON excluding `fingerprint` produces its `sha256:` fingerprint. IDs and ordering are deterministic. The persisted file uses stable indented JSON and atomic replacement. A state fingerprint covers normalized IR, exact version context, CP2, mappings, and review decisions. Reads reject stale state. Mapping updates remove the stale artifact.

Unordered modeled sets use canonical ordering. Ordered policy and route-policy semantics retain order. Values contain normalized model data only; raw configuration fragments and environment paths are excluded.

## API

- `POST /api/projects/{project_id}/migration/semantic-diff`
- `GET /api/projects/{project_id}/migration/semantic-diff`
- `GET /api/projects/{project_id}/migration/download/semantic-diff`

Generation does not require a candidate file. The workbench shows structured entity and property rows first. Raw source/target comparison remains under **Raw Comparison**.

## Limits

The engine adds no parser, renderer, target-version, or vendor-command behavior. Existing CP2 metadata may not prove every emitted router or switch property; those properties remain `REVIEW`. NAT remains non-emitting and conservative. No compatibility, confidence, accuracy, or migration score exists.