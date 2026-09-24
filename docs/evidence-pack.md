# Migration evidence pack

`POST /api/projects/{project_id}/migration/evidence-pack` builds a local `convert-in.evidence-pack/v1` snapshot. `GET` reads its manifest. `/migration/download/evidence-pack` downloads the deterministic ZIP.

The pack records exact source and target profiles, artifact statuses, summaries, SHA-256 checksums, and a manifest fingerprint. `PRESENT`, `NOT_GENERATED`, `NOT_APPLICABLE`, `STALE`, and `INVALID` distinguish inventory state. Stale profile-bound artifacts stay out of the trusted file set.

Raw source configuration is excluded. `source/source-metadata.json` records its filename, byte size, line count, profile, and chunked SHA-256 hash. Candidate output is copied unchanged when present; analysis-only projects remain exportable. All candidate content requires engineer review. No deployment occurs.

The fingerprint is SHA-256 over compact UTF-8 JSON with sorted keys and no `fingerprint` field. `checksums.sha256` covers every other pack file in forward-slash path order. Validate with `sha256sum -c checksums.sha256` from the pack directory.

The directory and ZIP omit timestamps, host data, user data, absolute paths, traversal paths, source bytes, and remote content. `REVIEW`, `UNSUPPORTED`, and `VERSION_NOT_VERIFIED` retain their existing meanings; packaging does not reinterpret them.