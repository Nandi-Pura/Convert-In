# Project persistence

`workspace/<project-id>/project.json` is the authoritative `convert-in.project/v1` manifest. The immutable project ID, source SHA-256 and metadata, exact source and target profile IDs and versions, mapping and review revisions, artifact states, and application/schema versions form a reproducible local engineering record.

The manifest fingerprint is SHA-256 over compact, sorted-key JSON excluding `fingerprint`. The state fingerprint covers source content, exact profiles, mappings, reviews, and relevant schemas. Artifacts are `CURRENT`, `STALE`, `NOT_GENERATED`, `INVALID`, or `NOT_APPLICABLE`; timestamps do not establish validity. Source changes stale all derived state. Target changes preserve CP0/CP1 and stale target-specific artifacts. Mapping and review changes stale only their dependents. Stale candidates are not presented as current.

JSON writes use a temporary file, flush, `fsync`, and atomic replacement. Legacy workspace metadata migrates through the project-schema migration path after backup to `backup/pre-migration-project-v0/`. A newer unknown schema returns `PROJECT_SCHEMA_NEWER_THAN_APPLICATION` without mutation. Missing historical profiles return `PROFILE_NOT_AVAILABLE`; no newer registry profile replaces the saved exact version.

`GET /api/projects/{id}` opens persisted state without conversion. `POST /api/projects/{id}/validate` checks source identity, profile availability, files, hashes, and stale state. Validation reports `PASS`, `WARNING`, or `FAIL`; it does not claim device equivalence.

Project Export uses `convert-in.project-export/v1` and `<project-id>.convertin.zip`. It includes `source.cfg`, so treat it as sensitive configuration data. Import stays local, verifies source SHA-256, validates schemas and paths, rejects absolute/traversal/symlink entries, and never overwrites a collision. Limits: 110 MiB compressed, 220 MiB expanded, 2,000 files. A collision receives a new local project ID while retaining `origin_project_id`.

Project Export resumes engineering work. Evidence Pack supports audit handover and excludes source configuration by default.