# Contributing to ConfigMorph

## Setup

Use Python 3.12. Create and activate `.venv`, then run:

```powershell
python -m pip install -e ".[test]"
alembic upgrade head
python -m compileall -q app
pytest -q
node --check app/static/js/app.js
```

`pytest` creates and migrates isolated temporary data and workspace directories. It never uses `data/studio.db` or `workspace/`.

## Architecture principles

- Parse vendor input into the normalized `FirewallConfig` IR first.
- Analysis, visualization, compatibility, and rendering consume normalized IR—not source syntax.
- Keep unsupported semantics visible. Never silently broaden conversion claims.
- Render candidates only. Engineer review remains mandatory; no deployment features.
- Prefer small, deterministic changes over new abstractions.

## Parsers and renderers

Parser changes need minimal synthetic fixtures, malformed-input coverage, and updated golden normalized output where behavior intentionally changes. Renderer changes must consume normalized IR, declare compatibility limits, preserve traceability, and include deterministic golden candidate output. A new parser or renderer requires documentation of supported and unsupported semantics.

Any pull request changing vendor parsing semantics, migration compatibility, or renderer behavior must include an official vendor documentation reference ID, affected OS family, synthetic fixture, and explicit expected behavior. Undocumented semantic changes are not accepted.

## Security and test data

Never submit real customer configurations, customer identifiers/IP addressing, credentials, tokens, certificates, workspace data, or generated customer candidates. This applies to commits, issues, discussions, logs, and screenshots. Use documentation networks (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) or clearly synthetic RFC1918 data. Provide the smallest sanitized reproducer.

## Style and pull requests

Follow existing Python and JavaScript conventions. Keep code direct and typed through existing Pydantic models. Run all checks above. Pull requests should explain scope, compatibility impact, tests, security/data review, and documentation changes. Keep unrelated product features out of the change.