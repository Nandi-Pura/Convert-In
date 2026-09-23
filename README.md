# Convert-In

Convert-In is a local multi-vendor, multi-domain configuration migration workbench.

## Unified workbench

1. Drop or paste a synthetic or sanitized Cisco ASA, FortiGate, or Juniper SRX configuration.
2. Confirm the source vendor and OS version.
3. Select a same-domain target independently of the source vendor.
4. Convert when the selected target has an evidence-gated renderer. Otherwise use analysis mode.
5. Review each entity's source, target or normalized form, semantic findings, and checkpoint status.
6. Copy only **READY** firewall entities or download the complete candidate configuration.

Generated output requires engineer review. No deployment or device validation occurs.

Assurance pipeline: [CP0 Source Extraction Coverage](docs/extraction-coverage.md) → [CP1 Reference Integrity](docs/reference-integrity.md) → [CP2 Semantic Compatibility](docs/semantic-compatibility.md) → evidence-gated candidate renderer. Checkpoints remain independent. None claims migration accuracy.

See [Unified workbench](docs/ui-workbench.md) for copy gates and interaction details. **Advanced Workbench** remains available at `/advanced` for visualization, mapping, compatibility evidence, semantic review, application validation, optional PAN lab validation, and package export.

Current capabilities:

- Cisco ASA, FortiGate, and Palo Alto PAN-OS XML parsing
- Juniper SRX Junos 23.4R2 set-style source parsing and bounded PAN-OS candidate generation
- Cisco IOS-XE 17.12.1 router parsing plus bounded Junos 23.4R2 target rendering
- separate RouterConfig and SwitchConfig foundations; no router/switch conversion claim
- a normalized vendor-neutral firewall model
- object and policy dependency visualization
- configuration and impact analysis
- Cisco ASA and FortiGate → PAN-OS migration assistance
- semantic migration review
- candidate PAN-OS set-command generation
- bounded FortiOS 7.6.4 candidate generation from normalized firewall IR

> **Generated configurations require engineer review.** Convert-In does not validate against a device or deploy configurations.

## Local-first by design

**No firewall configuration is uploaded externally. No cloud API is required. No telemetry. No analytics. No external AI API.** All processing and persistence stay on the local machine. The default bind is `127.0.0.1`.

Inputs are limited to 100 MiB by UTF-8 byte length, PAN XML uses `defusedxml`, configuration bodies are not logged, and CSP/security headers are set. Workspace files contain sensitive plaintext; protect local filesystem access and never commit `data/` or `workspace/`.

## Screenshots

Synthetic screenshots: [firewall conversion](docs/images/workbench-firewall.png) and [IOS-XE analysis](docs/images/workbench-iosxe.png). Existing advanced-workbench captures remain under `docs/images/`.

## Q1 support matrix

| Area | Capability | Status |
|---|---|---|
| Supported generation source | Cisco ASA 9.20, 9.22, 9.24 | Explicit profiles |
| Supported generation source | FortiOS 7.4, 7.6 | Explicit profiles |
| Source parsing | PAN-OS XML | MVP |
| Analysis | Dependencies, unused objects, duplicates, unresolved references | MVP |
| Analysis | Impact analysis, potential shadowing | MVP |
| Visualization | Policy graph, object dependencies, impact scope | MVP |
| Migration | Cisco ASA → PAN-OS | Candidate generation |
| Migration | FortiGate → PAN-OS | Alpha / candidate |
| Migration | ASA, FortiGate, PAN-OS, or SRX → FortiOS 7.6.4 | Bounded candidate generation |
| Supported generation target | PAN-OS 11.1 or FortiOS 7.6.4 | Bounded; engineer review required |
| Generated subset | Addresses/groups, services/groups, supported security policies, supported static routes | Documentation-gated |
| Review / non-generated | NAT, ambiguous target context, interface/zone mapping, advanced semantics, unverified versions | Inline comments |
| Blocked | PAN-OS 12.1, Panorama, live deployment | Not supported by Quick Convert |

Coverage is intentionally bounded by tests. Convert-In does **not** claim full vendor conversion.

## Run locally

```bash
python -m venv .venv
.venv/Scripts/activate
python -m pip install -e ".[test]"
alembic upgrade head
uvicorn app.main:app --host 127.0.0.1 --port 8080
```

Open <http://127.0.0.1:8080>.

## Docker

```bash
docker compose build
docker compose up -d
```

Compose publishes only `127.0.0.1:8080`. Intentionally exposing to a network requires changing the host-side bind; add authentication and TLS first.

### Corporate CA during Docker build

TLS verification remains enabled. Export the path to a PEM-encoded corporate root/intermediate bundle before building:

```powershell
$env:CORPORATE_CA_FILE = "C:\secure\corporate-ca.crt"
docker compose build --no-cache
```

Compose passes it as a BuildKit secret. `--no-cache` is required when changing the secret because secret contents do not invalidate BuildKit cache. The certificate is copied into the image trust store only when explicitly supplied; it is never copied into the build context or an intermediate layer. Files under `certs/` are ignored except the empty default placeholder. Do not commit corporate certificates. Without interception, omit the variable and normal public CA verification is used.

## Architecture

```text
Vendor Config
      ↓
Vendor Parser
      ↓
Normalized Firewall IR
      ↓
 ┌────┼──────────┐
 ↓    ↓          ↓
Analyze Visualize Migration
                   ↓
             Compatibility
                   ↓
                Mapping
                   ↓
                Renderer
                   ↓
            Candidate Config
```

Analysis and migration consume the normalized `FirewallConfig` IR. Conversion does not translate vendor syntax directly: normalization preserves intent, compatibility makes unsupported semantics visible, mappings capture target context, and rendering emits only the supported candidate subset.

Project workspaces contain `source.cfg`, `normalized.json`, and lightweight `analysis.json`. Migration adds a separate `migration/` artifact directory and never modifies source or normalized artifacts.

Analysis APIs:

- `GET /api/projects/{project_id}/analysis`
- `GET /api/projects/{project_id}/graph`
- `GET /api/projects/{project_id}/impact/{object_id}`
- `GET /api/projects/{project_id}/objects/{object_id}/references`
- `GET /api/projects/{project_id}/migration/compatibility`
- `GET /api/projects/{project_id}/semantic-compatibility`
- `GET|PUT /api/projects/{project_id}/migration/mappings`
- `POST /api/projects/{project_id}/migration/plan`
- `POST /api/projects/{project_id}/migration/render`
- `GET /api/projects/{project_id}/migration/report`
- `GET /api/projects/{project_id}/migration/download/{config|report}`
- `GET /api/projects/{project_id}/migration/review`
- `GET|PUT /api/projects/{project_id}/migration/review/{entity_id}`
- `POST|GET /api/projects/{project_id}/migration/validate|validation`
- `GET /api/projects/{project_id}/migration/review-package`

## Testing

```bash
python -m compileall -q app
pytest -q
node --check app/static/js/app.js
```

## Known limitations

- advanced ASA twice NAT, identity NAT, and destination NAT beyond proven cases
- outbound ACL migration
- VPN and dynamic routing migration
- advanced vendor security profiles
- FortiGate central NAT, multiple VDOM flattening, SD-WAN, and advanced VIP behavior
- IPv6 topology limitations
- device-level validation and live deployment

See [migration details](docs/migration.md), [version-aware support matrix](docs/support-matrix.md), [documentation policy](docs/documentation-policy.md), and the [review workflow](docs/review.md).

## Contributing and security

Read [CONTRIBUTING.md](CONTRIBUTING.md) before submitting changes. Never include real customer firewall configurations or secrets in issues, fixtures, or pull requests. Report vulnerabilities through [GitHub private vulnerability reporting](../../security/advisories/new); see [SECURITY.md](SECURITY.md).

## Release

Current development version: **0.2.0-alpha.1**. The corresponding prerelease is published. Alpha software; not production-ready. See [CHANGELOG.md](CHANGELOG.md).

## Roadmap

Next recommended phase: independent PAN-OS lab validation, richer FortiGate NAT fixtures, and usability hardening. PAN-OS → FortiGate remains unimplemented.

## License

Apache-2.0. See [LICENSE](LICENSE). Third-party attributions: [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).