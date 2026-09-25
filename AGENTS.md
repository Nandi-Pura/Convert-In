<!-- antislop:start -->
## antislop
For UI, copy, people, mobile layout, or code comments work, load the antislop skill for the task:
- Core filter, always on: `antislop`
- UI / visual: `antislop-ui`
- Copy & text: `antislop-copywriting`
- People: `antislop-human`
- Mobile / responsive: `antislop-layoutmobile`
- Code comments: `antislop-code`
Before starting, ask the user when antislop applies: during the work, or after it is done.
<!-- antislop:end -->

## ConfigMorph direction

For UI, copy, responsive layout, and code-comment work, apply the relevant antislop skill together with `DESIGN.md`.

`DESIGN.md` defines the project direction. antislop filters unwanted generic AI patterns. Neither replaces the other.

## Vendor semantics

Do not implement parser, migration, or renderer semantics from model knowledge alone. Locate official vendor documentation, record its reference ID, and associate behavior with an OS version profile. If authoritative evidence is unavailable, do not infer behavior; use `MANUAL_REVIEW` or `VERSION_NOT_VERIFIED`.

# ConfigMorph Agent Rules

## Product

ConfigMorph is a local-first Network Configuration Migration Workbench.

Tagline: **Visualize. Analyze. Migrate.**

## Canonical architecture

Vendor config → vendor parser → domain normalized IR → CP0 → CP1 → CP2 → target renderer → candidate configuration.

No pairwise translators. Keep `FirewallConfig`, `RouterConfig`, and `SwitchConfig` separate; do not create a universal `NetworkConfig`.

## Safety

Candidate output is never production-ready, vendor-certified, or device-validated. Label it **CANDIDATE CONFIGURATION — ENGINEER REVIEW REQUIRED**. No device deployment or mutation.

Preserve CP0 source-accounting semantics, CP1 reference-integrity semantics, CP2 compatibility/safety semantics, candidate safety, stable `convert-in.*` schema IDs, the 100 MiB source limit, project-persistence compatibility, and evidence source-exclusion defaults.

## Version policy

- Exact-version evidence required. A release line is not an exact version.
- No adjacent-version inheritance or nearest-patch mapping.
- Unknown exact versions remain exact and unverified.
- Source parser support does not imply target renderer support.

## CP0

Statuses: `NORMALIZED`, `RECOVERED`, `UNPARSED`, `SOURCE_UNSUPPORTED`, `IGNORED_NON_SEMANTIC`.

Semantic accounting must remain deterministic.

## CP1

Outcomes: `PASS`, `WARNING`, `BLOCKED`.

Preserve unresolved references, cycles, duplicates, ambiguity, invalid bindings, and dependency propagation. Never weaken blocked decisions for performance.

## CP2

Internal outcomes: `EXACT`, `SUPPORTED`, `PARTIAL`, `MANUAL_REVIEW`, `UNSUPPORTED`, `VERSION_NOT_VERIFIED`.

Only `EXACT` and `SUPPORTED` may emit target commands. User-facing outcomes: `READY`, `REVIEW REQUIRED`, `BLOCKED`. No compatibility or confidence percentage.

## Frontend

- React + TypeScript + Vite; production served by the FastAPI static bundle.
- Node is build-time only. No remote runtime fonts, scripts, CDNs, or cloud dependency.
- No body scroll on supported desktop workbench; internal panes scroll.
- Preserve virtualization for large configurations.
- Adopted Figma UI remains the visual source of truth.

## Security

No `eval`, shell execution from untrusted input, remote runtime JS/CSS, telemetry, analytics, configuration-content logging, or secret logging. No live device deployment.

## Git

Never run `git add .`, `git reset --hard`, `git clean -fd`, `git push --force`, auto-merge, release/tag creation, or package/image publication. Stage explicit paths only. Do not stage `convert_in.egg-info/` or the downloaded Figma source folder unless explicitly requested.

## Validation

Before product-change completion, run frontend typecheck, lint, build, tests; Python compileall and tests; browser tests; docs coverage; benchmark; Alembic; Docker Compose config; `git diff --check`. Apply only checks relevant to tooling-only changes.

## Review

Before commit: requirements check, code-quality review, targeted tests, then OpenCodeReview where available. OpenCodeReview reviews only; no auto-fix or auto-commit unless explicitly requested.

## Agent stack

- Cline: orchestration and tools.
- 9router: model transport and routing; no repository secrets or configuration required.
- Codex: reasoning and implementation.
- `.agents/skills/`: repository-local execution guidance.
- OpenCodeReview delegation mode: deterministic file/rule selection; host agent performs review without a second LLM provider.

Read `.agents/configmorph/project-rules.md`, `.agents/configmorph/workflow.md`, and `.agents/configmorph/review-gates.md` as applicable.

## Scope

Do not start Q28 without explicit instruction.
