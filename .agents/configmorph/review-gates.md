# ConfigMorph Review Gates

## Frontend

1. `frontend-ui-engineering`
2. `browser-testing-with-devtools`
3. Typecheck
4. Lint
5. Unit tests
6. Playwright
7. Visual screenshots where relevant
8. `code-review-and-quality`
9. OCR delegation review

Preserve backend semantics, accessibility, virtualization, local runtime assets, null-safe API handling, and current-result freshness.

## Parser, renderer, or vendor behavior

1. `source-driven-development`
2. Exact official evidence with reference ID and OS-version profile
3. TDD
4. Parser/renderer regression tests
5. CP0/CP1/CP2 semantic equality
6. `code-review`
7. OCR delegation review

No adjacent-version inheritance. Parser capability does not imply renderer capability. If exact behavior is not authoritative, use `MANUAL_REVIEW` or `VERSION_NOT_VERIFIED`.

## Performance

1. `diagnosing-bugs`
2. Baseline first
3. Real instrumentation
4. Semantic equality
5. Benchmark before/after
6. OCR delegation review

Never trade CP safety or deterministic accounting for speed.