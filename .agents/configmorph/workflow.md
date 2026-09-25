# ConfigMorph Agent Workflow

1. **Understand** — read `AGENTS.md`, task requirements, and `context-engineering` where scope is broad.
2. **Inspect** — preserve the worktree; use `diagnosing-bugs` for bugs or performance issues.
3. **Build a tight feedback loop** — reproduce and instrument before changing behavior.
4. **Specify acceptance criteria** — use `domain-modeling`, `api-and-interface-design`, or `source-driven-development` when applicable.
5. **Implement incrementally** — use `implement` or `incremental-implementation`; retain established architecture.
6. **Test** — use `tdd` or `test-driven-development`; prove semantic equality when required.
7. **Verify browser/runtime behavior** — use `frontend-ui-engineering` and `browser-testing-with-devtools` for UI work.
8. **Verify sources** — use `source-driven-development` or `research`; vendor behavior requires exact official evidence and an OS-version profile.
9. **Review** — use `code-review` and `code-review-and-quality`.
10. **Run OpenCodeReview** — `ocr delegate preview`, then `ocr delegate rule <paths>`; the host agent reviews. No OCR LLM provider required.
11. **Commit** — explicit staging only after validation.
12. **Push** — no force push.
13. **Verify exact-SHA CI** — report only observed status.
14. **Stop** — do not expand scope.

Use `debugging-and-error-recovery` for failures, `code-simplification` before adding abstractions, `codebase-design` for substantial module boundaries, and `resolving-merge-conflicts` only during an active merge/rebase.

## Dry-run routing

- FortiGate 7.0.13 parses incorrectly: `source-driven-development`, `diagnosing-bugs`, `tdd`, `code-review`, OCR delegation.
- Figma UI does not match target: `frontend-ui-engineering`, `browser-testing-with-devtools`, `incremental-implementation`, `code-review-and-quality`, OCR delegation.
- CP1 takes 120 seconds: `diagnosing-bugs`, `tdd` or `test-driven-development`, baseline instrumentation/benchmarking, `code-review`, OCR delegation.