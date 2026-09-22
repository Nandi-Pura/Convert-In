# Source Extraction Coverage (CP0)

CP0 answers: “How much of the source configuration did Convert-In recognize, parse, normalize, and account for?” It is deterministic parser accounting. It is not accuracy, confidence, compatibility, migration success, or device validation.

## Accounting

A source construct is a semantic object or rule, not a line. Blank lines, comments, delimiters, hierarchy commands, metadata, and fields nested under an object do not increase `semantic_total`.

```text
semantic_total = NORMALIZED + RECOVERED + UNPARSED + SOURCE_UNSUPPORTED
normalized_effective = NORMALIZED + RECOVERED
coverage_percent = normalized_effective / semantic_total * 100
```

Coverage is unavailable when `semantic_total` is zero. Conversion is blocked for zero semantic constructs. Parser errors block Quick Convert. Lower nonzero coverage remains convertible with visible engineering review records; CP0 percentages never describe target migration quality.

Outcomes:

- `NORMALIZED`: source construct produced normalized IR.
- `RECOVERED`: normalized IR exists, but malformed or unsupported nested source data remains visible.
- `UNPARSED`: potentially semantic source could not be normalized safely.
- `SOURCE_UNSUPPORTED`: recognized valid source section is intentionally unsupported.
- `IGNORED_NON_SEMANTIC`: excluded comments, blanks, delimiters, and metadata; reported only as a count.

Stable item IDs hash vendor, category, source identity, and location. Items list normalized entity IDs, enabling source-to-IR lineage without copying source bodies into the report. Reports are serialized inside `normalized.json`. Raw source text is not returned by CP0 APIs or logged.

## Vendor scope

ASA accounting covers parsed interfaces, objects/groups, services/groups, ACL entries, NAT, and routes. `nameif` zones and inline ACL services share their parent source item. Access-group bindings enrich their ACL rule; they are not counted separately. Unknown syntax is `UNPARSED`.

FortiGate accounting treats each `edit` object as one construct. `set` fields do not inflate totals. Supported interface, zone, address/group, service/group, policy, VIP/NAT, and route objects are accounted. Truncated objects and objects with preserved unsupported fields are `RECOVERED`. Recognized unsupported configuration sections are `SOURCE_UNSUPPORTED`.

PAN-OS XML CP0 is not implemented in Q2.