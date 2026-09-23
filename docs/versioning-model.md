# Versioning model

Audit date: 2026-09-21.

A **release line** is the compact user choice, such as FortiOS 7.6. An **exact version** is the immutable firmware identity, such as 7.6.7. The registry orders release lines explicitly; it never lexical-sorts vendor version strings.

`LATEST_VERIFIED` means the latest known exact release in that audited line according to bundled official evidence. It does not mean automatically tracked firmware. `LEGACY_VERIFIED` retains a previously evidenced exact release for reproducibility. `VERSION_NOT_VERIFIED` records a known candidate whose latest-release, platform, syntax, or semantic evidence is incomplete.

Release evidence and renderer evidence are separate. Release notes establish existence. Each emitting capability also needs exact-version syntax evidence, semantic evidence, implementation, and tests. Evidence never inherits from an adjacent release line or patch. Missing evidence produces no command emission and never silently selects another version.

Metadata is static and offline. Existing workspace artifacts retain their selected exact version. Adding a newer patch creates a new profile and changes the old profile status; it never changes the old profile identity.