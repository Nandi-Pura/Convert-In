# Blocker report

## Current Q

Q12: Firewall semantic coverage hardening

## Exact blocker

The required Q12 emitting semantics cannot be established safely from the official evidence currently available in the repository or from the official pages inspected on 2026-09-21.

Q12 requires exact-version syntax and semantic evidence for interface and zone context, disabled rules, ICMP, source ports, multiple service ranges, nested groups, FQDN addresses, IPv6 addresses, logging, schedules, and static-route options across ASA, FortiOS, PAN-OS, and Juniper SRX. Existing bundled references support narrower legacy renderer subsets. They do not establish every required Q12 behavior for all four exact target profiles. Extending emission would require inference or adjacent-version inheritance.

PAN-OS 12.2.3 and 12.1.6 release-note URLs in `docs/vendor-reference/q11-releases.yaml` returned HTTP 404 during the audit. The PAN-OS 11.2.9 page exists and was updated on 2026-09-09, but links to PAN-OS 11.2.10, so it does not prove that 11.2.9 is latest in its line. The Junos OS product index did not provide exact SRX release, date, latest-in-line, command, or semantic evidence for 25.4, 25.2, or 24.4.

## Evidence inspected

- `docs/vendor-reference/asa.yaml`
- `docs/vendor-reference/fortios.yaml`
- `docs/vendor-reference/panos.yaml`
- `docs/vendor-reference/junos.yaml`
- `docs/vendor-reference/q11-releases.yaml`
- <https://docs.paloaltonetworks.com/pan-os/12-2/pan-os-release-notes/pan-os-12-2-3-known-and-addressed-issues> (HTTP 404)
- <https://docs.paloaltonetworks.com/pan-os/12-1/pan-os-release-notes/pan-os-12-1-6-known-and-addressed-issues> (HTTP 404)
- <https://docs.paloaltonetworks.com/pan-os/11-2/pan-os-release-notes/pan-os-11-2-9-known-and-addressed-issues>
- <https://www.juniper.net/documentation/product/us/en/junos-os>

## Safe options

1. Supply exact official command and semantic references for each Q12 capability and exact legacy target release: ASA 9.24, FortiOS 7.6.4, PAN-OS 11.1, SRX 23.4R2.
2. Narrow Q12 acceptance to capabilities already proven by bundled exact-version references; keep every other construct `MANUAL_REVIEW`, `UNSUPPORTED`, or `VERSION_NOT_VERIFIED`.
3. Keep Q12 blocked. Continue no later phase because the roadmap requires sequential completed phases.

## Recommended option

Option 1. Build an evidence table per capability and exact target before changing parsers, CP2, or renderers. Release evidence must remain separate from syntax and semantic evidence.

## Current SHA

`9d09eb727fd20d3c6cea93674a1c3a6447a6fc0c`

Branch: `feature/roadmap-q12-q30`

Q11 remote SHA: `9d09eb727fd20d3c6cea93674a1c3a6447a6fc0c`