from dataclasses import asdict

from app.core.documentation import documentation_reference
from app.core.models import ConfigDomain
from app.core.platforms import NetworkVendor

from .models import HardwareProfile, HardwareSoftwareSupport, SupportStatus


IDENTITY_EVIDENCE = {
    "PA-5200-HARDWARE-OVERVIEW": "https://docs.paloaltonetworks.com/hardware/pa-5200-hardware-reference/pa-5200-series-firewall-overview",
    "PA-5400-PHYSICAL-SPECIFICATIONS": "https://docs.paloaltonetworks.com/hardware/pa-5400-hardware-reference/pa-5400-series-firewall-specifications/pa-5400-series-firewall-physical-specifications",
    "CISCO-CATALYST-9300-DATASHEET": "https://www.cisco.com/c/en/us/products/collateral/switches/catalyst-9300-series-switches/nb-06-cat9300-ser-data-sheet-cte-en.html",
}


def validate_registry(profiles: tuple[HardwareProfile, ...]) -> tuple[HardwareProfile, ...]:
    ids: set[str] = set()
    identities: set[tuple[NetworkVendor, str, str]] = set()
    for profile in profiles:
        identity = (profile.vendor, profile.product_family, profile.model)
        if profile.id in ids or identity in identities:
            raise ValueError("Duplicate hardware identity")
        if not profile.evidence_refs or any(ref not in IDENTITY_EVIDENCE for ref in profile.evidence_refs):
            raise ValueError("Hardware identity evidence required")
        ids.add(profile.id)
        identities.add(identity)
    return tuple(sorted(profiles, key=lambda profile: profile.id))


HARDWARE_PROFILES = validate_registry((
    HardwareProfile("paloalto-pa5220", ConfigDomain.FIREWALL, NetworkVendor.PALO_ALTO,
                    "PA-5200 Series", "PA-5220", ("PA-5200-HARDWARE-OVERVIEW",)),
    HardwareProfile("paloalto-pa5410", ConfigDomain.FIREWALL, NetworkVendor.PALO_ALTO,
                    "PA-5400 Series", "PA-5410", ("PA-5400-PHYSICAL-SPECIFICATIONS",)),
    HardwareProfile("cisco-c9300-48p", ConfigDomain.SWITCH, NetworkVendor.CISCO,
                    "Catalyst 9300 Series", "C9300-48P", ("CISCO-CATALYST-9300-DATASHEET",)),
))

HARDWARE_SOFTWARE_SUPPORT = (
    HardwareSoftwareSupport(
        "cisco-c9300-48p", "IOS-XE", "17.12.1", SupportStatus.SUPPORTED,
        ("CISCO-CATALYST-9300-DATASHEET", "IOSXE-17.12.1-C9300-RELEASE"),
    ),
    HardwareSoftwareSupport(
        "paloalto-pa5220", "PAN-OS", "12.1.6", SupportStatus.UNSUPPORTED,
        ("PANOS-HARDWARE-COMPATIBILITY-MATRIX", "PANOS-12.1.6-RELEASE"),
        ("PA-5200 Series is not listed as supporting PAN-OS 12.1.",),
    ),
)


def _evidence(reference_id: str) -> dict[str, str]:
    reference = documentation_reference(reference_id)
    return {
        "id": reference.id,
        "source": "Cisco" if reference.vendor.value == "cisco_iosxe" else reference.vendor.value,
        "title": reference.title,
        "reference": str(reference.official_url),
        "revision": reference.version_family,
        "section": reference.topic,
        "verified_at": reference.verified_at.isoformat(),
    }


def hardware_registry_payload() -> dict[str, object]:
    evidence_ids = {ref for profile in HARDWARE_PROFILES for ref in profile.evidence_refs}
    evidence_ids.update(ref for support in HARDWARE_SOFTWARE_SUPPORT for ref in support.evidence_refs)
    return {
        "hardware_profiles": [asdict(profile) for profile in HARDWARE_PROFILES],
        "hardware_software_support": [asdict(support) for support in HARDWARE_SOFTWARE_SUPPORT],
        "identity_evidence": dict(IDENTITY_EVIDENCE),
        "evidence": {reference_id: _evidence(reference_id) for reference_id in sorted(evidence_ids)},
    }
