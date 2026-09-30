from dataclasses import asdict, replace

from app.core.documentation import documentation_reference
from app.core.models import ConfigDomain
from app.core.platforms import NetworkVendor

from .models import HardwareProfile, HardwareSoftwareSupport, SupportScope, SupportStatus


_PALO_ALTO_FAMILIES = {
    "PA-400 Series": ("410", "415", "415-5G", "440", "445", "450", "455", "455-5G", "460"),
    "PA-800 Series": ("820", "850"),
    "PA-1400 Series": ("1410", "1420"),
    "PA-3200 Series": ("3220", "3250", "3260"),
    "PA-3400 Series": ("3410", "3420", "3430", "3440"),
    "PA-5200 Series": ("5220", "5250", "5260", "5280"),
    "PA-5400 Series": ("5410", "5420", "5430", "5440", "5445", "5450"),
}
_PALO_ALTO_IDENTITY_REFS = tuple(
    family.replace(" Series", "") + "-HARDWARE-OVERVIEW"
    for family in _PALO_ALTO_FAMILIES
)
_IDENTITY_REF_IDS = (*_PALO_ALTO_IDENTITY_REFS, "CISCO-CATALYST-9300-DATASHEET")
IDENTITY_EVIDENCE = {
    reference_id: str(documentation_reference(reference_id).official_url)
    for reference_id in _IDENTITY_REF_IDS
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


def _palo_alto_profiles() -> tuple[HardwareProfile, ...]:
    return tuple(
        HardwareProfile(
            f"paloalto-pa{model.lower()}",
            ConfigDomain.FIREWALL,
            NetworkVendor.PALO_ALTO,
            family,
            f"PA-{model}",
            (family.replace(" Series", "") + "-HARDWARE-OVERVIEW",),
        )
        for family, models in _PALO_ALTO_FAMILIES.items()
        for model in models
    )


HARDWARE_PROFILES = validate_registry((
    *_palo_alto_profiles(),
    HardwareProfile(
        "cisco-c9300-48p",
        ConfigDomain.SWITCH,
        NetworkVendor.CISCO,
        "Catalyst 9300 Series",
        "C9300-48P",
        ("CISCO-CATALYST-9300-DATASHEET",),
    ),
))


PALO_ALTO_COMPATIBILITY_GROUPS = {
    "paloalto-pa400-440-450-460": tuple(f"paloalto-pa{x}" for x in ("440", "450", "460")),
    "paloalto-pa800-series": tuple(f"paloalto-pa{x}" for x in ("820", "850")),
    "paloalto-pa1400-series": tuple(f"paloalto-pa{x}" for x in ("1410", "1420")),
    "paloalto-pa3200-series": tuple(f"paloalto-pa{x}" for x in ("3220", "3250", "3260")),
    "paloalto-pa3400-series": tuple(f"paloalto-pa{x}" for x in ("3410", "3420", "3430", "3440")),
    "paloalto-pa5200-series": tuple(f"paloalto-pa{x}" for x in ("5220", "5250", "5260", "5280")),
    "paloalto-pa5400-early": tuple(f"paloalto-pa{x}" for x in ("5410", "5420", "5430")),
}
_MATRIX = ("PANOS-HARDWARE-COMPATIBILITY-MATRIX",)
_TRAINS = ("10.1", "10.2", "11.0", "11.1", "11.2", "12.1", "12.2")


def _release_train_rules(
    hardware_or_group: str,
    supported: tuple[str, ...],
    minimum: dict[str, str] | None = None,
) -> tuple[HardwareSoftwareSupport, ...]:
    minimum = dict(minimum or {})
    if "12.1" in supported:
        minimum.setdefault("12.1", "12.1.2")
    return tuple(
        HardwareSoftwareSupport(
            hardware_or_group,
            "PAN-OS",
            train,
            SupportStatus.SUPPORTED if train in supported else SupportStatus.UNSUPPORTED,
            _MATRIX,
            (f"PAN-OS {train} support begins at {minimum[train]}.",) if train in minimum else (),
            SupportScope.RELEASE_TRAIN,
            minimum.get(train),
        )
        for train in _TRAINS
    )


def _supported_rule(
    hardware_id: str,
    version: str,
    evidence: str,
    scope: SupportScope = SupportScope.EXACT_VERSION,
) -> HardwareSoftwareSupport:
    return HardwareSoftwareSupport(
        hardware_id,
        "PAN-OS",
        version,
        SupportStatus.SUPPORTED,
        (evidence,),
        (),
        scope,
    )


_PA400_MODEL_RULES = (
    ("paloalto-pa410", ("10.1", "10.2", "11.0", "11.1", "11.2", "12.1"), {"10.1": "10.1.2"}),
    ("paloalto-pa415", ("11.0", "11.1", "11.2", "12.1"), {}),
    ("paloalto-pa415-5g", ("11.1", "11.2", "12.1"), {}),
    ("paloalto-pa445", ("11.0", "11.1", "11.2", "12.1", "12.2"), {}),
    ("paloalto-pa455", ("11.1", "11.2", "12.1", "12.2"), {}),
    ("paloalto-pa455-5g", ("11.2", "12.1", "12.2"), {"11.2": "11.2.3"}),
)

HARDWARE_SOFTWARE_SUPPORT = (
    HardwareSoftwareSupport(
        "cisco-c9300-48p", "IOS-XE", "17.12.1", SupportStatus.SUPPORTED,
        ("CISCO-CATALYST-9300-DATASHEET", "IOSXE-17.12.1-C9300-RELEASE"),
    ),
    *_release_train_rules("paloalto-pa400-440-450-460", _TRAINS),
    *(rule for hardware_id, supported, minimum in _PA400_MODEL_RULES
      for rule in _release_train_rules(hardware_id, supported, minimum)),
    *_release_train_rules("paloalto-pa800-series", ("10.1", "10.2", "11.0", "11.1")),
    *_release_train_rules("paloalto-pa1400-series", ("11.0", "11.1", "11.2", "12.1", "12.2")),
    *_release_train_rules("paloalto-pa3200-series", ("10.1", "10.2", "11.0", "11.1")),
    *_release_train_rules("paloalto-pa3400-series", ("10.2", "11.0", "11.1", "11.2", "12.1", "12.2")),
    *_release_train_rules("paloalto-pa5200-series", ("10.1", "10.2", "11.0", "11.1", "11.2")),
    *_release_train_rules("paloalto-pa5400-early", ("10.2", "11.0", "11.1", "11.2", "12.1", "12.2")),
    *_release_train_rules("paloalto-pa5440", ("11.0", "11.1", "11.2", "12.1", "12.2")),
    *_release_train_rules("paloalto-pa5445", ("11.1", "11.2", "12.1", "12.2")),
    *_release_train_rules("paloalto-pa5450", _TRAINS),
    *(_supported_rule(f"paloalto-pa{x}", "10.1.0", "PA-400-HARDWARE-OVERVIEW") for x in ("440", "450", "460")),
    _supported_rule("paloalto-pa410", "10.1.2", "PA-400-HARDWARE-OVERVIEW"),
    _supported_rule("paloalto-pa455-5g", "11.2.3", "PA-400-HARDWARE-OVERVIEW"),
    *(_supported_rule(f"paloalto-pa{x}", "8.0", "PA-800-HARDWARE-OVERVIEW", SupportScope.RELEASE_TRAIN) for x in ("820", "850")),
    *(_supported_rule(f"paloalto-pa{x}", "8.1", "PA-3200-HARDWARE-OVERVIEW", SupportScope.RELEASE_TRAIN) for x in ("3220", "3250", "3260")),
    *(_supported_rule(f"paloalto-pa{x}", "8.0", "PA-5200-HARDWARE-OVERVIEW", SupportScope.RELEASE_TRAIN) for x in ("5220", "5250", "5260")),
    _supported_rule("paloalto-pa5280", "8.1", "PA-5200-HARDWARE-OVERVIEW", SupportScope.RELEASE_TRAIN),
    *(_supported_rule(f"paloalto-pa{x}", "10.2.0", "PA-5400-HARDWARE-OVERVIEW") for x in ("5410", "5420", "5430")),
    _supported_rule("paloalto-pa5440", "11.0.0", "PA-5400-HARDWARE-OVERVIEW"),
    _supported_rule("paloalto-pa5445", "11.1.0", "PA-5400-HARDWARE-OVERVIEW"),
    _supported_rule("paloalto-pa5450", "10.1.0", "PA-5400-HARDWARE-OVERVIEW"),
)


def compatibility_groups_for(hardware_id: str) -> tuple[str, ...]:
    return tuple(group for group, members in PALO_ALTO_COMPATIBILITY_GROUPS.items() if hardware_id in members)


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


def _support_payload() -> list[dict[str, object]]:
    rows = []
    for support in HARDWARE_SOFTWARE_SUPPORT:
        members = PALO_ALTO_COMPATIBILITY_GROUPS.get(support.hardware_id)
        expanded = (replace(support, hardware_id=member) for member in members) if members else (support,)
        rows.extend(asdict(item) for item in expanded)
    return rows


def hardware_registry_payload() -> dict[str, object]:
    evidence_ids = {ref for profile in HARDWARE_PROFILES for ref in profile.evidence_refs}
    evidence_ids.update(ref for support in HARDWARE_SOFTWARE_SUPPORT for ref in support.evidence_refs)
    return {
        "hardware_profiles": [asdict(profile) for profile in HARDWARE_PROFILES],
        "hardware_software_support": _support_payload(),
        "identity_evidence": dict(IDENTITY_EVIDENCE),
        "evidence": {reference_id: _evidence(reference_id) for reference_id in sorted(evidence_ids)},
    }
