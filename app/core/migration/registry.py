from dataclasses import dataclass
from enum import StrEnum
from app.core.models import Vendor
from .sources import CiscoAsaSourceAdapter, FortiGateSourceAdapter, MigrationSourceAdapter


@dataclass(frozen=True)
class MigrationPair:
    source_adapter: type[MigrationSourceAdapter]
    target_renderer: str
    features: frozenset[str]
    documentation_profile: str
    supported_source_profiles: frozenset[str]
    supported_target_profiles: frozenset[str]

class QuickConvertRole(StrEnum): SOURCE="SOURCE"; TARGET="TARGET"

@dataclass(frozen=True)
class VendorProfile:
    vendor: Vendor
    label: str
    role: QuickConvertRole
    versions: tuple[str, ...]
    management_modes: tuple[str, ...] = ()

QUICK_CONVERT_PROFILES = (
    VendorProfile(Vendor.ASA,"Cisco ASA",QuickConvertRole.SOURCE,("9.20","9.22","9.24")),
    VendorProfile(Vendor.FORTIGATE,"FortiGate",QuickConvertRole.SOURCE,("7.4","7.6")),
    VendorProfile(Vendor.PALO_ALTO,"Palo Alto Networks",QuickConvertRole.TARGET,("11.1",),("LOCAL_FIREWALL",)),
)


SUPPORTED_MIGRATION_PAIRS = {
    (Vendor.ASA, Vendor.PALO_ALTO): MigrationPair(CiscoAsaSourceAdapter, "PaloAltoRenderer", frozenset({"policy", "nat", "route"}), "asa-to-pan", frozenset({"asa-9.20","asa-9.22","asa-9.24"}), frozenset({"panos-11.1","panos-12.1"})),
    (Vendor.FORTIGATE, Vendor.PALO_ALTO): MigrationPair(FortiGateSourceAdapter, "PaloAltoRenderer", frozenset({"policy", "nat", "vip", "route"}), "fortigate-to-pan", frozenset({"fortios-7.4","fortios-7.6"}), frozenset({"panos-11.1","panos-12.1"})),
}


def migration_pair(source: Vendor | str, target: Vendor | str = Vendor.PALO_ALTO) -> MigrationPair:
    try:
        pair = SUPPORTED_MIGRATION_PAIRS[(Vendor(source), Vendor(target))]
    except (ValueError, KeyError) as exc:
        raise ValueError(f"Unsupported migration pair: {source} to {target}") from exc
    return pair