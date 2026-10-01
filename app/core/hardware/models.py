from dataclasses import dataclass
from enum import StrEnum

from app.core.models import ConfigDomain
from app.core.platforms import NetworkVendor


class SupportStatus(StrEnum):
    SUPPORTED = "SUPPORTED"
    UNSUPPORTED = "UNSUPPORTED"
    VERSION_NOT_VERIFIED = "VERSION_NOT_VERIFIED"
    UNKNOWN_HARDWARE = "UNKNOWN_HARDWARE"
    UNKNOWN_SOFTWARE = "UNKNOWN_SOFTWARE"


class SupportScope(StrEnum):
    RELEASE_TRAIN = "RELEASE_TRAIN"
    EXACT_VERSION = "EXACT_VERSION"


class HardwareSelectionStatus(StrEnum):
    AUTO_DETECTED = "AUTO_DETECTED"
    MANUAL = "MANUAL"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class HardwareProfile:
    id: str
    domain: ConfigDomain
    vendor: NetworkVendor
    product_family: str
    model: str
    evidence_refs: tuple[str, ...]
    generation: str | None = None
    architecture: str | None = None
    form_factor: str | None = None
    capabilities: tuple[str, ...] = ()
    constraints: tuple[str, ...] = ()


@dataclass(frozen=True)
class HardwareSelection:
    status: HardwareSelectionStatus = HardwareSelectionStatus.UNKNOWN
    hardware_id: str | None = None


@dataclass(frozen=True)
class HardwareSoftwareSupport:
    hardware_id: str
    os_family: str
    exact_version: str
    status: SupportStatus = SupportStatus.VERSION_NOT_VERIFIED
    evidence_refs: tuple[str, ...] = ()
    constraints: tuple[str, ...] = ()
    support_scope: SupportScope = SupportScope.EXACT_VERSION
    minimum_version: str | None = None

class PortConnector(StrEnum):
    RJ45 = "RJ45"
    SFP = "SFP"
    SFP_PLUS = "SFP_PLUS"
    SFP28 = "SFP28"
    QSFP = "QSFP"
    QSFP_PLUS = "QSFP_PLUS"
    QSFP28 = "QSFP28"
    UNKNOWN = "UNKNOWN"


class MediaCapability(StrEnum):
    COPPER = "COPPER"
    TRANSCEIVER = "TRANSCEIVER"
    UNKNOWN = "UNKNOWN"


class PortSpeed(StrEnum):
    M10 = "10M"
    M100 = "100M"
    G1 = "1G"
    G2_5 = "2_5G"
    G5 = "5G"
    G10 = "10G"
    G25 = "25G"
    G40 = "40G"
    G100 = "100G"


class PortMappingStatus(StrEnum):
    EXACT = "EXACT"
    COMPATIBLE = "COMPATIBLE"
    REQUIRES_REMAP = "REQUIRES_REMAP"
    INCOMPATIBLE = "INCOMPATIBLE"
    UNVERIFIED = "UNVERIFIED"
    UNMAPPED = "UNMAPPED"


@dataclass(frozen=True)
class PortCapability:
    hardware_id: str
    interface_name: str
    physical_port_number: int | str
    interface_family: str
    connector: PortConnector
    media_capability: MediaCapability
    supported_speeds: tuple[PortSpeed, ...]
    supports_layer3: bool
    supports_subinterface: bool
    supports_aggregate_membership: bool
    breakout_capable: bool = False
    breakout_parent: str | None = None
    evidence_refs: tuple[str, ...] = ()
    constraints: tuple[str, ...] = ()


@dataclass(frozen=True)
class SourceInterfaceContext:
    configured_speed: PortSpeed | None = None
    requires_layer3: bool = True
    requires_subinterface: bool = False


@dataclass(frozen=True)
class PortCompatibility:
    status: PortMappingStatus
    reasons: tuple[str, ...]
    evidence_refs: tuple[str, ...]


@dataclass(frozen=True)
class TargetPortCandidate:
    target_interface: str
    status: PortMappingStatus
    reasons: tuple[str, ...]
    already_assigned: bool
    evidence_refs: tuple[str, ...]
