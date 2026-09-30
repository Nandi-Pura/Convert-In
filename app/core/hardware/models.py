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
