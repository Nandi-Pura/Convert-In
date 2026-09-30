from app.core.models import ConfigDomain
from app.core.platforms import NetworkVendor

from .models import HardwareProfile, HardwareSelection, HardwareSoftwareSupport, SupportStatus
from .registry import HARDWARE_PROFILES, HARDWARE_SOFTWARE_SUPPORT


def resolve_hardware(
    domain: ConfigDomain,
    vendor: NetworkVendor,
    product_family: str | None = None,
    model: str | None = None,
) -> HardwareProfile | None:
    return next((profile for profile in HARDWARE_PROFILES
                 if profile.domain == domain and profile.vendor == vendor
                 and profile.model == model
                 and (product_family is None or profile.product_family == product_family)), None)


def detect_hardware(source: str) -> HardwareSelection:
    return HardwareSelection()


def resolve_hardware_software_support(
    hardware_id: str, os_family: str, exact_version: str,
) -> HardwareSoftwareSupport:
    hardware = next((profile for profile in HARDWARE_PROFILES if profile.id == hardware_id), None)
    if hardware is None:
        return HardwareSoftwareSupport(hardware_id, os_family, exact_version, SupportStatus.UNKNOWN_HARDWARE)
    exact = next((support for support in HARDWARE_SOFTWARE_SUPPORT
                  if support.hardware_id == hardware_id and support.os_family == os_family
                  and support.exact_version == exact_version), None)
    if exact:
        return exact
    from app.core.platforms import PLATFORM_PROFILES
    from app.core.versions import exact_profile
    software_known = any(
        profile.domain == hardware.domain and profile.vendor == hardware.vendor
        and profile.os_family == os_family
        and (exact_version in profile.supported_versions or bool(profile.source_vendor and exact_profile(profile.source_vendor, exact_version)))
        for profile in PLATFORM_PROFILES
    )
    status = SupportStatus.VERSION_NOT_VERIFIED if software_known else SupportStatus.UNKNOWN_SOFTWARE
    return HardwareSoftwareSupport(hardware_id, os_family, exact_version, status)
