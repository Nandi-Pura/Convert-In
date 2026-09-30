import re

from app.core.models import ConfigDomain
from app.core.platforms import NetworkVendor

from .models import HardwareProfile, HardwareSelection, HardwareSoftwareSupport, SupportScope, SupportStatus
from .registry import HARDWARE_PROFILES, HARDWARE_SOFTWARE_SUPPORT, compatibility_groups_for


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


def _version_parts(version: str) -> tuple[int, ...] | None:
    match = re.fullmatch(r"(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:-[A-Za-z0-9.-]+)?", version)
    if not match:
        return None
    return tuple(int(part) for part in match.groups(default="0"))


def _release_train(version: str) -> str | None:
    parts = _version_parts(version)
    return f"{parts[0]}.{parts[1]}" if parts else None


def _known_software(os_family: str, version: str) -> bool:
    from app.core.versions import exact_profile
    if os_family != "PAN-OS":
        from app.core.platforms import PLATFORM_PROFILES
        return any(
            profile.os_family == os_family
            and (version in profile.supported_versions
                 or bool(profile.source_vendor and exact_profile(profile.source_vendor, version)))
            for profile in PLATFORM_PROFILES
        )
    from app.core.models import Vendor
    train = _release_train(version)
    known_train = version == train and any(
        support.os_family == os_family
        and support.support_scope == SupportScope.RELEASE_TRAIN
        and support.exact_version == train
        for support in HARDWARE_SOFTWARE_SUPPORT
    )
    return (
        known_train
        or exact_profile(Vendor.PALO_ALTO, version) is not None
        or any(
            support.os_family == os_family
            and (
                (support.support_scope == SupportScope.EXACT_VERSION and support.exact_version == version)
                or support.minimum_version == version
            )
            for support in HARDWARE_SOFTWARE_SUPPORT
        )
    )


def _result(
    rule: HardwareSoftwareSupport,
    hardware_id: str,
    requested_version: str,
    status: SupportStatus | None = None,
    constraints: tuple[str, ...] | None = None,
) -> HardwareSoftwareSupport:
    return HardwareSoftwareSupport(
        hardware_id,
        rule.os_family,
        requested_version,
        status or rule.status,
        rule.evidence_refs,
        rule.constraints if constraints is None else constraints,
        rule.support_scope,
        rule.minimum_version,
    )


def resolve_hardware_software_support(
    hardware_id: str, os_family: str, exact_version: str,
) -> HardwareSoftwareSupport:
    hardware = next((profile for profile in HARDWARE_PROFILES if profile.id == hardware_id), None)
    if hardware is None:
        return HardwareSoftwareSupport(hardware_id, os_family, exact_version, SupportStatus.UNKNOWN_HARDWARE)

    exact = next((
        support for support in HARDWARE_SOFTWARE_SUPPORT
        if support.hardware_id == hardware_id
        and support.os_family == os_family
        and support.support_scope == SupportScope.EXACT_VERSION
        and support.exact_version == exact_version
    ), None)
    if exact:
        return exact

    train = _release_train(exact_version)
    release_rule = next((
        support
        for identity in (hardware_id, *compatibility_groups_for(hardware_id))
        for support in HARDWARE_SOFTWARE_SUPPORT
        if support.hardware_id == identity
        and support.os_family == os_family
        and support.support_scope == SupportScope.RELEASE_TRAIN
        and support.exact_version == train
    ), None)
    if release_rule:
        requested = _version_parts(exact_version)
        minimum = _version_parts(release_rule.minimum_version) if release_rule.minimum_version else None
        if release_rule.status == SupportStatus.SUPPORTED and requested and minimum and requested < minimum:
            constraints = (*release_rule.constraints, f"{exact_version} predates the documented minimum {release_rule.minimum_version}.")
            return _result(release_rule, hardware_id, exact_version, SupportStatus.UNSUPPORTED, constraints)
        if _known_software(os_family, exact_version):
            return _result(release_rule, hardware_id, exact_version)
        return HardwareSoftwareSupport(hardware_id, os_family, exact_version, SupportStatus.UNKNOWN_SOFTWARE)

    status = SupportStatus.VERSION_NOT_VERIFIED if _known_software(os_family, exact_version) else SupportStatus.UNKNOWN_SOFTWARE
    return HardwareSoftwareSupport(hardware_id, os_family, exact_version, status)
