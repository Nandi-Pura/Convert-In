from dataclasses import asdict, dataclass
from enum import StrEnum

from app.core.models import ConfigDomain, Vendor


class NetworkVendor(StrEnum):
    CISCO="CISCO"; ARUBA="ARUBA"; JUNIPER="JUNIPER"; HUAWEI="HUAWEI"; FORTINET="FORTINET"; PALO_ALTO="PALO_ALTO"


class Platform(StrEnum):
    ASA="ASA"; IOS_XE="IOS_XE"; NX_OS="NX_OS"; AOS_CX="AOS_CX"; SRX="SRX"; JUNOS="JUNOS"; VRP="VRP"; FORTIGATE="FORTIGATE"; PAN_OS="PAN_OS"


class TargetCapability(StrEnum):
    ANALYZE_ONLY="ANALYZE_ONLY"; TARGET_NOT_IMPLEMENTED="TARGET_NOT_IMPLEMENTED"; BOUNDED_RENDERER="BOUNDED_RENDERER"; SUPPORTED_RENDERER="SUPPORTED_RENDERER"


@dataclass(frozen=True)
class VendorPlatformProfile:
    id: str
    vendor: NetworkVendor
    platform: Platform
    os_family: str
    domain: ConfigDomain
    supported_versions: tuple[str,...]
    source_vendor: Vendor | None = None
    source_parser: str | None = None
    target_renderer: str | None = None
    capabilities: tuple[str,...] = ()
    documentation_profile: tuple[str,...] = ()
    analysis_supported: bool = False
    conversion_supported: bool = False
    target_capability: TargetCapability = TargetCapability.TARGET_NOT_IMPLEMENTED
    target_versions: tuple[str,...] = ()

    @property
    def versions(self): return self.supported_versions


PLATFORM_PROFILES=(
    VendorPlatformProfile("firewall-cisco-asa",NetworkVendor.CISCO,Platform.ASA,"ASA",ConfigDomain.FIREWALL,("9.20","9.22","9.24"),Vendor.ASA,"AsaParser","AsaRenderer",capabilities=("address","address_group","service","service_group"),documentation_profile=("ASA-9.24-ACCESS-OBJECTS",),analysis_supported=True,conversion_supported=True,target_capability=TargetCapability.BOUNDED_RENDERER,target_versions=("9.24",)),
    VendorPlatformProfile("firewall-fortinet-fortigate",NetworkVendor.FORTINET,Platform.FORTIGATE,"FortiOS",ConfigDomain.FIREWALL,("7.4","7.6","7.6.4"),Vendor.FORTIGATE,"FortiGateParser","FortiOSRenderer",capabilities=("address","address_group","service","service_group","security_policy","route"),documentation_profile=("FORTIOS-7.6.4-CLI-REFERENCE",),analysis_supported=True,conversion_supported=True,target_capability=TargetCapability.BOUNDED_RENDERER,target_versions=("7.6.4",)),
    VendorPlatformProfile("firewall-paloalto-panos",NetworkVendor.PALO_ALTO,Platform.PAN_OS,"PAN-OS",ConfigDomain.FIREWALL,("11.1",),Vendor.PALO_ALTO,"PaloAltoParser","PaloAltoRenderer",analysis_supported=True,conversion_supported=True,target_capability=TargetCapability.BOUNDED_RENDERER),
    VendorPlatformProfile("firewall-juniper-srx",NetworkVendor.JUNIPER,Platform.SRX,"Junos OS",ConfigDomain.FIREWALL,("23.4R2",),Vendor.JUNIPER_SRX,"JunosSrxParser",capabilities=("addresses","applications","policies","zones","nat","static_routes"),documentation_profile=("JUNOS-23.4R2-RELEASE",),analysis_supported=True),
    VendorPlatformProfile("router-cisco-iosxe",NetworkVendor.CISCO,Platform.IOS_XE,"IOS-XE",ConfigDomain.ROUTER,("17.12.1",),Vendor.CISCO_IOSXE,"IosXeRouterParser",capabilities=("interface_ipv4","vrf","static_route","prefix_list","route_map","ospf","bgp_neighbor"),documentation_profile=("IOSXE-17.12.1-COMMANDS",),analysis_supported=True,target_capability=TargetCapability.ANALYZE_ONLY),
    VendorPlatformProfile("router-juniper-junos",NetworkVendor.JUNIPER,Platform.JUNOS,"Junos OS",ConfigDomain.ROUTER,("23.4R2",),target_renderer="JunosRouterRenderer",capabilities=("interface_ipv4","static_route","prefix_list"),documentation_profile=("JUNOS-23.4R2-RELEASE",),conversion_supported=True,target_capability=TargetCapability.BOUNDED_RENDERER),
    VendorPlatformProfile("router-huawei-vrp",NetworkVendor.HUAWEI,Platform.VRP,"VRP",ConfigDomain.ROUTER,()),
    VendorPlatformProfile("router-aruba-aoscx",NetworkVendor.ARUBA,Platform.AOS_CX,"AOS-CX",ConfigDomain.ROUTER,()),
    VendorPlatformProfile("switch-cisco-iosxe",NetworkVendor.CISCO,Platform.IOS_XE,"IOS-XE",ConfigDomain.SWITCH,()),
    VendorPlatformProfile("switch-cisco-nxos",NetworkVendor.CISCO,Platform.NX_OS,"NX-OS",ConfigDomain.SWITCH,()),
    VendorPlatformProfile("switch-aruba-aoscx",NetworkVendor.ARUBA,Platform.AOS_CX,"AOS-CX",ConfigDomain.SWITCH,()),
    VendorPlatformProfile("switch-juniper-junos",NetworkVendor.JUNIPER,Platform.JUNOS,"Junos OS",ConfigDomain.SWITCH,()),
    VendorPlatformProfile("switch-huawei-vrp",NetworkVendor.HUAWEI,Platform.VRP,"VRP",ConfigDomain.SWITCH,()),
)


def platform_profile(profile_id:str,version:str|None=None):
    return next((p for p in PLATFORM_PROFILES if p.id==profile_id and (version is None or version in p.supported_versions)),None)


def profiles_payload():
    return [{**asdict(p),"vendor":p.vendor.value,"platform":p.platform.value,"domain":p.domain.value,"source_vendor":p.source_vendor.value if p.source_vendor else None,"target_capability":p.target_capability.value} for p in PLATFORM_PROFILES]