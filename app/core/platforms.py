from dataclasses import dataclass
from enum import StrEnum

from app.core.models import ConfigDomain


class NetworkVendor(StrEnum):
    CISCO="CISCO"; ARUBA="ARUBA"; JUNIPER="JUNIPER"; HUAWEI="HUAWEI"; FORTINET="FORTINET"; PALO_ALTO="PALO_ALTO"


class Platform(StrEnum):
    ASA="ASA"; IOS="IOS"; IOS_XE="IOS_XE"; NX_OS="NX_OS"; AOS_CX="AOS_CX"; SRX="SRX"; JUNOS="JUNOS"; VRP="VRP"; FORTIGATE="FORTIGATE"; PAN_OS="PAN_OS"


@dataclass(frozen=True)
class VendorPlatformProfile:
    vendor: NetworkVendor
    platform: Platform
    os_family: str
    domain: ConfigDomain
    versions: tuple[str,...]
    parser: str | None = None
    renderer: str | None = None
    capabilities: tuple[str,...] = ()
    docs: tuple[str,...] = ()


PLATFORM_PROFILES=(
    VendorPlatformProfile(NetworkVendor.CISCO,Platform.ASA,"ASA",ConfigDomain.FIREWALL,("9.20","9.22","9.24"),"AsaParser","PaloAltoRenderer"),
    VendorPlatformProfile(NetworkVendor.JUNIPER,Platform.SRX,"Junos OS",ConfigDomain.FIREWALL,("23.4R2",),"JunosSrxParser",None,("addresses","applications","policies","zones","nat","static_routes"),("JUNOS-23.4R2-RELEASE","JUNOS-SECURITY-POLICIES","JUNOS-ADDRESS-BOOKS")),
    VendorPlatformProfile(NetworkVendor.CISCO,Platform.IOS_XE,"IOS-XE",ConfigDomain.ROUTER,()),
    VendorPlatformProfile(NetworkVendor.CISCO,Platform.IOS_XE,"IOS-XE",ConfigDomain.SWITCH,()),
    VendorPlatformProfile(NetworkVendor.CISCO,Platform.NX_OS,"NX-OS",ConfigDomain.SWITCH,()),
    VendorPlatformProfile(NetworkVendor.ARUBA,Platform.AOS_CX,"AOS-CX",ConfigDomain.ROUTER,()),
    VendorPlatformProfile(NetworkVendor.ARUBA,Platform.AOS_CX,"AOS-CX",ConfigDomain.SWITCH,()),
    VendorPlatformProfile(NetworkVendor.JUNIPER,Platform.JUNOS,"Junos OS",ConfigDomain.ROUTER,()),
    VendorPlatformProfile(NetworkVendor.JUNIPER,Platform.JUNOS,"Junos OS",ConfigDomain.SWITCH,()),
    VendorPlatformProfile(NetworkVendor.HUAWEI,Platform.VRP,"VRP",ConfigDomain.ROUTER,()),
    VendorPlatformProfile(NetworkVendor.HUAWEI,Platform.VRP,"VRP",ConfigDomain.SWITCH,()),
)