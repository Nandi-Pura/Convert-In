from app.core.models import ConfigDomain
from app.core.platforms import NetworkVendor, Platform
from .junos_router import JunosRouterRenderer
from .paloalto import PaloAltoRenderer
from .fortios import FortiOSRenderer
from .asa import AsaRenderer
from .junos_srx import JunosSrxRenderer
from .iosxe_switch import IosXeSwitchRenderer

RENDERERS={
    (ConfigDomain.FIREWALL,NetworkVendor.PALO_ALTO,Platform.PAN_OS,"11.1"):PaloAltoRenderer,
    (ConfigDomain.FIREWALL,NetworkVendor.FORTINET,Platform.FORTIGATE,"7.6.4"):FortiOSRenderer,
    (ConfigDomain.FIREWALL,NetworkVendor.CISCO,Platform.ASA,"9.24"):AsaRenderer,
    (ConfigDomain.FIREWALL,NetworkVendor.JUNIPER,Platform.SRX,"23.4R2"):JunosSrxRenderer,
    (ConfigDomain.ROUTER,NetworkVendor.JUNIPER,Platform.JUNOS,"23.4R2"):JunosRouterRenderer,
    (ConfigDomain.SWITCH,NetworkVendor.CISCO,Platform.IOS_XE,"17.12.1"):IosXeSwitchRenderer,
}

def lookup_renderer(domain,vendor,platform,version):
    try:return RENDERERS.get((ConfigDomain(domain),NetworkVendor(vendor),Platform(platform),version))
    except ValueError:return None