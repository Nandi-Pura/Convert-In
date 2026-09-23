from app.core.models import ConfigDomain
from app.core.platforms import NetworkVendor, Platform
from .junos_router import JunosRouterRenderer
from .paloalto import PaloAltoRenderer

RENDERERS={
    (ConfigDomain.FIREWALL,NetworkVendor.PALO_ALTO,Platform.PAN_OS,"11.1"):PaloAltoRenderer,
    (ConfigDomain.ROUTER,NetworkVendor.JUNIPER,Platform.JUNOS,"23.4R2"):JunosRouterRenderer,
}

def lookup_renderer(domain,vendor,platform,version):
    try:return RENDERERS.get((ConfigDomain(domain),NetworkVendor(vendor),Platform(platform),version))
    except ValueError:return None