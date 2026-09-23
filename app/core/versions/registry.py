from app.core.models import Vendor
from .models import Capability,CapabilityStatus as S,VersionProfile

def _cap(refs,status=S.DOCUMENTED_IMPLEMENTED_TESTED,limitation=None,**evidence):
    verified=status==S.DOCUMENTED_IMPLEMENTED_TESTED
    return Capability(status=status,documentation_refs=refs,limitation=limitation,renderer_support=verified,test_refs=["tests/test_semantic_compatibility.py"] if verified else [],**evidence)
PROFILES={}
for family in ("9.20","9.22","9.24"):
    objects=f"ASA-{family}-ACCESS-OBJECTS"; routes=f"ASA-{family}-STATIC-ROUTES"; firewall=f"ASA-{family}-FIREWALL"
    PROFILES[f"asa-{family}"]=VersionProfile(id=f"asa-{family}",vendor=Vendor.ASA,os_name="Cisco ASA",version_family=family,documentation_refs=[objects,firewall,routes],capabilities={x:_cap([objects]) for x in ("address","address_group","service","service_group")}|{"security_policy":_cap([firewall]),"route":_cap([routes])},tested=True)
    nat_ref=[f"ASA-{family}-NAT"] if family=="9.20" else []
    for name in ("static_source_nat","dynamic_ip_and_port","identity_nat","twice_nat"):
        PROFILES[f"asa-{family}"].capabilities[name]=_cap(nat_ref,S.DOCUMENTED_NOT_IMPLEMENTED if nat_ref else S.VERSION_NOT_VERIFIED)
    PROFILES[f"asa-{family}"].capabilities["security_policy"]=_cap([f"ASA-{family}-FIREWALL"])
for family in ("7.4","7.6"):
    vip=f"FORTIOS-{family}-STATIC-VIP"; snat=f"FORTIOS-{family}-DYNAMIC-SNAT"
    cli=f"FORTIOS-{family}-CLI-REFERENCE"
    caps={x:_cap([cli]) for x in ("address","address_group","service","service_group","route")}
    caps.update({"interface_address_pat":_cap([snat],S.DOCUMENTED_NOT_IMPLEMENTED),"destination_static_nat":_cap([vip],S.DOCUMENTED_NOT_IMPLEMENTED),"destination_port_translation":_cap([vip],S.DOCUMENTED_NOT_IMPLEMENTED),"ip_pool_snat":_cap([snat],S.DOCUMENTED_NOT_IMPLEMENTED),"central_nat":_cap([snat],S.DOCUMENTED_NOT_IMPLEMENTED),"identity_nat":_cap([],S.DOCUMENTED_NOT_IMPLEMENTED),"twice_nat":_cap([],S.DOCUMENTED_NOT_IMPLEMENTED),"vdom":_cap([],S.DOCUMENTED_NOT_IMPLEMENTED),"sdwan":_cap([],S.DOCUMENTED_NOT_IMPLEMENTED),"security_profiles":_cap([],S.DOCUMENTED_NOT_IMPLEMENTED)})
    caps["security_policy"]=_cap([f"FORTIOS-{family}-FIREWALL-POLICY-CLI"])
    PROFILES[f"fortios-{family}"]=VersionProfile(id=f"fortios-{family}",vendor=Vendor.FORTIGATE,os_name="FortiOS",version_family=family,documentation_refs=[cli,vip,snat],capabilities=caps,tested=True,known_limitations=["Central NAT, IP pools, VDOM, SD-WAN, security profiles, and advanced VIPs require manual review."])
for family in ("11.1","12.1"):
    refs=[f"PANOS-{family}-SECURITY-POLICY"] if family=="11.1" else []
    caps={x:_cap([],S.IMPLEMENTED_NOT_DOCUMENTATION_VERIFIED) for x in ("address","address_group","service","service_group","route")}
    for name in ("static_source_nat","dynamic_ip_and_port","interface_address_pat","destination_static_nat","destination_port_translation","identity_nat","twice_nat","ip_pool_snat","central_nat"):
        caps[name]=_cap([],S.DOCUMENTED_NOT_IMPLEMENTED if family=="11.1" else S.VERSION_NOT_VERIFIED,limitation="Subtype remains blocked until semantic, CLI, ordering, placement, mapping, and test evidence is complete.")
    caps["security_policy"]=_cap(refs+["PANOS-11.1-CONFIG-API-ACTIONS"] if refs else [],S.DOCUMENTED_IMPLEMENTED_TESTED if refs else S.IMPLEMENTED_NOT_DOCUMENTATION_VERIFIED)
    if family=="11.1":
        cli="PANOS-11.1-CONFIGURE-CLI-HIERARCHY"
        general="PANOS-11.1-NAT-POLICY-RULES"; dipp="PANOS-11.1-SOURCE-DIPP"; dnat="PANOS-11.1-DNAT-ONE-TO-ONE"
        caps["dynamic_ip_and_port"]=_cap([general,dipp,cli],S.DOCUMENTED_NOT_IMPLEMENTED,target_match_semantics_documented=True,target_translation_semantics_documented=True,route_lookup_semantics_documented=True,limitation="Ordering, placement, mapping, and renderer verification remain blocked.")
        caps["interface_address_pat"]=_cap([general,dipp,cli],S.DOCUMENTED_NOT_IMPLEMENTED,target_match_semantics_documented=True,target_translation_semantics_documented=True,route_lookup_semantics_documented=True,limitation="Target interface selection, ordering, placement, mapping, and renderer verification remain blocked.")
        caps["destination_static_nat"]=_cap([general,dnat,cli],S.DOCUMENTED_NOT_IMPLEMENTED,target_match_semantics_documented=True,target_translation_semantics_documented=True,route_lookup_semantics_documented=True,limitation="Original-destination route outcome, ordering, placement, mapping, and renderer verification remain blocked.")
        semantics={"address":"PANOS-11.1-ADDRESSES","address_group":"PANOS-11.1-ADDRESS-GROUPS","service":"PANOS-11.1-SERVICES","service_group":"PANOS-11.1-SERVICE-GROUPS","route":"PANOS-11.1-STATIC-ROUTES"}
        for name,semantic in semantics.items(): caps[name]=_cap([semantic,cli])
    PROFILES[f"panos-{family}"]=VersionProfile(id=f"panos-{family}",vendor=Vendor.PALO_ALTO,os_name="PAN-OS",version_family=family,documentation_refs=refs,capabilities=caps,tested=family=="11.1")
refs={"address":"JUNOS-ADDRESS-BOOKS","address_group":"JUNOS-ADDRESS-BOOKS","service":"JUNOS-CUSTOM-APPLICATIONS","service_group":"JUNOS-CUSTOM-APPLICATIONS","security_policy":"JUNOS-SECURITY-POLICIES","route":"JUNOS-STATIC-ROUTES"}
PROFILES["junos-23.4R2"]=VersionProfile(id="junos-23.4R2",vendor=Vendor.JUNIPER_SRX,os_name="Junos OS",version_family="23.4R2",documentation_refs=["JUNOS-23.4R2-RELEASE",*refs.values()],capabilities={name:_cap([ref]) for name,ref in refs.items()}|{name:_cap(["JUNOS-NAT-OVERVIEW"],S.DOCUMENTED_NOT_IMPLEMENTED) for name in ("source_nat","destination_nat","static_nat")},tested=True,known_limitations=["Set-style only. NAT recognized but never generated. Scoped address-book ambiguity blocks generation."])
iosxe_refs={"iosxe.interface.ipv4":"IOSXE-IP-ADDRESSING","iosxe.vrf":"IOSXE-PROTOCOL-INDEPENDENT","iosxe.static_route":"IOSXE-PROTOCOL-INDEPENDENT","iosxe.prefix_list":"IOSXE-PROTOCOL-INDEPENDENT","iosxe.route_map":"IOSXE-PROTOCOL-INDEPENDENT","iosxe.ospf":"IOSXE-OSPF","iosxe.bgp.neighbor":"IOSXE-BGP"}
PROFILES["iosxe-17.12.1"]=VersionProfile(id="iosxe-17.12.1",vendor=Vendor.CISCO_IOSXE,os_name="Cisco IOS XE",version_family="17.12.1",documentation_refs=["IOSXE-17.12.1-COMMANDS",*set(iosxe_refs.values())],capabilities={name:_cap([ref]).model_copy(update={"renderer_support":False,"test_refs":["tests/test_q6_iosxe_router.py"]}) for name,ref in iosxe_refs.items()},tested=True,known_limitations=["Parser and CP0/CP1 analysis only. No router renderer or conversion path.","Advanced routing features remain source-unsupported."])

def version_profile(vendor:Vendor,family:str|None): return next((x for x in PROFILES.values() if x.vendor==vendor and x.version_family==family),None)