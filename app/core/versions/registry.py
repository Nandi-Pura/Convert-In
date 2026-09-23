from app.core.models import Vendor
from .models import Capability,CapabilityStatus as S,VersionProfile,VersionStatus as VS

def _cap(refs,status=S.DOCUMENTED_IMPLEMENTED_TESTED,limitation=None,**evidence):
    verified=status==S.DOCUMENTED_IMPLEMENTED_TESTED
    tests=evidence.pop("test_refs",["tests/test_semantic_compatibility.py"] if verified else [])
    return Capability(status=status,documentation_refs=refs,limitation=limitation,renderer_support=verified,test_refs=tests,**evidence)
PROFILES={}
for family in ("9.20","9.22","9.24"):
    objects=f"ASA-{family}-ACCESS-OBJECTS"; routes=f"ASA-{family}-STATIC-ROUTES"; firewall=f"ASA-{family}-FIREWALL"
    PROFILES[f"asa-{family}"]=VersionProfile(id=f"asa-{family}",vendor=Vendor.ASA,os_name="Cisco ASA",version_family=family,documentation_refs=[objects,firewall,routes],capabilities={x:_cap([objects]) for x in ("address","address_group","service","service_group")}|{"security_policy":_cap([firewall]),"route":_cap([routes])},tested=True)
    nat_ref=[f"ASA-{family}-NAT"] if family=="9.20" else []
    for name in ("static_source_nat","dynamic_ip_and_port","identity_nat","twice_nat"):
        PROFILES[f"asa-{family}"].capabilities[name]=_cap(nat_ref,S.DOCUMENTED_NOT_IMPLEMENTED if nat_ref else S.VERSION_NOT_VERIFIED)
    PROFILES[f"asa-{family}"].capabilities["security_policy"]=_cap([f"ASA-{family}-FIREWALL"])
PROFILES["asa-9.24-target"]=VersionProfile(id="asa-9.24-target",vendor=Vendor.ASA,os_name="Cisco ASA",version_family="9.24",documentation_refs=["ASA-9.24-ACCESS-OBJECTS","ASA-9.24-ACCESS-RULES","ASA-9.24-STATIC-ROUTES"],capabilities={name:_cap(["ASA-9.24-ACCESS-OBJECTS"],test_refs=["tests/test_q9_asa.py"]) for name in ("address","address_group","service","service_group")}|{"security_policy":_cap(["ASA-9.24-ACCESS-RULES"],S.DOCUMENTED_NOT_IMPLEMENTED),"route":_cap(["ASA-9.24-STATIC-ROUTES"],S.DOCUMENTED_NOT_IMPLEMENTED)},tested=True,known_limitations=["IPv4 objects only. ACLs, access-group bindings, interfaces, routes, NAT, and deployment are not generated."])
for family in ("7.4","7.6"):
    vip=f"FORTIOS-{family}-STATIC-VIP"; snat=f"FORTIOS-{family}-DYNAMIC-SNAT"
    cli=f"FORTIOS-{family}-CLI-REFERENCE"
    caps={x:_cap([cli]) for x in ("address","address_group","service","service_group","route")}
    caps.update({"interface_address_pat":_cap([snat],S.DOCUMENTED_NOT_IMPLEMENTED),"destination_static_nat":_cap([vip],S.DOCUMENTED_NOT_IMPLEMENTED),"destination_port_translation":_cap([vip],S.DOCUMENTED_NOT_IMPLEMENTED),"ip_pool_snat":_cap([snat],S.DOCUMENTED_NOT_IMPLEMENTED),"central_nat":_cap([snat],S.DOCUMENTED_NOT_IMPLEMENTED),"identity_nat":_cap([],S.DOCUMENTED_NOT_IMPLEMENTED),"twice_nat":_cap([],S.DOCUMENTED_NOT_IMPLEMENTED),"vdom":_cap([],S.DOCUMENTED_NOT_IMPLEMENTED),"sdwan":_cap([],S.DOCUMENTED_NOT_IMPLEMENTED),"security_profiles":_cap([],S.DOCUMENTED_NOT_IMPLEMENTED)})
    caps["security_policy"]=_cap([f"FORTIOS-{family}-FIREWALL-POLICY-CLI"])
    PROFILES[f"fortios-{family}"]=VersionProfile(id=f"fortios-{family}",vendor=Vendor.FORTIGATE,os_name="FortiOS",version_family=family,documentation_refs=[cli,vip,snat],capabilities=caps,tested=True,known_limitations=["Central NAT, IP pools, VDOM, SD-WAN, security profiles, and advanced VIPs require manual review."])
fortios_refs={"address":"FORTIOS-7.6.4-ADDRESS","address_group":"FORTIOS-7.6.4-ADDRGRP","service":"FORTIOS-7.6.4-SERVICE-CUSTOM","service_group":"FORTIOS-7.6.4-SERVICE-GROUP","security_policy":"FORTIOS-7.6.4-FIREWALL-POLICY","route":"FORTIOS-7.6.4-STATIC-ROUTE"}
PROFILES["fortios-7.6.4"]=VersionProfile(id="fortios-7.6.4",vendor=Vendor.FORTIGATE,os_name="FortiOS",version_family="7.6.4",documentation_refs=["FORTIOS-7.6.4-CLI-REFERENCE",*fortios_refs.values()],capabilities={name:_cap([ref],test_refs=["tests/test_q8_fortios.py"]) for name,ref in fortios_refs.items()}|{"interface_address_pat":_cap([],S.DOCUMENTED_NOT_IMPLEMENTED),"destination_static_nat":_cap([],S.DOCUMENTED_NOT_IMPLEMENTED),"destination_port_translation":_cap([],S.DOCUMENTED_NOT_IMPLEMENTED),"central_nat":_cap([],S.DOCUMENTED_NOT_IMPLEMENTED)},tested=True,known_limitations=["IPv4 only. NAT, VIP, VDOM, zones, security profiles, built-in mappings, and interface creation are not generated."])
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
srx_refs={"address":"JUNOS-23.4R2-SRX-ADDRESS-BOOK","address_group":"JUNOS-23.4R2-SRX-ADDRESS-BOOK","service":"JUNOS-23.4R2-SRX-APPLICATIONS","service_group":"JUNOS-23.4R2-SRX-APPLICATIONS","security_policy":"JUNOS-23.4R2-SRX-SECURITY-POLICIES","route":"JUNOS-23.4R2-SRX-STATIC-ROUTES"}
PROFILES["junos-23.4R2-srx-target"]=VersionProfile(id="junos-23.4R2-srx-target",vendor=Vendor.JUNIPER_SRX,os_name="Junos OS",version_family="23.4R2",documentation_refs=["JUNOS-23.4R2-RELEASE",*set(srx_refs.values()),"JUNOS-23.4R2-SRX-ZONES"],capabilities={name:_cap([ref],test_refs=["tests/test_q10_srx.py"]) for name,ref in srx_refs.items()}|{name:_cap(["JUNOS-NAT-OVERVIEW"],S.DOCUMENTED_NOT_IMPLEMENTED) for name in ("source_nat","destination_nat","static_nat")},tested=True,known_limitations=["Global IPv4 address book only. Flat sets and TCP/UDP destination-port applications only.","NAT, IPv6, FQDN, disabled policies, logging, schedulers, routing instances, and deployment are not generated."])
iosxe_refs={"iosxe.interface.ipv4":"IOSXE-IP-ADDRESSING","iosxe.vrf":"IOSXE-PROTOCOL-INDEPENDENT","iosxe.static_route":"IOSXE-PROTOCOL-INDEPENDENT","iosxe.prefix_list":"IOSXE-PROTOCOL-INDEPENDENT","iosxe.route_map":"IOSXE-PROTOCOL-INDEPENDENT","iosxe.ospf":"IOSXE-OSPF","iosxe.bgp.neighbor":"IOSXE-BGP"}
PROFILES["iosxe-17.12.1"]=VersionProfile(id="iosxe-17.12.1",vendor=Vendor.CISCO_IOSXE,os_name="Cisco IOS XE",version_family="17.12.1",documentation_refs=["IOSXE-17.12.1-COMMANDS",*set(iosxe_refs.values())],capabilities={name:_cap([ref]).model_copy(update={"renderer_support":False,"test_refs":["tests/test_q6_iosxe_router.py"]}) for name,ref in iosxe_refs.items()},tested=True,known_limitations=["Parser and CP0/CP1 analysis only. No router renderer or conversion path.","Advanced routing features remain source-unsupported."])

def version_profile(vendor:Vendor,family:str|None): return next((x for x in PROFILES.values() if x.vendor==vendor and x.version_family==family),None)
def target_version_profile(vendor:Vendor,family:str|None):
    if vendor==Vendor.ASA and family=="9.24": return PROFILES.get("asa-9.24-target")
    if vendor==Vendor.JUNIPER_SRX and family=="23.4R2": return PROFILES.get("junos-23.4R2-srx-target")
    return version_profile(vendor,family)

# Release existence never enables rendering. Exact command evidence must register the renderer separately.
AUDIT_DATE="2026-09-21"
_release_specs=(
    (Vendor.ASA,"ASA","9.24","9.24(10)",1,"ASA-9.24-RELEASE"),(Vendor.ASA,"ASA","9.23","9.23(1)",2,"ASA-9.23-RELEASE"),(Vendor.ASA,"ASA","9.22","9.22(3)",3,"ASA-9.22-RELEASE"),
    (Vendor.FORTIGATE,"FORTIGATE","7.6","7.6.7",1,"FORTIOS-7.6.7-RELEASE"),(Vendor.FORTIGATE,"FORTIGATE","7.4","7.4.12",2,"FORTIOS-7.4.12-RELEASE"),(Vendor.FORTIGATE,"FORTIGATE","7.2","7.2.13",3,"FORTIOS-7.2.13-RELEASE"),
    (Vendor.PALO_ALTO,"PAN_OS","12.2","12.2.3",1,"PANOS-12.2.3-RELEASE"),(Vendor.PALO_ALTO,"PAN_OS","12.1","12.1.6",2,"PANOS-12.1.6-RELEASE"),(Vendor.PALO_ALTO,"PAN_OS","11.2","11.2.9",3,"PANOS-11.2.9-RELEASE"),
    (Vendor.JUNIPER_SRX,"SRX","25.4","25.4",1,"JUNOS-25.4-RELEASE"),(Vendor.JUNIPER_SRX,"SRX","25.2","25.2R1",2,"JUNOS-25.2R1-SRX-RELEASE"),(Vendor.JUNIPER_SRX,"SRX","24.4","24.4R2",3,"JUNOS-24.4R2-SRX-RELEASE"),
)
RELEASE_PROFILES={f"{vendor.value}-{exact}":VersionProfile(id=f"{vendor.value}-{exact}",vendor=vendor,os_name={Vendor.ASA:"Cisco ASA",Vendor.FORTIGATE:"FortiOS",Vendor.PALO_ALTO:"PAN-OS",Vendor.JUNIPER_SRX:"Junos OS"}[vendor],version_family=line,platform=platform,release_line=line,exact_version=exact,display_version=line,version_status=VS.LATEST_VERIFIED if vendor in {Vendor.ASA,Vendor.FORTIGATE} else VS.VERSION_NOT_VERIFIED,latest_in_line=vendor in {Vendor.ASA,Vendor.FORTIGATE},release_evidence_ids=[evidence],documentation_refs=[evidence],source_parser_available=True,target_renderer_available=False,audited_at=AUDIT_DATE,rank=rank) for vendor,platform,line,exact,rank,evidence in _release_specs}
for key,profile_id,line,exact in (("cisco_asa-9.24","asa-9.24-target","9.24","9.24"),("fortigate-7.6.4","fortios-7.6.4","7.6","7.6.4"),("paloalto-11.1","panos-11.1","11.1","11.1"),("juniper_srx-23.4R2","junos-23.4R2-srx-target","23.4","23.4R2")):
    old=PROFILES[profile_id]
    RELEASE_PROFILES[key]=old.model_copy(update={"id":key,"platform":{"cisco_asa":"ASA","fortigate":"FORTIGATE","paloalto":"PAN_OS","juniper_srx":"SRX"}[old.vendor.value],"release_line":line,"exact_version":exact,"display_version":line,"version_status":VS.LEGACY_VERIFIED,"latest_in_line":False,"release_evidence_ids":old.documentation_refs[:1],"source_parser_available":True,"target_renderer_available":True,"target_capability":"BOUNDED_RENDERER","audited_at":AUDIT_DATE,"rank":99})

Q12_CAPABILITIES=("interface_zone_context","disabled_rules","icmp","source_ports","multiple_service_ranges","nested_groups","fqdn_objects","ipv6_objects","logging","schedules","static_route_options")
for profile in RELEASE_PROFILES.values():
    if profile.exact_version not in {"9.24","7.6.4","11.1","23.4R2"}: continue
    profile.capabilities.update({f"q12.{name}":_cap([],S.VERSION_NOT_VERIFIED,limitation="Q12 exact-version emitting semantics were not established; engineer review required.") for name in Q12_CAPABILITIES})

def release_profiles(vendor:Vendor|None=None):
    return sorted((p for p in RELEASE_PROFILES.values() if vendor is None or p.vendor==vendor),key=lambda p:(p.vendor.value,p.rank))

def exact_profile(vendor:Vendor,exact_version:str):
    return next((p for p in RELEASE_PROFILES.values() if p.vendor==vendor and p.exact_version==exact_version),None)