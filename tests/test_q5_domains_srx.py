from app.core.models import BGPProcess,ConfigDomain,LAG,OSPFProcess,RouterConfig,RouterInterface,RouterStaticRoute,RouterVRF,SVI,SwitchConfig,SwitchPort,VLAN,Vendor
from app.core.parsing import detect_vendor,parse_config
from app.core.reference_integrity import ReferenceIntegrityValidator
from app.core.domain_detection import detect_domain
from app.core.migration.quick_convert import convert


SRX='''set security zones security-zone trust interfaces ge-0/0/0.0
set security zones security-zone untrust
set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24
set security address-book global address WEB 192.0.2.10/32
set security address-book global address-set SERVERS address WEB
set applications application HTTPS protocol tcp
set applications application HTTPS destination-port 443
set applications application-set WEB-APPS application HTTPS
set security policies from-zone trust to-zone untrust policy web match source-address any
set security policies from-zone trust to-zone untrust policy web match destination-address SERVERS
set security policies from-zone trust to-zone untrust policy web match application WEB-APPS
set security policies from-zone trust to-zone untrust policy web then permit
set routing-options static route 0.0.0.0/0 next-hop 10.0.0.254
set security nat source rule-set OUT rule PAT then source-nat interface
set security mystery value
'''


def test_domain_models_are_separate_and_bounded():
    router=RouterConfig(interfaces=[RouterInterface(name="lo0",addresses=["192.0.2.1/32"])],vrfs=[RouterVRF(name="blue")],static_routes=[RouterStaticRoute(destination="0.0.0.0/0",next_hop="192.0.2.254")],ospf_processes=[OSPFProcess(process_id="1")],bgp_processes=[BGPProcess(local_as=65000)])
    switch=SwitchConfig(vlans=[VLAN(vlan_id=10)],ports=[SwitchPort(name="1/1/1",mode="access")],lags=[LAG(name="lag1")],svis=[SVI(name="vlan10",vlan_id=10)])
    assert router.domain==ConfigDomain.ROUTER and switch.domain==ConfigDomain.SWITCH
    assert not hasattr(router,"security_policies") and not hasattr(switch,"security_policies")


def test_srx_detection_parsing_cp0_cp1_and_nat_accounting():
    assert detect_vendor(SRX).vendor==Vendor.JUNIPER_SRX
    cfg=parse_config(SRX,Vendor.JUNIPER_SRX)
    assert (len(cfg.addresses),len(cfg.address_groups),len(cfg.services),len(cfg.service_groups),len(cfg.security_policies),len(cfg.nat_policies),len(cfg.static_routes))==(1,1,1,1,1,1,1)
    assert cfg.extraction_coverage.semantic_total==cfg.extraction_coverage.normalized+cfg.extraction_coverage.recovered+cfg.extraction_coverage.unparsed+cfg.extraction_coverage.unsupported
    integrity=ReferenceIntegrityValidator().validate(cfg)
    assert integrity.unresolved_references==0


def test_generic_junos_router_not_detected_as_srx():
    assert detect_vendor("set protocols bgp group EDGE type external\nset interfaces ge-0/0/0 unit 0").vendor==Vendor.UNKNOWN

def test_domain_detection_and_quick_convert_evidence_gates():
    assert detect_domain(SRX).primary==ConfigDomain.FIREWALL
    assert detect_domain("set protocols bgp group EDGE type external").primary==ConfigDomain.ROUTER
    assert detect_domain("set vlans USERS vlan-id 10\nset interfaces ge-0/0/1 unit 0 family ethernet-switching").primary==ConfigDomain.SWITCH
    result=convert(SRX,"juniper_srx","23.4R2")
    commands=[x for x in result.lines if x.startswith("set ")]
    assert any(x.startswith("set address WEB") for x in commands)
    assert not any(x.startswith("set rulebase nat") for x in commands)

def test_exact_junos_release_metadata_detection():
    from app.core.migration.quick_convert import detect_source
    detected,version=detect_source("## Last changed: synthetic Junos: 23.4R2\nset security policies from-zone a to-zone b policy p then deny")
    assert detected.vendor==Vendor.JUNIPER_SRX and version=="23.4R2"