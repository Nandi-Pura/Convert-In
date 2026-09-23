from pathlib import Path

from app.core.domain_detection import detect_domain
from app.core.models import ConfigDomain,ExtractionOutcome,RouterConfig,Vendor
from app.core.parsing import detect_vendor,parse_config
from app.core.router_assurance import RouterReferenceIntegrityValidator
from app.core.versions import detect_version,version_profile

ROOT=Path("tests/fixtures/iosxe")
def parsed(name):return parse_config((ROOT/name).read_text(),Vendor.CISCO_IOSXE)

def test_detection_version_profile_and_router_domain():
    text=(ROOT/"basic-router.cfg").read_text()
    assert detect_vendor(text).vendor==Vendor.CISCO_IOSXE
    assert detect_domain(text).primary==ConfigDomain.ROUTER
    assert detect_version(text,Vendor.CISCO_IOSXE).detected_family=="17.12.1"
    assert detect_version(text.replace("17.12.1","17.13.1"),Vendor.CISCO_IOSXE).detected_family is None
    profile=version_profile(Vendor.CISCO_IOSXE,"17.12.1")
    assert profile and not any(x.renderer_support for x in profile.capabilities.values())
    assert version_profile(Vendor.CISCO_IOSXE,"17.13.1") is None
    assert detect_vendor("ASA Version 9.20\nrouter ospf 1").vendor!=Vendor.CISCO_IOSXE

def test_interfaces_secondary_static_routes_and_lineage():
    cfg=parsed("basic-router.cfg"); assert isinstance(cfg,RouterConfig) and cfg.hostname=="EDGE-1"
    assert [x.name for x in cfg.interfaces]==["GigabitEthernet0/0","GigabitEthernet0/1","Loopback0"]
    assert cfg.interfaces[0].description=="WAN" and cfg.interfaces[1].enabled is False
    assert cfg.static_routes[0].interface=="GigabitEthernet0/0" and cfg.static_routes[0].distance==10
    assert cfg.interfaces[0].provenance.source_line==3 and cfg.extraction_coverage.source_version=="17.12.1"
    secondary=parse_config("Cisco IOS XE Software, Version 17.12.1\ninterface Loopback1\n ip address 192.0.2.1 255.255.255.255\n ip address 192.0.2.2 255.255.255.255 secondary",Vendor.CISCO_IOSXE)
    assert secondary.interfaces[0].addresses==["192.0.2.1/32","192.0.2.2/32"]
    unverified=parse_config("router ospf 1",Vendor.CISCO_IOSXE)
    assert unverified.metadata["version_status"]=="VERSION_NOT_VERIFIED" and unverified.extraction_coverage.source_version is None

def test_vrf_and_cp1_missing_vrf():
    cfg=parsed("vrf-router.cfg"); assert cfg.vrfs[0].name=="CUSTOMER-A" and cfg.static_routes[0].vrf=="CUSTOMER-A"
    report=RouterReferenceIntegrityValidator().validate(cfg)
    assert report.blocking_findings==1 and report.findings[0].referenced_entity_name=="MISSING"

def test_prefix_route_map_and_cp1_reference():
    cfg=parsed("policy-router.cfg"); entry=cfg.prefix_lists[0].entries[0]
    assert (entry.sequence,entry.action,entry.ge,entry.le)==(10,"permit",16,24)
    report=RouterReferenceIntegrityValidator().validate(cfg)
    assert report.unresolved_references==1 and report.findings[0].referenced_entity_name=="ABSENT"

def test_ospf_wildcard_preserved():
    process=parsed("ospf-router.cfg").ospf_processes[0]
    assert process.router_id=="198.51.100.1" and process.areas[0].networks==["10.0.0.0 0.0.0.255"]

def test_bgp_context_and_references():
    cfg=parsed("bgp-router.cfg"); process=cfg.bgp_processes[0]; neighbor=process.neighbors[0]
    assert process.local_as==65000 and process.router_id=="198.51.100.1"
    assert (neighbor.remote_as,neighbor.description,neighbor.update_source,neighbor.route_policy_in)==(65001,"TRANSIT","Loopback0","RM-IN")
    assert process.networks[0].route_policy=="RM-IN"
    assert RouterReferenceIntegrityValidator().validate(cfg).unresolved_references==0

def test_malformed_unsupported_cp0_and_deterministic_ids():
    first=parsed("malformed-router.cfg"); second=parsed("malformed-router.cfg"); report=first.extraction_coverage
    assert report.semantic_total==report.normalized+report.recovered+report.unparsed+report.unsupported
    assert report.recovered==1 and report.unparsed>=1 and report.unsupported>=1 and report.ignored_non_semantic==1
    assert any(x.outcome==ExtractionOutcome.SOURCE_UNSUPPORTED for x in report.items)
    assert [x.id for x in report.items]==[x.id for x in second.extraction_coverage.items]
    a=RouterReferenceIntegrityValidator().validate(parsed("policy-router.cfg"));b=RouterReferenceIntegrityValidator().validate(parsed("policy-router.cfg"))
    assert [x.finding_id for x in a.findings]==[x.finding_id for x in b.findings]