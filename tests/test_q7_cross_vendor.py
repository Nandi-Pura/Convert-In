from pathlib import Path

from fastapi.testclient import TestClient

from app.core.models import ConfigDomain
from app.core.parsing.registry import lookup_parser
from app.core.platforms import PLATFORM_PROFILES, NetworkVendor, Platform, platform_profile
from app.core.renderers.registry import lookup_renderer
from app.core.router_migration import RouterCompatibilityEvaluator, RouterInterfaceMapping, RouterMigrationMappings
from app.core.parsing import parse_config
from app.core.models import Vendor
from app.core.router_assurance import RouterReferenceIntegrityValidator
from app.main import app

client=TestClient(app)


def test_platform_registry_keeps_targets_independent_within_domain():
    firewall={p.vendor for p in PLATFORM_PROFILES if p.domain==ConfigDomain.FIREWALL}
    assert firewall=={NetworkVendor.CISCO,NetworkVendor.FORTINET,NetworkVendor.PALO_ALTO,NetworkVendor.JUNIPER}
    assert platform_profile("firewall-cisco-asa").supported_versions==("9.20","9.22","9.24")
    assert platform_profile("firewall-fortinet-fortigate").supported_versions==("7.4","7.6")
    assert lookup_parser("router-cisco-iosxe","17.12.1")


def test_renderer_registry_is_target_driven_and_unknown_is_clean():
    assert lookup_renderer("ROUTER","JUNIPER","JUNOS","23.4R2")
    assert lookup_renderer("ROUTER","HUAWEI","VRP","23.4R2") is None
    assert lookup_renderer("FIREWALL","PALO_ALTO","PAN_OS","11.1")


def test_iosxe_to_junos_uses_scoped_mapping_and_safe_subset():
    text=Path("tests/fixtures/iosxe/basic-router.cfg").read_text(); cfg=parse_config(text,Vendor.CISCO_IOSXE)
    source=platform_profile("router-cisco-iosxe","17.12.1"); target=platform_profile("router-juniper-junos","23.4R2")
    mapping=RouterInterfaceMapping(source_profile=source.id,source_version="17.12.1",target_profile=target.id,target_version="23.4R2",source_entity_id="interface:GigabitEthernet0/0",target_identity="ge-0/0/0",confirmed=True)
    cp2=RouterCompatibilityEvaluator().evaluate(cfg,source,target,RouterMigrationMappings(interfaces=[mapping]),RouterReferenceIntegrityValidator().validate(cfg))
    mapped=next(x for x in cp2 if x.entity_id==mapping.source_entity_id); loopback=next(x for x in cp2 if x.entity_id=="interface:Loopback0")
    assert mapped.status=="SUPPORTED" and any("ge-0/0/0" in x for x in mapped.target_semantic["commands"])
    assert loopback.status=="MANUAL_REVIEW" and not loopback.target_semantic["commands"]
    assert all(x.status=="MANUAL_REVIEW" for x in cp2 if x.entity_type=="route")


def test_workbench_junos_candidate_and_same_domain_invariant():
    text=Path("tests/fixtures/iosxe/basic-router.cfg").read_text(); mapping={"interfaces":[{"source_profile":"router-cisco-iosxe","source_version":"17.12.1","target_profile":"router-juniper-junos","target_version":"23.4R2","source_entity_id":"interface:GigabitEthernet0/0","target_identity":"ge-0/0/0","confirmed":True}]}
    body={"source_text":text,"source_vendor":"cisco_iosxe","source_profile":"router-cisco-iosxe","source_version":"17.12.1","target_profile":"router-juniper-junos","target_version":"23.4R2","mappings":mapping}
    response=client.post("/api/workbench/run",json=body); assert response.status_code==200, response.text
    result=response.json(); assert result["mode"]=="CONVERT" and result["renderer_available"]
    assert result["candidate_filename"]=="candidate-junos-23.4R2.set" and "# Source:" in result["candidate"] and "set interfaces ge-0/0/0" in result["candidate"]
    body["target_profile"]="firewall-paloalto-panos"; body["target_version"]="11.1"
    assert client.post("/api/workbench/run",json=body).status_code==422