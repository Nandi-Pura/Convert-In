from pathlib import Path

import pytest

from app.core.migration.models import InterfaceMapping,MigrationMappings
from app.core.migration.planner import MigrationPlanner
from app.core.models import Address,FirewallConfig,Interface,NatRule,SecurityRule,Service,StaticRoute,Vendor,Zone
from app.core.reference_integrity import ReferenceIntegrityValidator
from app.core.renderers.junos_srx import JunosSrxRenderer,junos_token
from app.core.renderers.registry import lookup_renderer
from app.core.versions import PROFILES,resolve_context
from app.core.workbench import build


def mappings():
    return MigrationMappings(interfaces=[
        InterfaceMapping(source_interface="port2",source_nameif="inside",target_interface="ge-0/0/1.0",target_zone="trust",confirmed=True,target_profile="firewall-juniper-srx",target_version="23.4R2"),
        InterfaceMapping(source_interface="port1",source_nameif="outside",target_interface="ge-0/0/0.0",target_zone="untrust",confirmed=True,target_profile="firewall-juniper-srx",target_version="23.4R2"),
    ])


def config(vendor=Vendor.FORTIGATE):
    return FirewallConfig(metadata={"source_vendor":vendor},interfaces=[Interface(id="i1",name="port2",zone="inside"),Interface(id="i2",name="port1",zone="outside")],zones=[Zone(id="z1",name="inside",interfaces=["port2"]),Zone(id="z2",name="outside",interfaces=["port1"])],addresses=[Address(id="a1",name="HOST",type="host",value="10.0.0.1"),Address(id="a2",name="NET",type="network",value="10.0.1.0/24"),Address(id="a3",name="RANGE",type="range",value="10.0.2.1-10.0.2.9")],address_groups=[Address(id="ag",name="ADDRS",type="group",members=["HOST","NET","RANGE"])],services=[Service(id="s1",name="HTTPS_CUSTOM",protocol="tcp",destination_ports=["443"]),Service(id="s2",name="DNS_RANGE",protocol="udp",destination_ports=["53-54"])],service_groups=[Service(id="sg",name="APPS",protocol="group",members=["HTTPS_CUSTOM","DNS_RANGE"])],security_policies=[SecurityRule(id="p1",name="ALLOW_WEB",position=1,source_zones=["inside"],destination_zones=["outside"],sources=["ADDRS"],destinations=["HOST"],services=["APPS"],action="allow")],nat_policies=[NatRule(id="n1",name="NAT",type="source_nat")],static_routes=[StaticRoute(id="r1",name="DEFAULT",destination="0.0.0.0/0",next_hop="192.0.2.1")])


def render(cfg=None):
    cfg=cfg or config(); vendor=Vendor(cfg.metadata["source_vendor"]); source={Vendor.ASA:"9.24",Vendor.FORTIGATE:"7.6",Vendor.PALO_ALTO:"11.1",Vendor.JUNIPER_SRX:"23.4R2"}[vendor]
    plan=MigrationPlanner().plan(cfg,mappings(),resolve_context("",vendor,source),resolve_context("",Vendor.JUNIPER_SRX,"23.4R2"),ReferenceIntegrityValidator().validate(cfg),Vendor.JUNIPER_SRX)
    renderer=JunosSrxRenderer(); lines,report=renderer.render(plan); return plan,renderer,"\n".join(lines),report


def test_exact_registry_profile_and_encoder():
    assert lookup_renderer("FIREWALL","JUNIPER","SRX","23.4R2") is JunosSrxRenderer
    assert lookup_renderer("FIREWALL","JUNIPER","SRX","23.4R1") is None
    assert junos_token('café "x" \\')=='"café \\"x\\" \\\\"'
    for value in ("bad\nset system root-authentication", "bad\rdelete security", "bad\x00x", "bad\x1fx"):
        with pytest.raises(ValueError): junos_token(value)


def test_golden_dependency_order_determinism_and_accounting():
    plan,renderer,text,report=render(); assert text=="\n".join(JunosSrxRenderer().render(plan)[0])
    assert text==Path("tests/fixtures/srx-target/expected.set").read_text().rstrip("\n")
    assert report.generated_entities==9 and not any("security nat" in line for line in text.splitlines())
    assert next(x for x in plan.compatibility if x.entity_id=="n1").status=="MANUAL_REVIEW"
    assert all(c.capability_id.startswith("junos-23.4R2-srx-target:") for c in renderer.commands)


@pytest.mark.parametrize("vendor",[Vendor.ASA,Vendor.FORTIGATE,Vendor.PALO_ALTO,Vendor.JUNIPER_SRX])
def test_four_sources_use_same_ir_renderer(vendor):
    cfg=config(vendor); cfg.security_policies=[]
    plan,_,text,_=render(cfg); assert plan.source_vendor==vendor and "set security address-book global address HOST 10.0.0.1/32" in text


def test_negative_semantics_and_dependency_closure():
    cfg=config(); cfg.services[0].source_ports=["1024-65535"]; cfg.security_policies[0].enabled=False; cfg.static_routes[0].distance=10
    cfg.address_groups[0].members.append("MISSING")
    plan,_,text,_=render(cfg); states={x.entity_id:x.status for x in plan.compatibility}
    assert all(states[x]=="MANUAL_REVIEW" for x in ("s1","p1","r1","ag"))
    assert "application HTTPS_CUSTOM" not in text and "policy ALLOW_WEB" not in text and "route 0.0.0.0/0" not in text and "address-set ADDRS" not in text


def test_evidence_gate(monkeypatch):
    monkeypatch.setattr(PROFILES["junos-23.4R2-srx-target"].capabilities["address"],"renderer_support",False)
    plan,_,text,_=render(); assert "address HOST" not in text and next(x for x in plan.compatibility if x.entity_id=="a1").status=="VERSION_NOT_VERIFIED"


def test_workbench_candidate_contract():
    text="config firewall address\n edit HOST\n set subnet 10.0.0.1 255.255.255.255\n next\nend"
    result=build(text,Vendor.FORTIGATE,"7.6","23.4R2","firewall-fortinet-fortigate","firewall-juniper-srx")
    assert result["mode"]=="CONVERT" and result["candidate_filename"]=="candidate-srx-23.4R2.set"
    assert "# Target: Juniper SRX / Junos OS 23.4R2" in result["candidate"] and "address HOST 10.0.0.1/32" in result["candidate"]