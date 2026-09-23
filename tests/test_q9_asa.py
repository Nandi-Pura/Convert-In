from pathlib import Path

import pytest

from app.core.migration.models import MigrationMappings
from app.core.migration.planner import MigrationPlanner
from app.core.models import Address,FirewallConfig,NatRule,SecurityRule,Service,StaticRoute,Vendor
from app.core.reference_integrity import ReferenceIntegrityValidator
from app.core.renderers.asa import AsaRenderer,asa_token
from app.core.renderers.registry import lookup_renderer
from app.core.versions import PROFILES,resolve_context
from app.core.workbench import build


def config(vendor=Vendor.FORTIGATE):
    return FirewallConfig(metadata={"source_vendor":vendor},addresses=[Address(id="a1",name="HOST",type="host",value="10.0.0.1"),Address(id="a2",name="NET",type="network",value="10.0.1.0/24"),Address(id="a3",name="RANGE",type="range",value="10.0.2.1-10.0.2.9")],address_groups=[Address(id="ag1",name="INNER",type="group",members=["HOST"]),Address(id="ag2",name="ALL_NETS",type="group",members=["NET","INNER"])],services=[Service(id="s1",name="HTTPS",protocol="tcp",destination_ports=["443"]),Service(id="s2",name="DNS_RANGE",protocol="udp",destination_ports=["53-54"])],service_groups=[Service(id="sg1",name="WEB",protocol="group",members=["HTTPS"]),Service(id="sg2",name="APPS",protocol="group",members=["WEB","DNS_RANGE"])],security_policies=[SecurityRule(id="p1",name="ALLOW",position=1,action="allow")],nat_policies=[NatRule(id="n1",name="NAT",type="dynamic_pat")],static_routes=[StaticRoute(id="r1",name="DEFAULT",destination="0.0.0.0/0",next_hop="192.0.2.1",interface="outside")])


def render(cfg=None):
    cfg=cfg or config(); source={Vendor.FORTIGATE:"7.6",Vendor.ASA:"9.20",Vendor.PALO_ALTO:"11.1",Vendor.JUNIPER_SRX:"23.4R2"}[Vendor(cfg.metadata["source_vendor"])]
    plan=MigrationPlanner().plan(cfg,MigrationMappings(),resolve_context("",Vendor(cfg.metadata["source_vendor"]),source),resolve_context("",Vendor.ASA,"9.24"),ReferenceIntegrityValidator().validate(cfg),Vendor.ASA)
    renderer=AsaRenderer(); lines,report=renderer.render(plan); return plan,renderer,"\n".join(lines),report


def test_registry_exact_version_and_token_rejection():
    assert lookup_renderer("FIREWALL","CISCO","ASA","9.24") is AsaRenderer
    assert lookup_renderer("FIREWALL","CISCO","ASA","9.22") is None
    assert asa_token("safe_NAME-1")=="safe_NAME-1"
    for value in ("bad name","safe\naccess-list x","x;reload"):
        with pytest.raises(ValueError): asa_token(value)


def test_golden_objects_only_are_deterministic():
    plan,renderer,text,report=render(); assert text=="\n".join(AsaRenderer().render(plan)[0])
    assert text==Path("tests/fixtures/asa-target/expected.conf").read_text().rstrip("\n")
    assert report.generated_entities==9 and all(x.capability_id.startswith("asa-9.24-target:") for x in renderer.commands)
    assert "access-list" not in text and "access-group" not in text and "route " not in text and " nat " not in f" {text.lower()} "
    states={x.entity_id:x.status for x in plan.compatibility}; assert all(states[x]=="MANUAL_REVIEW" for x in ("p1","n1","r1"))


@pytest.mark.parametrize("vendor",[Vendor.FORTIGATE,Vendor.ASA,Vendor.PALO_ALTO,Vendor.JUNIPER_SRX])
def test_renderer_is_source_independent(vendor):
    plan,_,text,_=render(config(vendor)); assert plan.target_vendor==Vendor.ASA and "object network HOST" in text


def test_multiport_name_and_evidence_gates(monkeypatch):
    cfg=config(); cfg.services[0].destination_ports=["80","443"]; cfg.addresses[0].name="bad name"
    plan,_,text,_=render(cfg); states={x.entity_id:x.status for x in plan.compatibility}
    assert states["s1"]==states["a1"]=="MANUAL_REVIEW" and "bad name" not in text and "object service HTTPS" not in text
    monkeypatch.setattr(PROFILES["asa-9.24-target"].capabilities["address"],"renderer_support",False)
    plan,_,text,_=render(); assert "object network HOST" not in text


def test_workbench_candidate_contract():
    result=build("config firewall address\n edit HOST\n set subnet 10.0.0.1 255.255.255.255\n next\nend",Vendor.FORTIGATE,"7.6","9.24","firewall-fortinet-fortigate","firewall-cisco-asa")
    assert result["mode"]=="CONVERT" and result["candidate_filename"]=="candidate-asa-9.24.conf"
    assert "# Target: Cisco ASA / ASA 9.24" in result["candidate"] and "object network HOST" in result["candidate"]