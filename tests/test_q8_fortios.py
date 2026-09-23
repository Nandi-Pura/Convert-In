from pathlib import Path

import pytest

from app.core.migration.models import InterfaceMapping,MigrationMappings
from app.core.migration.planner import MigrationPlanner
from app.core.models import Address,FirewallConfig,Interface,NatRule,SecurityRule,Service,StaticRoute,Vendor,Zone
from app.core.platforms import platform_profile
from app.core.reference_integrity import ReferenceIntegrityValidator
from app.core.renderers.fortios import FortiOSRenderer,encode_fortios_value
from app.core.renderers.registry import lookup_renderer
from app.core.versions import PROFILES,resolve_context
from app.core.workbench import build


def mappings():
    return MigrationMappings(interfaces=[
        InterfaceMapping(source_interface="ethernet2",source_nameif="inside",target_interface="port2",target_zone="port2",confirmed=True),
        InterfaceMapping(source_interface="ethernet1",source_nameif="outside",target_interface="port1",target_zone="port1",confirmed=True),
    ])


def config(vendor=Vendor.ASA):
    return FirewallConfig(metadata={"source_vendor":vendor},interfaces=[Interface(id="i1",name="ethernet2",zone="inside"),Interface(id="i2",name="ethernet1",zone="outside")],zones=[Zone(id="z1",name="inside",interfaces=["ethernet2"]),Zone(id="z2",name="outside",interfaces=["ethernet1"])],addresses=[
        Address(id="a1",name="HOST",type="host",value="10.0.0.1"),
        Address(id="a2",name="NET",type="network",value="10.0.1.0/24"),
        Address(id="a3",name="RANGE",type="range",value="10.0.2.1-10.0.2.9"),
    ],address_groups=[Address(id="ag",name="ADDRS",type="group",members=["HOST","NET","RANGE"])],services=[
        Service(id="s1",name="TCP_WEB",protocol="tcp",destination_ports=["80","443-444"]),
        Service(id="s2",name="UDP_DNS",protocol="udp",destination_ports=["53"]),
    ],service_groups=[Service(id="sg",name="WEB_DNS",protocol="group",members=["TCP_WEB","UDP_DNS"])],security_policies=[
        SecurityRule(id="p2",name="DENY_WEB",position=2,source_zones=["inside"],destination_zones=["outside"],sources=["ADDRS"],destinations=["HOST"],services=["WEB_DNS"],action="deny",enabled=False),
        SecurityRule(id="p1",name="ALLOW_WEB",position=1,source_zones=["inside"],destination_zones=["outside"],sources=["HOST"],destinations=["NET"],services=["TCP_WEB"],action="allow"),
    ],nat_policies=[NatRule(id="n1",name="NAT",type="dynamic_pat")],static_routes=[StaticRoute(id="r1",name="DEFAULT",destination="0.0.0.0/0",next_hop="192.0.2.1",interface="ethernet1")])


def render(cfg=None):
    cfg=cfg or config(); source_version={Vendor.ASA:"9.24",Vendor.FORTIGATE:"7.6",Vendor.PALO_ALTO:"11.1",Vendor.JUNIPER_SRX:"23.4R2"}[Vendor(cfg.metadata["source_vendor"])]
    plan=MigrationPlanner().plan(cfg,mappings(),resolve_context("",Vendor(cfg.metadata["source_vendor"]),source_version),resolve_context("",Vendor.FORTIGATE,"7.6.4"),ReferenceIntegrityValidator().validate(cfg),Vendor.FORTIGATE)
    renderer=FortiOSRenderer(); lines,report=renderer.render(plan); return plan,renderer,"\n".join(lines),report


def test_profile_registry_and_exact_version_isolation():
    profile=platform_profile("firewall-fortinet-fortigate","7.6.4")
    assert profile.target_renderer=="FortiOSRenderer" and profile.target_capability=="BOUNDED_RENDERER"
    assert lookup_renderer("FIREWALL","FORTINET","FORTIGATE","7.6.4") is FortiOSRenderer
    assert lookup_renderer("FIREWALL","FORTINET","FORTIGATE","7.6.3") is None


def test_encoder_quotes_text_and_rejects_injection():
    assert encode_fortios_value("plain") == "plain"
    assert encode_fortios_value('café "x" \\') == '"café \\"x\\" \\\\"'
    with pytest.raises(ValueError): encode_fortios_value("safe\nend")
    with pytest.raises(ValueError): encode_fortios_value("safe\x00end")


def test_golden_candidate_is_grouped_ordered_and_deterministic():
    plan,renderer,text,report=render(); assert text=="\n".join(FortiOSRenderer().render(plan)[0])
    assert text==Path("tests/fixtures/fortios/expected.conf").read_text().rstrip("\n")
    assert text.index("config firewall address")<text.index("config firewall addrgrp")<text.index("config firewall service custom")<text.index("config firewall service group")<text.index("config router static")<text.index("config firewall policy")
    assert 'edit 1\n        set name ALLOW_WEB' in text and 'edit 2\n        set name DENY_WEB' in text and "set status disable" in text
    assert not any("nat" in line.lower() for line in text.splitlines())
    nat=next(x for x in plan.compatibility if x.entity_id=="n1"); assert nat.status=="MANUAL_REVIEW" and report.generated_entities==10
    assert all(command.capability_id.startswith("fortios-7.6.4:") for command in renderer.commands)


@pytest.mark.parametrize("vendor",[Vendor.ASA,Vendor.FORTIGATE,Vendor.PALO_ALTO,Vendor.JUNIPER_SRX])
def test_target_renderer_is_source_independent(vendor):
    plan,_,text,_=render(config(vendor)); assert plan.source_vendor==vendor and plan.target_vendor==Vendor.FORTIGATE
    assert "config firewall address" in text and plan.generate


def test_name_dependency_interface_route_distance_and_logging_gates():
    cfg=config(); cfg.addresses[0].name="bad name"; cfg.address_groups[0].members.append("MISSING"); cfg.services[0].source_ports=["1024-65535"]
    cfg.security_policies[0].log_end=True; cfg.static_routes[0].distance=10
    plan,_,text,_=render(cfg); states={x.entity_id:x.status for x in plan.compatibility}
    assert all(states[x]=="MANUAL_REVIEW" for x in ("a1","ag","s1","p2","r1"))
    assert "bad name" not in text and "MISSING" not in text and "set distance" not in text and "set logtraffic" not in text


def test_evidence_removal_blocks_emission(monkeypatch):
    monkeypatch.setattr(PROFILES["fortios-7.6.4"].capabilities["address"],"renderer_support",False)
    plan,_,text,_=render(); assert all(x.entity_id!="a1" for x in plan.generate) and "edit HOST" not in text


def test_workbench_selects_fortios_and_names_candidate():
    text="ASA Version 9.24\nobject network HOST\n host 10.0.0.1"
    result=build(text,Vendor.ASA,"9.24","7.6.4","firewall-cisco-asa","firewall-fortinet-fortigate")
    assert result["mode"]=="CONVERT" and result["target_profile"]["capability"]=="BOUNDED_RENDERER"
    assert result["candidate_filename"]=="candidate-fortios-7.6.4.conf"
    assert "# Target: Fortinet FORTIGATE / FortiOS 7.6.4" in result["candidate"] and "config firewall address" in result["candidate"]