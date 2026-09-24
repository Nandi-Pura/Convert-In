import json

from fastapi.testclient import TestClient

from app.core.linting import build_lint_artifact, canonical_json, lint_config, serialize_lint_artifact
from app.core.models import (Address, BGPNeighbor, BGPProcess, FirewallConfig, LAG, PrefixList, RouterConfig,
    RouterStaticRoute, SVI, SecurityRule, Service, SwitchConfig, VLAN)
from app.main import app
from app.core.switch_assurance import SwitchReferenceIntegrityValidator


def rules(findings): return {x.rule_id for x in findings}


def test_firewall_rules_determinism_and_no_mutation():
    cfg=FirewallConfig(
        addresses=[Address(id="a",name="a",type="network",value="10.0.0.0/24"),Address(id="b",name="b",type="network",value="10.0.0.0/24"),Address(id="c",name="c",type="host",value="10.0.0.2")],
        services=[Service(id="s1",name="s1",protocol="tcp",destination_ports=["443"]),Service(id="s2",name="s2",protocol="tcp",destination_ports=["443"])],
        security_policies=[SecurityRule(id="p1",name="p1",position=1,source_zones=["in"],destination_zones=["out"],sources=["any"],destinations=["any"],services=["any"],action="allow"),SecurityRule(id="p2",name="p2",position=2,source_zones=["in"],destination_zones=["out"],sources=["a"],destinations=["a"],services=["s1"],action="allow"),SecurityRule(id="off",name="off",position=3,enabled=False)])
    before=cfg.model_dump_json(); first=lint_config(cfg); second=lint_config(cfg)
    assert before==cfg.model_dump_json()
    assert {"DUPLICATE_ADDRESS_OBJECT","DUPLICATE_SERVICE_OBJECT","UNUSED_ADDRESS_OBJECT","UNUSED_SERVICE_OBJECT","DISABLED_POLICY","BROAD_ANY_POLICY","ADDRESS_RANGE_OVERLAP","POLICY_SHADOW_CANDIDATE"}<=rules(first)
    assert [x.id for x in first]==[x.id for x in second]
    artifact=build_lint_artifact(first,"project")
    assert artifact.fingerprint==build_lint_artifact(list(reversed(second)),"project").fingerprint
    assert serialize_lint_artifact(artifact)==serialize_lint_artifact(build_lint_artifact(list(reversed(second)),"project"))
    assert canonical_json(artifact).count("sha256:")==1


def test_uncertain_policy_shadow_is_not_reported():
    cfg=FirewallConfig(security_policies=[SecurityRule(id="p1",name="p1",position=1,source_zones=["in"],destination_zones=["out"],action="allow",log_end=True),SecurityRule(id="p2",name="p2",position=2,source_zones=["in"],destination_zones=["out"],action="allow")])
    assert "POLICY_SHADOW_CANDIDATE" not in rules(lint_config(cfg))


def test_switch_and_router_rules():
    switch=SwitchConfig(vlans=[VLAN(id="v10",vlan_id=10)],lags=[LAG(id="l1",name="Port-channel1")],svis=[SVI(id="s20",name="Vlan20",vlan_id=20)])
    assert {"UNREFERENCED_VLAN","LAG_WITHOUT_MEMBERS","SVI_WITHOUT_VLAN"}<=rules(lint_config(switch,SwitchReferenceIntegrityValidator().validate(switch)))
    router=RouterConfig(static_routes=[RouterStaticRoute(id="r1",name="r1",destination="0.0.0.0/0",next_hop="192.0.2.1"),RouterStaticRoute(id="r2",name="r2",destination="0.0.0.0/0",next_hop="192.0.2.1")],prefix_lists=[PrefixList(id="pl",name="PL")],bgp_processes=[BGPProcess(id="b",name="B",local_as=65000,neighbors=[BGPNeighbor(id="n",name="N",address="192.0.2.2")])])
    assert {"DUPLICATE_STATIC_ROUTE","UNUSED_PREFIX_LIST","EMPTY_PREFIX_LIST"}<=rules(lint_config(router))


def test_api_generate_get_download_without_renderer(monkeypatch,tmp_path):
    from app.config import settings
    monkeypatch.setattr(settings,"workspace_dir",tmp_path); client=TestClient(app)
    response=client.post("/api/analyze",data={"source":"ASA Version 9.20\nobject network A\n host 192.0.2.1\n","source_vendor":"cisco_asa","source_version":"9.20","target_vendor":"paloalto","target_version":"11.1"})
    project=response.text.split("Project: <code>")[1].split("<")[0]; url=f"/api/projects/{project}"
    generated=client.post(url+"/lint"); read=client.get(url+"/lint"); download=client.get(url+"/migration/download/lint")
    assert generated.status_code==read.status_code==download.status_code==200
    assert generated.json()==read.json()==json.loads(download.content)
    first=download.content; client.post(url+"/lint"); assert client.get(url+"/migration/download/lint").content==first
    assert not (tmp_path/project/"migration"/"candidate-pan-os.set").exists()