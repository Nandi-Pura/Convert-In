import json

from fastapi.testclient import TestClient

from app.core.migration.models import CompatibilityResult, CompatibilityStatus
from app.core.models import Address, FirewallConfig, NatRule, RouterConfig, RouterStaticRoute, SwitchConfig, SwitchPort
from app.core.semantic_diff import build_semantic_diff, serialize_semantic_diff
from app.main import app


SOURCE={"domain":"FIREWALL","vendor":"cisco_asa","platform":"ASA","exact_version":"9.20"}
TARGET={"domain":"FIREWALL","vendor":"paloalto","platform":"PAN_OS","exact_version":"11.1"}


def decision(entity,status=CompatibilityStatus.EXACT,**values):
    return CompatibilityResult(entity_id=entity.id,entity_type="address",source_name=entity.name,status=status,decision_id="cp2",**values)


def test_determinism_ordering_classifications_sets_and_no_mutation():
    entity=Address(id="source-a",name="WEB-SERVER",type="host",value="192.0.2.1",members=["b","a"]); cfg=FirewallConfig(addresses=[entity]); before=cfg.model_dump_json()
    cp2=decision(entity,source_semantic={"name":"WEB-SERVER","type":"host","value":"192.0.2.1","members":["b","a"]},target_semantic={"name":"WEB_SERVER","type":"host","value":"192.0.2.1","members":["a","b"]},preserved_semantics=["type","value","members"],source_evidence_refs=["SRC"],target_evidence_refs=["DST"])
    mappings={"interfaces":[{"source_entity_id":"source-a","target_identity":"WEB_SERVER","confirmed":True}]}
    first=build_semantic_diff(cfg,[cp2],SOURCE,TARGET,mappings=mappings); second=build_semantic_diff(cfg,[cp2],SOURCE,TARGET,mappings=mappings)
    assert first.schema_=="convert-in.semantic-diff/v2" and serialize_semantic_diff(first)==serialize_semantic_diff(second)
    assert first.fingerprint==second.fingerprint and len(first.entities[0].entity_id)==16
    props=first.entities[0].property_diffs; assert [x.property for x in props]==sorted(x.property for x in props)
    assert next(x for x in props if x.property=="name").classification=="CHANGED"
    assert next(x for x in props if x.property=="value").classification=="PRESERVED"
    assert next(x for x in props if x.property=="members").classification=="PRESERVED"
    assert cfg.model_dump_json()==before


def test_loss_requires_explicit_unsupported_and_unknown_is_review():
    entity=Address(id="a",name="A",type="fqdn",value="example.test"); cfg=FirewallConfig(addresses=[entity])
    lost=decision(entity,CompatibilityStatus.UNSUPPORTED,lost_semantics=["value"])
    artifact=build_semantic_diff(cfg,[lost],SOURCE,TARGET); values={x.property:x.classification for x in artifact.entities[0].property_diffs}
    assert values["value"]=="LOST" and values["type"]=="REVIEW"
    for status in (CompatibilityStatus.VERSION_NOT_VERIFIED,CompatibilityStatus.MANUAL_REVIEW):
        assert {x.classification for x in build_semantic_diff(cfg,[decision(entity,status)],SOURCE,TARGET).entities[0].property_diffs}=={"REVIEW"}


def test_domains_ordered_values_and_nat_are_conservative():
    port=SwitchPort(id="p",name="Gi1/0/1",allowed_vlans=[20,10]); switch=SwitchConfig(ports=[port])
    item=CompatibilityResult(entity_id="p",entity_type="interface",source_name=port.name,status=CompatibilityStatus.SUPPORTED,target_semantic={"allowed_vlans":[10,20]},preserved_semantics=["allowed_vlans"])
    artifact=build_semantic_diff(switch,[item],{**SOURCE,"domain":"SWITCH"},{**TARGET,"domain":"SWITCH"})
    assert next(x for x in artifact.entities[0].property_diffs if x.property=="allowed_vlans").classification=="PRESERVED"
    route=RouterStaticRoute(id="r",name="r",destination="0.0.0.0/0",next_hop="192.0.2.1"); router=RouterConfig(static_routes=[route])
    route_item=CompatibilityResult(entity_id="r",entity_type="route",source_name="r",status=CompatibilityStatus.SUPPORTED,target_semantic={"destination":"0.0.0.0/0","next_hop":"192.0.2.2"},preserved_semantics=["destination","next_hop"])
    assert next(x for x in build_semantic_diff(router,[route_item],{**SOURCE,"domain":"ROUTER"},{**TARGET,"domain":"ROUTER"}).entities[0].property_diffs if x.property=="next_hop").classification=="CHANGED"
    nat=NatRule(id="n",name="N",type="identity_nat"); nat_item=CompatibilityResult(entity_id="n",entity_type="nat_policy",source_name="N",status=CompatibilityStatus.SUPPORTED,preserved_semantics=["type"],target_semantic={"type":"identity_nat"})
    assert {x.classification for x in build_semantic_diff(FirewallConfig(nat_policies=[nat]),[nat_item],SOURCE,TARGET).entities[0].property_diffs}=={"REVIEW"}


def test_api_post_get_download_without_candidate(monkeypatch,tmp_path):
    from app.config import settings
    monkeypatch.setattr(settings,"workspace_dir",tmp_path); client=TestClient(app)
    response=client.post("/api/analyze",data={"source":"ASA Version 9.20\nobject network A\n host 192.0.2.1\n","source_vendor":"cisco_asa","source_version":"9.20","target_vendor":"paloalto","target_version":"11.1"})
    project=response.text.split("Project: <code>")[1].split("<")[0]; base=f"/api/projects/{project}/migration"
    generated=client.post(base+"/semantic-diff"); read=client.get(base+"/semantic-diff"); download=client.get(base+"/download/semantic-diff")
    assert generated.status_code==read.status_code==download.status_code==200
    assert generated.json()==read.json()==json.loads(download.content)
    first=download.content; client.post(base+"/semantic-diff"); assert client.get(base+"/download/semantic-diff").content==first
    assert not (tmp_path/project/"migration"/"candidate-pan-os.set").exists()