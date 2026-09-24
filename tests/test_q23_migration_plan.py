import json

from fastapi.testclient import TestClient

from app.core.migration import InterfaceMapping, MigrationMappings, MigrationPlanner, build_plan_artifact, canonical_json
from app.core.migration.models import CompatibilityStatus
from app.core.models import Address, FirewallConfig, NatRule, Vendor
from app.core.versions import resolve_context
from app.main import app


def _plan(mapping="ethernet1/1"):
    cfg=FirewallConfig(metadata={"source_vendor":Vendor.ASA},addresses=[Address(id="a",name="A",type="host",value="192.0.2.1")],nat_policies=[NatRule(id="n",name="N",type="identity_nat",original_source=["A"],translated_source=["A"])])
    mappings=MigrationMappings(interfaces=[InterfaceMapping(source_interface="inside",source_nameif="inside",target_interface=mapping,target_zone="trust",suggested_zone="suggestion",confirmed=True)])
    plan=MigrationPlanner().plan(cfg,mappings,resolve_context("",Vendor.ASA,"9.20"),resolve_context("",Vendor.PALO_ALTO,"11.1"))
    return cfg,plan,build_plan_artifact(plan,cfg)


def test_contract_determinism_accounting_mapping_and_evidence():
    cfg,plan,first=_plan(); second=build_plan_artifact(plan,cfg)
    assert first.schema_=="convert-in.migration-plan/v1"
    assert canonical_json(first)==canonical_json(second) and first.plan_id==second.plan_id
    assert first.summary.total_entities==len(first.entities)==len(plan.compatibility)
    assert first.summary.render_eligible==len(plan.generate)
    assert first.context.interfaces[0].confirmed and first.context.interfaces[0].target_zone=="trust"
    assert first.entities[0].capability_refs and first.entities[0].documentation_refs
    assert first.entities[0].source_evidence_refs and first.entities[0].target_evidence_refs
    manual=next(x for x in first.entities if x.compatibility_status==CompatibilityStatus.MANUAL_REVIEW)
    assert manual.blocking and not manual.render_eligible
    assert "source.cfg" not in canonical_json(first) and "192.0.2.1" not in canonical_json(first)
    assert _plan("ethernet1/2")[2].plan_id!=first.plan_id
    reversed_plan=plan.model_copy(deep=True); reversed_plan.compatibility.reverse(); reversed_plan.names.reverse(); reversed_plan.generate.reverse()
    assert build_plan_artifact(reversed_plan,cfg).plan_id==first.plan_id


def test_blocked_states_remain_visible_and_not_renderable():
    _,plan,artifact=_plan()
    plan.compatibility[0].status=CompatibilityStatus.UNSUPPORTED; plan.compatibility[0].blocking=True; plan.generate=[]
    plan.compatibility[1].status=CompatibilityStatus.VERSION_NOT_VERIFIED; plan.compatibility[1].blocking=True
    artifact=build_plan_artifact(plan)
    assert {x.compatibility_status for x in artifact.entities}=={CompatibilityStatus.UNSUPPORTED,CompatibilityStatus.VERSION_NOT_VERIFIED}
    assert not any(x.render_eligible for x in artifact.entities)
    assert all(x.blocking for x in artifact.entities)


def test_api_export_does_not_require_render(monkeypatch,tmp_path):
    from app.config import settings
    monkeypatch.setattr(settings,"workspace_dir",tmp_path)
    client=TestClient(app)
    response=client.post("/api/analyze",data={"source":"ASA Version 9.20\nobject network A\n host 192.0.2.1\n","source_vendor":"cisco_asa","source_version":"9.20","target_vendor":"paloalto","target_version":"11.1"})
    project=response.text.split("Project: <code>")[1].split("<")[0]; base=f"/api/projects/{project}/migration"
    artifact=client.get(base+"/plan"); download=client.get(base+"/download/plan")
    assert artifact.status_code==download.status_code==200
    assert download.headers["content-type"].startswith("application/json")
    assert 'filename="migration-plan.json"' in download.headers["content-disposition"]
    assert artifact.json()==json.loads(download.content)
    assert not (tmp_path/project/"migration"/"candidate-pan-os.set").exists()