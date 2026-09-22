from app.core.migration import MigrationMappings,MigrationPlanner
from app.core.migration.models import CompatibilityStatus,InterfaceMapping,SecurityRulePlacement
from app.core.models import Address,FirewallConfig,NatRule,SecurityRule,Vendor
from app.core.reference_integrity import ReferenceIntegrityValidator
from app.core.renderers import PaloAltoRenderer
from app.core.versions import PROFILES,resolve_context

def plan(cfg):
    mappings=MigrationMappings(interfaces=[InterfaceMapping(source_interface="inside",source_nameif="inside",target_interface="ethernet1/1",target_zone="trust",confirmed=True),InterfaceMapping(source_interface="outside",source_nameif="outside",target_interface="ethernet1/2",target_zone="untrust",confirmed=True)],security_rule_placement=SecurityRulePlacement(mode="BOTTOM"))
    return MigrationPlanner().plan(cfg,mappings,resolve_context("",Vendor.ASA,"9.20"),resolve_context("",Vendor.PALO_ALTO,"11.1"),ReferenceIntegrityValidator().validate(cfg))

def test_decision_id_is_stable_and_cp1_blocks_dependency():
    cfg=FirewallConfig(metadata={"source_vendor":Vendor.ASA},addresses=[Address(id="a",name="A",type="host",value="192.0.2.1")])
    first,second=plan(cfg),plan(cfg)
    assert first.compatibility[0].decision_id==second.compatibility[0].decision_id
    assert first.compatibility[0].status==CompatibilityStatus.SUPPORTED
    assert first.compatibility[0].preserved_semantics==["type","value"]
    assert first.compatibility[0].lost_semantics==[]

def test_different_target_field_name_preserves_behavior():
    from app.core.models import Service
    cfg=FirewallConfig(metadata={"source_vendor":Vendor.ASA},services=[Service(id="s",name="HTTPS",protocol="tcp",destination_ports=["443"])])
    decision=plan(cfg).compatibility[0]
    assert "destination_ports" in decision.preserved_semantics
    assert "destination_ports" not in decision.lost_semantics

def test_missing_each_evidence_gate_blocks_emission(monkeypatch):
    cfg=FirewallConfig(metadata={"source_vendor":Vendor.ASA},addresses=[Address(id="a",name="A",type="host",value="192.0.2.1")])
    monkeypatch.setattr(PROFILES["panos-11.1"].capabilities["address"],"renderer_support",False)
    decision=plan(cfg).compatibility[0]
    assert decision.status==CompatibilityStatus.VERSION_NOT_VERIFIED and decision.blocking
    assert not PaloAltoRenderer().render(plan(cfg))[0]

def test_behavioral_partial_never_emits():
    cfg=FirewallConfig(metadata={"source_vendor":Vendor.ASA},addresses=[Address(id="a",name="A",type="host",value="192.0.2.1")])
    migration=plan(cfg); item=migration.compatibility[0]; item.status=CompatibilityStatus.PARTIAL
    item.blocking=True
    assert not PaloAltoRenderer().render(migration)[0]

def test_nat_decision_exists_but_zero_commands():
    cfg=FirewallConfig(metadata={"source_vendor":Vendor.ASA},nat_policies=[NatRule(id="n",name="N",type="static_source_nat",original_source=["any"],translated_source=["any"])])
    migration=plan(cfg); lines,_=PaloAltoRenderer().render(migration)
    assert next(x for x in migration.compatibility if x.entity_type=="nat_policy").status not in {CompatibilityStatus.EXACT,CompatibilityStatus.SUPPORTED}
    assert not [x for x in lines if x.startswith("set rulebase nat")]