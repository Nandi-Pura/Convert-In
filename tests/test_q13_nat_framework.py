import pytest

from app.core.migration.models import CompatibilityResult,MigrationMappings,MigrationPlan,NatRouteOutcome,NatRulePlacement,PlannedEntity
from app.core.models import Vendor
from app.core.renderers.registry import lookup_renderer
from app.core.versions import PROFILES


def test_nat_mapping_contract_rejects_ambiguous_or_unsafe_context():
    with pytest.raises(ValueError,match="requires anchor_rule"):
        NatRulePlacement(mode="BEFORE")
    with pytest.raises(ValueError,match="forbids"):
        NatRulePlacement(mode="TOP",anchor_rule="existing")
    with pytest.raises(ValueError,match="invalid NAT route outcome"):
        NatRouteOutcome(nat_rule="rule 1",nat_from_zone="trust",nat_pre_translation_to_zone="untrust",security_post_translation_to_zone="dmz")
    outcome=NatRouteOutcome(nat_rule="rule-1",nat_from_zone="trust",nat_pre_translation_to_zone="untrust",security_post_translation_to_zone="dmz",confirmed=True)
    with pytest.raises(ValueError,match="duplicate NAT route outcome"):
        MigrationMappings(nat_rule_placement=NatRulePlacement(mode="BOTTOM"),nat_route_outcomes=[outcome,outcome])


def test_every_firewall_renderer_explicitly_emits_zero_nat_commands():
    targets=(("CISCO","ASA","9.24","asa-9.24-target",Vendor.ASA),("FORTINET","FORTIGATE","7.6.4","fortios-7.6.4",Vendor.FORTIGATE),("PALO_ALTO","PAN_OS","11.1","panos-11.1",Vendor.PALO_ALTO),("JUNIPER","SRX","23.4R2","junos-23.4R2-srx-target",Vendor.JUNIPER_SRX))
    item=PlannedEntity(entity_id="nat-1",entity_type="nat_policy",target_name="NAT_1",data={"type":"static_source_nat"})
    decision=CompatibilityResult(entity_id="nat-1",entity_type="nat_policy",source_name="NAT_1",status="SUPPORTED",version_status="VERIFIED",renderer_support=True,target_evidence_refs=["TEST"],capability_refs=["SOURCE","TARGET"],documentation_refs=["TEST"],renderer_capability_id="static_source_nat")
    for vendor,platform,version,profile,target_vendor in targets:
        renderer=lookup_renderer("FIREWALL",vendor,platform,version)()
        plan=MigrationPlan(source_vendor=Vendor.ASA,target_vendor=target_vendor,mappings=MigrationMappings(),compatibility=[decision],names=[],generate=[item])
        lines,_=renderer.render(plan,PROFILES[profile])
        assert lines==[]