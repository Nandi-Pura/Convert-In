import pytest
from app.core.migration.models import CompatibilityResult,CompatibilityStatus,MigrationMappings,MigrationPlan,PlannedEntity,RulebaseScope,TargetManagementMode
from app.core.models import Vendor
from app.core.renderers import PaloAltoRenderer
from app.core.migration.validation import validate_candidate
from app.core.renderers.paloalto import quote
from app.core.versions import PROFILES

REF="PANOS-11.1-CONFIGURE-CLI-HIERARCHY"

def render(kind,data,name="safe_name",profile="panos-11.1"):
    compatibility=CompatibilityResult(entity_id="e",entity_type=kind,source_name=name,status=CompatibilityStatus.SUPPORTED,capability_refs=[f"test-source:{kind}",f"{profile}:{kind}"],documentation_refs=[REF],version_status="VERIFIED")
    plan=MigrationPlan(source_vendor=Vendor.ASA,mappings=MigrationMappings(),compatibility=[compatibility],names=[],generate=[PlannedEntity(entity_id="e",entity_type=kind,target_name=name,data=data)])
    renderer=PaloAltoRenderer(); lines,report=renderer.render(plan,PROFILES[profile])
    return renderer,lines,report

@pytest.mark.parametrize("data,path",[
    ({"type":"host","value":"192.0.2.1/32"},["set","address","safe_name","ip-netmask","192.0.2.1/32"]),
    ({"type":"range","value":"192.0.2.1-192.0.2.2"},["set","address","safe_name","ip-range","192.0.2.1-192.0.2.2"]),
    ({"type":"fqdn","value":"www.example.com"},["set","address","safe_name","fqdn","www.example.com"]),
])
def test_local_address_dto_has_documented_root_and_context(data,path):
    renderer,lines,_=render("address",data)
    assert renderer.commands[0].path==path and lines[0]==" ".join(path)
    assert "vsys" not in path and renderer.commands[0].management_context.vsys=="vsys1"
    assert renderer.commands[0].documentation_refs==[REF]

def test_group_service_and_route_dtos():
    renderer,_,_=render("address_group",{"members":["member_1"]}); assert renderer.commands[0].path==["set","address-group","safe_name","static","member_1"]
    renderer,_,_=render("service",{"protocol":"tcp","ports":["443"]}); assert renderer.commands[0].path==["set","service","safe_name","protocol","tcp","port","443"]
    renderer,_,_=render("service_group",{"members":["https"]}); assert renderer.commands[0].path==["set","service-group","safe_name","members","https"]
    route={"virtual_router":"default","destination":"192.0.2.0/24","next_hop":"198.51.100.1","interface":"ethernet1/1","metric":10}
    renderer,_,_=render("route",route); assert renderer.commands[0].path[:8]==["set","network","virtual-router","default","routing-table","ip","static-route","safe_name"]

def test_12_1_legacy_route_rejected():
    route={"virtual_router":"default","destination":"192.0.2.0/24","next_hop":"198.51.100.1","interface":None,"metric":None}
    renderer,lines,report=render("route",route,profile="panos-12.1")
    assert not lines and not renderer.commands and "limited to PAN-OS 11.1" in report.errors[0]

def test_panorama_context_is_explicit_and_generation_blocked():
    with pytest.raises(ValueError,match="device_group"): MigrationMappings(management_mode=TargetManagementMode.PANORAMA)
    with pytest.raises(ValueError,match="rulebase_scope"): MigrationMappings(management_mode=TargetManagementMode.PANORAMA,device_group="DG1")
    mappings=MigrationMappings(management_mode=TargetManagementMode.PANORAMA,device_group="DG1",rulebase_scope=RulebaseScope.PRE)
    compatibility=CompatibilityResult(entity_id="e",entity_type="address",source_name="a",status="SUPPORTED",capability_refs=["panos-11.1:address"],documentation_refs=[REF])
    plan=MigrationPlan(source_vendor=Vendor.ASA,mappings=mappings,compatibility=[compatibility],names=[],generate=[])
    assert PaloAltoRenderer().render(plan,PROFILES["panos-11.1"])[1].errors

def test_serializer_rejects_unsafe_tokens_without_quoting():
    assert quote("safe_name-1.2/3")=="safe_name-1.2/3"
    assert quote("unsafe name")=='"unsafe name"'
    with pytest.raises(ValueError): quote("unsafe\nname")
    _,lines,report=render("address",{"type":"host","value":"192.0.2.1/32"},name="unsafe name")
    assert lines == ['set address "unsafe name" ip-netmask 192.0.2.1/32'] and not report.errors
    _,lines,report=render("address",{"type":"host","value":"192.0.2.1/32"},name="unsafe\nname")
    assert not lines and "unsafe PAN-OS name" in report.errors[0]

def test_candidate_validator_accepts_documented_local_firewall_roots():
    assert validate_candidate([
        "set address host ip-netmask 192.0.2.1/32",
        "set rulebase security rules allow-web action allow",
        "set network virtual-router default routing-table ip static-route default destination 0.0.0.0/0",
    ])==[]