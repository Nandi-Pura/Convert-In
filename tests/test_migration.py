from pathlib import Path
from fastapi.testclient import TestClient
from app.main import app
from app.core.models import Address, FirewallConfig, SecurityRule, Service, Vendor
from app.core.parsing import parse_config
from app.core.migration import InterfaceMapping, MigrationMappings, MigrationPlanner
from app.core.renderers import PaloAltoRenderer
from app.core.renderers.paloalto import quote

def mappings():
    return MigrationMappings(interfaces=[InterfaceMapping(source_interface="GigabitEthernet0/0",source_nameif="outside",target_interface="ethernet1/1",target_zone="untrust",confirmed=True),InterfaceMapping(source_interface="GigabitEthernet0/1",source_nameif="inside",target_interface="ethernet1/2",target_zone="trust",confirmed=True)])

def test_basic_golden_and_no_silent_omission():
    cfg=parse_config(Path("examples/asa/basic.cfg").read_text(),Vendor.ASA)
    plan=MigrationPlanner().plan(cfg,mappings()); lines,report=PaloAltoRenderer().render(plan)
    assert lines==[]
    assert report.total_entities==report.generated_entities+report.skipped_entities
    policy=next(x for x in report.compatibility if x.entity_type=="security_policy")
    assert policy.status=="MANUAL_REVIEW"

def test_policy_order_disabled_logging_and_mapping():
    cfg=FirewallConfig(metadata={"source_vendor":Vendor.ASA},addresses=[Address(id="a",name="A",type="host",value="10.0.0.1")],services=[Service(id="s",name="S",protocol="tcp",destination_ports=["443"])],security_policies=[SecurityRule(id="r2",name="Second",position=2,source_zones=["inside"],destination_zones=["outside"],sources=["A"],destinations=["any"],services=["S"],action="deny",enabled=False,log_end=True),SecurityRule(id="r1",name="First",position=1,source_zones=["inside"],destination_zones=["outside"],action="allow")])
    lines,report=PaloAltoRenderer().render(MigrationPlanner().plan(cfg,mappings()))
    assert not lines and report.manual_review==2 and report.version_not_verified==2

def test_negative_semantics_names_and_quoting():
    cfg=FirewallConfig(metadata={"source_vendor":Vendor.ASA},addresses=[Address(id="a",name="Web Server #1",type="host",value="10.0.0.1"),Address(id="b",name="Web Server @1",type="host",value="10.0.0.2")],services=[Service(id="bad",name="bad",protocol="icmp")],security_policies=[SecurityRule(id="r",name="unknown",position=1,source_zones=["inside"],destination_zones=["outside"],action="reject")])
    plan=MigrationPlanner().plan(cfg,mappings()); lines,report=PaloAltoRenderer().render(plan)
    assert any(x.collision for x in report.names)
    assert not any(" bad " in x or " rules unknown " in x for x in lines)
    assert report.unsupported==2
    import pytest
    with pytest.raises(ValueError): quote('a "b" \\ c')

def test_migration_api_smoke_and_downloads():
    client=TestClient(app); source=Path("examples/asa/basic.cfg").read_text()
    response=client.post("/api/analyze",data={"source":source,"source_vendor":"cisco_asa","source_version":"9.20","target_vendor":"paloalto","target_version":"11.1"}); project=response.text.split("Project: <code>")[1].split("<")[0]
    base=f"/api/projects/{project}/migration"; data=client.get(base+"/mappings").json()
    for item in data["interfaces"]: item.update(target_interface="ethernet1/1" if item["source_nameif"]=="outside" else "ethernet1/2",target_zone="untrust" if item["source_nameif"]=="outside" else "trust",confirmed=True)
    assert client.put(base+"/mappings",json=data).status_code==200
    assert client.get(base+"/compatibility").status_code==200 and client.post(base+"/plan").status_code==200
    rendered=client.post(base+"/render"); assert rendered.status_code==200 and rendered.json()["status"]=="REVIEW_REQUIRED"
    assert client.get(base+"/report").status_code==200
    assert "attachment" in client.get(base+"/download/config").headers["content-disposition"]
    assert "attachment" in client.get(base+"/download/report").headers["content-disposition"]