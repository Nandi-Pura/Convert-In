import time
from pathlib import Path
from fastapi.testclient import TestClient
from app.main import app
from app.core.models import Vendor
from app.core.parsing import parse_config
from app.core.migration import InterfaceMapping,MigrationMappings,MigrationPlanner,SUPPORTED_MIGRATION_PAIRS
from app.core.renderers import PaloAltoRenderer
from app.core.review import build_review,validate_migration

FORTI='''config system interface
 edit "lan"
  set ip 10.0.0.1 255.255.255.0
 next
 edit "wan1"
  set ip 192.0.2.2 255.255.255.0
 next
end
config firewall address
 edit "WEB_SERVER"
  set subnet 192.0.2.10 255.255.255.255
 next
end
config firewall service custom
 edit "HTTPS"
  set tcp-portrange 443
 next
end
config firewall policy
 edit 10
  set name "LAN to WEB"
  set srcintf "lan"
  set dstintf "wan1"
  set srcaddr "all"
  set dstaddr "WEB_SERVER"
  set service "HTTPS"
  set action accept
  set logtraffic all
 next
end
'''

def mappings():
    return MigrationMappings(interfaces=[InterfaceMapping(source_interface="lan",source_nameif="lan",target_interface="ethernet1/2",target_zone="trust",confirmed=True),InterfaceMapping(source_interface="wan1",source_nameif="wan1",target_interface="ethernet1/1",target_zone="untrust",confirmed=True)])

def test_pair_registry_and_basic_fortigate_plan_review_validation():
    assert {(a.value,b.value) for a,b in SUPPORTED_MIGRATION_PAIRS}=={("cisco_asa","paloalto"),("fortigate","paloalto"),("juniper_srx","paloalto")}
    cfg=parse_config(FORTI,Vendor.FORTIGATE); plan=MigrationPlanner().plan(cfg,mappings()); renderer=PaloAltoRenderer(); lines,report=renderer.render(plan); review=build_review(cfg,plan,renderer.commands)
    assert plan.source_vendor==Vendor.FORTIGATE and report.total_entities==report.generated_entities+report.skipped_entities
    assert not lines
    assert all(item.source_vendor=="fortigate" for item in review.items) and validate_migration(cfg,plan,review,lines).status=="BLOCKING"

def test_cross_vendor_policy_and_plan_parity():
    asa='''interface Gi0/0\n nameif outside\n ip address 192.0.2.2 255.255.255.0\n!\ninterface Gi0/1\n nameif inside\n ip address 10.0.0.1 255.255.255.0\n!\nobject network WEB_SERVER\n host 192.0.2.10\nobject service HTTPS\n service tcp destination eq 443\naccess-list ACL extended permit tcp any object WEB_SERVER object-group HTTPS\naccess-group ACL in interface inside\n'''
    a=parse_config(asa,Vendor.ASA); f=parse_config(FORTI,Vendor.FORTIGATE)
    ar=a.security_policies[0]; fr=f.security_policies[0]
    assert (ar.sources,ar.destinations,ar.action)==(fr.sources,fr.destinations,fr.action)==(["any"],["WEB_SERVER"],"allow")
    amap=MigrationMappings(interfaces=[InterfaceMapping(source_interface="Gi0/1",source_nameif="inside",target_interface="ethernet1/2",target_zone="trust",confirmed=True),InterfaceMapping(source_interface="Gi0/0",source_nameif="outside",target_interface="ethernet1/1",target_zone="untrust",confirmed=True)])
    assert not MigrationPlanner().plan(a,amap).generate and not MigrationPlanner().plan(f,mappings()).generate

def test_fortigate_nat_vip_and_manual_review_boundaries():
    cfg=parse_config(FORTI+'''config firewall vip
 edit "WEB-VIP"
  set extip 203.0.113.10
  set mappedip 192.0.2.10
  set extintf "wan1"
  set portforward enable
  set protocol tcp
  set extport 443
  set mappedport 8443
 next
end
''',Vendor.FORTIGATE)
    plan=MigrationPlanner().plan(cfg,mappings()); lines,_=PaloAltoRenderer().render(plan)
    assert not lines
    manual=parse_config('''config firewall policy\n edit 1\n set srcintf "lan"\n set dstintf "wan1"\n set srcaddr "all"\n set dstaddr "all"\n set service "ALL"\n set action accept\n set nat enable\n set ippool enable\n set poolname "POOL"\n next\nend\n''',Vendor.FORTIGATE)
    result=MigrationPlanner().plan(manual,mappings())
    assert next(x for x in result.compatibility if x.entity_type=="nat_policy").status=="MANUAL_REVIEW"

def test_fortigate_api_and_unsupported_pair():
    client=TestClient(app); response=client.post("/api/analyze",data={"source":FORTI,"source_vendor":"fortigate","source_version":"7.4","target_vendor":"paloalto","target_version":"11.1"}); assert response.status_code==200
    project=response.text.split("Project: <code>")[1].split("<")[0]; base=f"/api/projects/{project}/migration"
    compatibility=client.get(base+"/compatibility").json(); assert compatibility["source_vendor"]=="fortigate" and compatibility["target_vendor"]=="paloalto"
    assert client.post("/api/analyze",data={"source":FORTI,"source_vendor":"fortigate","target_vendor":"fortigate"}).status_code==422

def test_fortigate_1000_by_1000_performance():
    addresses='\n'.join(f' edit "A{i}"\n  set subnet 10.{i//65536}.{(i//256)%256}.{i%256} 255.255.255.255\n next' for i in range(1000))
    policies='\n'.join(f' edit {i+1}\n  set srcintf "lan"\n  set dstintf "wan1"\n  set srcaddr "all"\n  set dstaddr "A{i}"\n  set service "ALL"\n  set action accept\n next' for i in range(1000))
    started=time.perf_counter(); cfg=parse_config(FORTI.split('config firewall address')[0]+f'config firewall address\n{addresses}\nend\nconfig firewall policy\n{policies}\nend\n',Vendor.FORTIGATE); plan=MigrationPlanner().plan(cfg,mappings()); PaloAltoRenderer().render(plan); elapsed=time.perf_counter()-started
    assert len(cfg.addresses)==len(cfg.security_policies)==1000 and elapsed<10

def test_migration_layer_does_not_parse_source_syntax():
    text='\n'.join(path.read_text(encoding="utf-8") for path in Path("app/core/migration").rglob("*.py"))
    assert "config firewall policy" not in text and "set srcintf" not in text

def test_fortigate_golden_catalog():
    import json
    root=Path("tests/fixtures/migration/fortigate_to_pan")
    assert len([x for x in root.iterdir() if x.is_dir()])==16
    for case in sorted(x for x in root.iterdir() if x.is_dir()):
        cfg=parse_config((case/"source.conf").read_text(encoding="utf-8"),Vendor.FORTIGATE); plan=MigrationPlanner().plan(cfg,mappings()); renderer=PaloAltoRenderer(); lines,_=renderer.render(plan); review=build_review(cfg,plan,renderer.commands)
        expected=json.loads((case/"expected-semantics.json").read_text(encoding="utf-8"))
        assert len(plan.compatibility)==expected["entities"] and all(x.status not in {"EXACT","SUPPORTED","PARTIAL"} for x in plan.compatibility)
        assert not lines