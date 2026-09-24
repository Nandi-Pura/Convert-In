from pathlib import Path
from app.core.models import SwitchConfig
from app.core.parsing.registry import parse_profile
from app.core.platforms import platform_profile
from app.core.switch_assurance import SwitchCompatibilityEvaluator,SwitchReferenceIntegrityValidator
from app.core.renderers.registry import lookup_renderer

TEXT=Path("tests/fixtures/iosxe/basic-switch.cfg").read_text()

def test_switch_parser_cp0_cp1_and_unsupported_visibility():
    cfg=parse_profile(TEXT,"switch-cisco-iosxe","17.12.1")
    assert isinstance(cfg,SwitchConfig) and [x.vlan_id for x in cfg.vlans]==[10,20,99]
    assert cfg.ports[0].access_vlan==10 and cfg.ports[1].native_vlan==99 and cfg.ports[1].allowed_vlans==[10,20,99]
    assert cfg.ports[1].lag=="Port-channel1" and cfg.lags[0].members==["GigabitEthernet1/0/2"] and cfg.svis[0].addresses==["192.0.2.1/24"]
    assert cfg.extraction_coverage.semantic_total==cfg.extraction_coverage.normalized+cfg.extraction_coverage.recovered+cfg.extraction_coverage.unparsed+cfg.extraction_coverage.unsupported
    assert cfg.extraction_coverage.unsupported==1 and SwitchReferenceIntegrityValidator().validate(cfg).blocking_findings==0

def test_switch_cp1_and_renderer_gates():
    cfg=parse_profile(TEXT.replace("switchport access vlan 10","switchport access vlan 777"),"switch-cisco-iosxe","17.12.1")
    assert SwitchReferenceIntegrityValidator().validate(cfg).blocking_findings==1
    cfg=parse_profile(TEXT,"switch-cisco-iosxe","17.12.1");profile=platform_profile("switch-cisco-iosxe","17.12.1");cp1=SwitchReferenceIntegrityValidator().validate(cfg)
    cp2=SwitchCompatibilityEvaluator().evaluate(cfg,profile,profile,{},cp1);renderer=lookup_renderer("SWITCH","CISCO","IOS_XE","17.12.1")();candidate=renderer.render(cp2)
    assert " switchport access vlan 10" in candidate and " channel-group 1 mode active" in candidate and "interface Vlan10" in candidate
    assert all(x.status in {"EXACT","SUPPORTED"} for x in cp2)

def test_switch_workbench_is_domain_scoped():
    from fastapi.testclient import TestClient
    from app.main import app
    response=TestClient(app).post("/api/workbench/run",json={"source_text":TEXT,"source_vendor":"cisco_iosxe","source_profile":"switch-cisco-iosxe","source_version":"17.12.1","target_profile":"switch-cisco-iosxe","target_version":"17.12.1"})
    body=response.json();assert response.status_code==200 and body["mode"]=="CONVERT" and body["source_profile"]["domain"]=="SWITCH"
    assert {x["entity_type"] for x in body["entities"]}=={"VLAN","Interface","LAG","SVI"} and all(x["copyable"] for x in body["entities"])