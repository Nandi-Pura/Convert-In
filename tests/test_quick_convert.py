from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.config import settings
from app.core.migration.quick_convert import convert, detect_source, safe_filename
from app.core.models import Vendor
from app.main import app

client=TestClient(app)
EXAMPLES={"fortigate":(Path("examples/fortigate/basic.conf"),"7.4"),"cisco_asa":(Path("examples/asa/basic.cfg"),"9.20")}

@pytest.mark.parametrize("vendor",EXAMPLES)
def test_vendor_quick_convert_is_accounted_and_reviewable(vendor):
    path,version=EXAMPLES[vendor]; result=convert(path.read_text(),vendor,version)
    candidate="\n".join(result.lines)
    assert candidate.startswith("# Convert-In\n# CANDIDATE CONFIGURATION — ENGINEER REVIEW REQUIRED")
    assert result.summary["total"]==sum(result.summary[x] for x in ("generated","manual_review","unsupported","version_not_verified"))
    assert result.extraction_coverage.semantic_total==result.extraction_coverage.normalized+result.extraction_coverage.recovered+result.extraction_coverage.unparsed+result.extraction_coverage.unsupported
    assert "# Source Extraction Coverage" in candidate and "# Semantic Constructs:" in candidate
    assert "# Addresses:" in candidate and "# [" in candidate
    assert not any(line.startswith("set rulebase nat") for line in result.lines)

def test_detection_and_explicit_selection():
    fg="#config-version=FGT60F-7.4.12-FW-build1234-240101:opmode=0:vdom=0\n"+Path("examples/fortigate/basic.conf").read_text()
    asa="ASA Version 9.20(2)\n"+Path("examples/asa/basic.cfg").read_text()
    assert detect_source(fg)[0].vendor==Vendor.FORTIGATE and detect_source(fg)[1]=="7.4"
    assert detect_source(asa)[0].vendor==Vendor.ASA and detect_source(asa)[1]=="9.20"
    assert convert(asa,"cisco_asa","9.20").source_version=="9.20"

@pytest.mark.parametrize("kwargs,message",[
    ({"source_vendor":"cisco_asa","source_version":"9.99"},"Unsupported source version"),
    ({"source_vendor":"cisco_asa","source_version":"9.20","target_version":"12.1"},"only PAN-OS 11.1"),
    ({"source_vendor":"cisco_asa","source_version":"9.20","management_mode":"PANORAMA"},"only LOCAL_FIREWALL"),
])
def test_version_and_context_gates(kwargs,message):
    with pytest.raises(ValueError,match=message): convert("object network A\n host 10.0.0.1",**kwargs)

def test_missing_documentation_emits_no_command(monkeypatch):
    from app.core.versions import PROFILES
    monkeypatch.setattr(PROFILES["panos-11.1"].capabilities["address"],"documentation_refs",[])
    text="ASA Version 9.20\nobject network A\n host 10.0.0.1"
    result=convert(text,"cisco_asa","9.20")
    assert not [x for x in result.lines if x.startswith("set ")]
    assert "[VERSION_NOT_VERIFIED]" in "\n".join(result.lines)

def test_malformed_empty_result_is_actionable():
    with pytest.raises(ValueError,match="No supported firewall constructs"): convert("not a firewall configuration","cisco_asa","9.20")

def test_api_file_contract_and_download_isolation(tmp_path,monkeypatch):
    monkeypatch.setattr(settings,"workspace_dir",tmp_path)
    text=Path("examples/fortigate/basic.conf").read_text()
    response=client.post("/api/convert",data={"config":text,"source_vendor":"fortigate","source_version":"7.4","target_vendor":"paloalto","target_version":"11.1","management_mode":"LOCAL_FIREWALL","source_filename":"../../unsafe config.cfg"})
    assert response.status_code==200; data=response.json()
    assert data["extraction_coverage"]["semantic_total"] and data["extraction_coverage"]["coverage_percent"] is not None
    assert data["candidate_filename"]=="unsafe-config-to-panos-11.1.set"
    download=client.get(data["download_url"])
    assert download.status_code==200 and "source.cfg" not in download.text
    assert len(list((tmp_path/data["project_id"]/"quick-convert").iterdir()))==1

def test_paste_size_limit(tmp_path,monkeypatch):
    monkeypatch.setattr(settings,"workspace_dir",tmp_path); monkeypatch.setattr(settings,"max_input_bytes",8)
    assert client.post("/api/convert",data={"config":"ASA Version 9.20"}).status_code==413

def test_safe_filename():
    assert safe_filename("../a b.cfg")=="a-b-to-panos-11.1.set"