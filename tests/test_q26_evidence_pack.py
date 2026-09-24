import hashlib
import json
import zipfile
from pathlib import Path, PurePosixPath

import pytest
from fastapi.testclient import TestClient

from app.core.evidence_pack import build, canonical
from app.main import app

CONTEXT={"source_filename":"input.cfg","source":{"domain":"FIREWALL","vendor":"CISCO","platform":"ASA","exact_version":"9.20","profile_id":"firewall-cisco-asa"},"target":{"domain":"FIREWALL","vendor":"PALO_ALTO","platform":"PAN_OS","exact_version":"11.1","profile_id":"firewall-paloalto-panos"}}
RESULT={"cp0_summary":{"normalized":1,"recovered":0,"unparsed":0,"unsupported":0},"cp1_summary":{"blocking_findings":0},"cp2_summary":{"SUPPORTED":1},"lint_findings":[],"semantic_diff":{"summary":{"PRESERVED":1}},"normalized":{"entities":1}}

def project(tmp_path,domain="FIREWALL",candidate=False):
    root=tmp_path/"p"; root.mkdir(); context=json.loads(json.dumps(CONTEXT)); context["source"]["domain"]=context["target"]["domain"]=domain
    (root/"source.cfg").write_text("secret\n",encoding="utf-8"); (root/"evidence-context.json").write_text(json.dumps(context)); (root/"workbench-result.json").write_text(json.dumps(RESULT))
    if candidate: (root/"migration").mkdir(); (root/"migration"/"candidate-test.set").write_text("# CANDIDATE CONFIGURATION — ENGINEER REVIEW REQUIRED\n")
    return root

def test_deterministic_private_analysis_only_pack(tmp_path):
    root=project(tmp_path); first,_=build("p",tmp_path); before={p.relative_to(root).as_posix():p.read_bytes() for p in root.rglob("*") if p.is_file() and "evidence-pack" not in p.parts and p.suffix!=".zip"}; files1={p.relative_to(root/"migration"/"evidence-pack").as_posix():p.read_bytes() for p in (root/"migration"/"evidence-pack").rglob("*") if p.is_file()}
    second,_=build("p",tmp_path); files2={p.relative_to(root/"migration"/"evidence-pack").as_posix():p.read_bytes() for p in (root/"migration"/"evidence-pack").rglob("*") if p.is_file()}
    unsigned={k:v for k,v in first.items() if k!="fingerprint"}; assert first==second and files1==files2 and first["fingerprint"]=="sha256:"+hashlib.sha256(canonical(unsigned)).hexdigest()
    assert not (root/"migration"/"evidence-pack"/"source.cfg").exists() and json.loads((root/"migration"/"evidence-pack"/"source"/"source-metadata.json").read_text())["sha256"]==hashlib.sha256((root/"source.cfg").read_bytes()).hexdigest()
    assert next(x for x in first["artifacts"] if x["name"]=="candidate")["status"]=="NOT_GENERATED" and before=={p.relative_to(root).as_posix():p.read_bytes() for p in root.rglob("*") if p.is_file() and "evidence-pack" not in p.parts and p.suffix!=".zip"}
    lines=(root/"migration"/"evidence-pack"/"checksums.sha256").read_text().splitlines(); assert lines==sorted(lines,key=lambda x:x.split("  ",1)[1])

@pytest.mark.parametrize("domain",["FIREWALL","SWITCH","ROUTER"])
def test_domains_and_candidate(tmp_path,domain):
    root=project(tmp_path,domain,candidate=True); manifest,archive=build("p",tmp_path); candidate=next(x for x in manifest["artifacts"] if x["name"]=="candidate")
    assert candidate["status"]=="PRESENT" and candidate["sha256"]
    with zipfile.ZipFile(archive) as bundle: assert all(not PurePosixPath(name).is_absolute() and ".." not in PurePosixPath(name).parts for name in bundle.namelist())

def test_stale_and_malformed_artifacts(tmp_path):
    root=project(tmp_path); migration=root/"migration"; migration.mkdir(); (migration/"semantic-diff.json").write_text(json.dumps({"source":{"profile_id":"wrong"}})); manifest,_=build("p",tmp_path)
    assert next(x for x in manifest["artifacts"] if x["name"]=="semantic_diff")["status"]=="STALE"
    (migration/"migration-plan.json").write_text("{")
    with pytest.raises(ValueError,match="Invalid JSON"): build("p",tmp_path)

def test_containment(tmp_path):
    project(tmp_path)
    with pytest.raises(ValueError,match="containment"): build("../p",tmp_path)

def test_api_post_get_download_and_safe_filename(tmp_path,monkeypatch):
    from app.config import settings
    monkeypatch.setattr(settings,"workspace_dir",tmp_path); project(tmp_path); client=TestClient(app); base="/api/projects/p/migration"
    assert client.post(base+"/evidence-pack").status_code==200 and client.get(base+"/evidence-pack").status_code==200
    response=client.get(base+"/download/evidence-pack"); assert response.status_code==200 and response.headers["content-disposition"]=='attachment; filename="convert-in-evidence-pack-p.zip"'