import json,zipfile
from pathlib import Path
import pytest
from app.core.project_state import *

CONTEXT={"source_filename":"input.cfg","source":{"domain":"FIREWALL","vendor":"CISCO","platform":"ASA","release_line":"9.20","exact_version":"9.20","profile_id":"firewall-cisco-asa"},"target":{"domain":"FIREWALL","vendor":"PALO_ALTO","platform":"PAN_OS","release_line":"11.1","exact_version":"11.1","profile_id":"firewall-paloalto-panos","target_capability":"BOUNDED_RENDERER"}}
def fixture(tmp_path,name="p"):
    root=tmp_path/name; (root/"migration").mkdir(parents=True); (root/"source.cfg").write_text("object network A\n host 1.1.1.1\n"); (root/"normalized.json").write_text("{}")
    return root,create_manifest(root,name,CONTEXT)

def test_manifest_identity_exact_versions_and_determinism(tmp_path):
    root,first=fixture(tmp_path); second=create_manifest(root,"p",CONTEXT)
    assert first["schema"]==SCHEMA and first["project_id"]=="p" and first["source"]["exact_version"]=="9.20" and first["target"]["exact_version"]=="11.1"
    assert first["fingerprint"]==second["fingerprint"] and first["source"]["sha256"]==file_sha(root/"source.cfg")

@pytest.mark.parametrize(("reason","stale","current"),[("target",("cp2","candidate","semantic_diff","evidence_pack"),("cp0","cp1")),("mapping",("candidate","migration_report","semantic_diff"),("normalized","cp0")),("review",("migration_report","evidence_pack"),("normalized","candidate"))])
def test_invalidation_matrix(tmp_path,reason,stale,current):
    root,_=fixture(tmp_path)
    for path in ARTIFACT_PATHS.values(): p=root/path; p.parent.mkdir(parents=True,exist_ok=True); p.write_text("{}")
    load_manifest(tmp_path,"p"); result=invalidate(tmp_path,"p",reason)
    assert all(result["artifacts"][x]["status"]=="STALE" for x in stale) and all(result["artifacts"][x]["status"]=="CURRENT" for x in current)

def test_source_change_validation_and_missing_profile(tmp_path):
    root,manifest=fixture(tmp_path); root.joinpath("source.cfg").write_text("changed")
    assert validate_project_state(tmp_path,"p")["status"]=="FAIL"
    manifest["target"]["profile_id"]="removed"; atomic_json(root/"project.json",manifest)
    assert load_manifest(tmp_path,"p")["profile_status"]["target"]=="PROFILE_NOT_AVAILABLE"

def test_legacy_migration_backup_and_future_rejection(tmp_path):
    root,_=fixture(tmp_path); (root/"project.json").unlink(); (root/"evidence-context.json").write_text(json.dumps(CONTEXT)); migrate_project_manifest(root,"p")
    assert (root/"backup"/"pre-migration-project-v0"/"evidence-context.json").is_file()
    atomic_json(root/"project.json",{"schema":"convert-in.project/v99"})
    with pytest.raises(ValueError,match="PROJECT_SCHEMA_NEWER"): load_manifest(tmp_path,"p")

def test_export_import_source_collision_and_sha(tmp_path):
    root,_=fixture(tmp_path); archive=export_project(tmp_path,"p")
    with zipfile.ZipFile(archive) as bundle: assert "source.cfg" in bundle.namelist()
    imported=import_project(tmp_path,archive); assert imported["project_id"]!="p" and imported["origin_project_id"]=="p"
    bad=tmp_path/"bad.zip"
    with zipfile.ZipFile(bad,"w") as bundle: bundle.writestr("../escape","x"); bundle.writestr("export.json","{}")
    with pytest.raises(ValueError,match="Unsafe"): import_project(tmp_path,bad)

def test_atomic_write_and_archive_limits(tmp_path,monkeypatch):
    path=tmp_path/"x.json"; atomic_json(path,{"b":1}); assert path.read_bytes()==b'{"b":1}\n'
    _,_=fixture(tmp_path,"p"); archive=export_project(tmp_path,"p"); monkeypatch.setattr("app.core.project_state.MAX_ARCHIVE_FILES",1)
    with pytest.raises(ValueError,match="limits"): import_project(tmp_path,archive)