import hashlib,json,os,shutil,tempfile,zipfile
from pathlib import Path,PurePosixPath
from uuid import uuid4

from app import __version__
from app.core.platforms import platform_profile

SCHEMA="convert-in.project/v1"
EXPORT_SCHEMA="convert-in.project-export/v1"
MAX_ARCHIVE_BYTES=110*1024*1024
MAX_EXPANDED_BYTES=220*1024*1024
MAX_ARCHIVE_FILES=2000
ARTIFACT_PATHS={
    "normalized":"normalized.json","cp0":"cp0-summary.json","cp1":"cp1-summary.json","cp2":"cp2-summary.json",
    "candidate":"migration/candidate-pan-os.set","migration_plan":"migration/migration-plan.json","migration_report":"migration/migration-report.json",
    "lint":"migration/lint-findings.json","semantic_diff":"migration/semantic-diff.json","evidence_pack":"migration/evidence-pack/manifest.json",
}
SOURCE_INVALIDATES=tuple(ARTIFACT_PATHS)
TARGET_INVALIDATES=("cp2","candidate","migration_plan","migration_report","semantic_diff","evidence_pack")
MAPPING_INVALIDATES=("candidate","migration_plan","migration_report","semantic_diff","evidence_pack")
REVIEW_INVALIDATES=("migration_plan","migration_report","semantic_diff","evidence_pack")

def canonical(value): return json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()
def sha_bytes(value:bytes): return "sha256:"+hashlib.sha256(value).hexdigest()
def file_sha(path:Path):
    digest=hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda:stream.read(1024*1024),b""): digest.update(chunk)
    return digest.hexdigest()

def atomic_json(path:Path,value):
    path.parent.mkdir(parents=True,exist_ok=True); fd,name=tempfile.mkstemp(dir=path.parent,prefix=f".{path.name}.")
    try:
        with os.fdopen(fd,"wb") as stream: stream.write(canonical(value)+b"\n"); stream.flush(); os.fsync(stream.fileno())
        os.replace(name,path)
    finally:
        if os.path.exists(name): os.unlink(name)

def _fingerprint(manifest): return sha_bytes(canonical({k:v for k,v in manifest.items() if k!="fingerprint"}))
def _state(manifest):
    return sha_bytes(canonical({"source_sha256":manifest["source"]["sha256"],"source_profile_id":manifest["source"]["profile_id"],"source_exact_version":manifest["source"]["exact_version"],"target_profile_id":manifest["target"]["profile_id"],"target_exact_version":manifest["target"]["exact_version"],"mapping_fingerprint":manifest["state"]["mapping_revision"],"review_fingerprint":manifest["state"]["review_revision"],"schema_versions":manifest["ir"]["schema_versions"]}))

def _revision(path:Path): return sha_bytes(path.read_bytes()) if path.is_file() else sha_bytes(b"{}")
def _artifact(root:Path,name:str,state_revision:str):
    path=root/ARTIFACT_PATHS[name]
    return {"path":ARTIFACT_PATHS[name],"status":"CURRENT" if path.is_file() else "NOT_GENERATED",**({"sha256":file_sha(path),"state_revision":state_revision} if path.is_file() else {})}

def create_manifest(root:Path,project_id:str,context:dict):
    source=root/"source.cfg"; mappings=root/"migration"/"mappings.json"; review=root/"migration"/"review.json"
    source_meta={**context["source"],"filename":context.get("source_filename") or "source.cfg","sha256":file_sha(source),"size_bytes":source.stat().st_size,"line_count":sum(1 for _ in source.open("rb"))}
    manifest={"schema":SCHEMA,"project_id":project_id,"application":{"created_with_version":__version__,"last_opened_with_version":__version__},"source":source_meta,"target":context["target"],"ir":{"schema_versions":{"project":SCHEMA,"normalized":"current","semantic_diff":"convert-in.semantic-diff/v2","evidence_pack":"convert-in.evidence-pack/v1"}},"state":{"mapping_revision":_revision(mappings),"review_revision":_revision(review),"source_revision":sha_bytes(canonical(source_meta)),"target_revision":sha_bytes(canonical(context["target"]))},"artifacts":{}}
    revision=_state(manifest); manifest["state"]["fingerprint"]=revision
    manifest["artifacts"]={name:_artifact(root,name,revision) for name in ARTIFACT_PATHS}; manifest["fingerprint"]=_fingerprint(manifest)
    atomic_json(root/"project.json",manifest); return manifest

def _backup(root:Path,path:Path):
    destination=root/"backup"/"pre-migration-project-v0"; destination.mkdir(parents=True,exist_ok=True)
    if path.is_file() and not (destination/path.name).exists(): shutil.copyfile(path,destination/path.name)
    for name in ("evidence-context.json","versions.json"):
        source=root/name
        if source.is_file() and not (destination/name).exists(): shutil.copyfile(source,destination/name)

def migrate_project_manifest(root:Path,project_id:str):
    path=root/"project.json"
    if not path.is_file():
        context_path=root/"evidence-context.json"
        if not context_path.is_file(): raise FileNotFoundError("Project manifest not found")
        _backup(root,path); return create_manifest(root,project_id,json.loads(context_path.read_text(encoding="utf-8")))
    data=json.loads(path.read_text(encoding="utf-8")); schema=data.get("schema")
    if schema==SCHEMA: return data
    if schema and schema!="convert-in.project/v0": raise ValueError("PROJECT_SCHEMA_NEWER_THAN_APPLICATION")
    _backup(root,path)
    context={"source_filename":data.get("source",{}).get("filename","source.cfg"),"source":data["source"],"target":data["target"]}
    return create_manifest(root,project_id,context)

def load_manifest(workspace:Path,project_id:str,refresh=True):
    root=(workspace/project_id).resolve(); base=workspace.resolve()
    if root!=base and base not in root.parents: raise ValueError("Path containment violation")
    manifest=migrate_project_manifest(root,project_id)
    if manifest.get("project_id")!=project_id: raise ValueError("Project identity mismatch")
    if refresh:
        manifest["application"]["last_opened_with_version"]=__version__
        manifest["state"]["mapping_revision"]=_revision(root/"migration"/"mappings.json"); manifest["state"]["review_revision"]=_revision(root/"migration"/"review.json")
        current=_state(manifest); manifest["state"]["fingerprint"]=current
        for name,item in manifest["artifacts"].items():
            path=root/item["path"]
            if not path.is_file(): item["status"]="NOT_GENERATED"; item.pop("sha256",None); item.pop("state_revision",None)
            elif item["status"]=="NOT_GENERATED": item.update(status="CURRENT",sha256=file_sha(path),state_revision=current)
            elif item.get("state_revision") not in {None,current}: item["status"]="STALE"
            elif item.get("sha256") and item["sha256"]!=file_sha(path): item["status"]="INVALID"
        manifest["fingerprint"]=_fingerprint(manifest); atomic_json(root/"project.json",manifest)
    manifest["profile_status"]={"source":"AVAILABLE" if platform_profile(manifest["source"]["profile_id"],manifest["source"]["exact_version"]) else "PROFILE_NOT_AVAILABLE","target":"AVAILABLE" if platform_profile(manifest["target"]["profile_id"],manifest["target"]["exact_version"]) else "PROFILE_NOT_AVAILABLE"}
    return manifest

def invalidate(workspace:Path,project_id:str,reason:str):
    if not (workspace/project_id/"project.json").is_file() and not (workspace/project_id/"evidence-context.json").is_file(): return None
    manifest=load_manifest(workspace,project_id); names={"source":SOURCE_INVALIDATES,"target":TARGET_INVALIDATES,"mapping":MAPPING_INVALIDATES,"review":REVIEW_INVALIDATES}[reason]
    for name in names:
        if manifest["artifacts"][name]["status"]!="NOT_GENERATED": manifest["artifacts"][name]["status"]="STALE"
    manifest["fingerprint"]=_fingerprint(manifest); atomic_json(workspace/project_id/"project.json",manifest); return manifest

def validate_project_state(workspace:Path,project_id:str):
    manifest=load_manifest(workspace,project_id); root=workspace/project_id; checks=[]
    def check(name,ok,level="FAIL"): checks.append({"check":name,"status":"PASS" if ok else level})
    check("source_sha",(root/"source.cfg").is_file() and file_sha(root/"source.cfg")==manifest["source"]["sha256"])
    check("source_profile",manifest["profile_status"]["source"]=="AVAILABLE","WARNING"); check("target_profile",manifest["profile_status"]["target"]=="AVAILABLE","WARNING")
    for name,item in manifest["artifacts"].items(): check(name,item["status"] not in {"INVALID","STALE"},"WARNING")
    status="FAIL" if any(x["status"]=="FAIL" for x in checks) else "WARNING" if any(x["status"]=="WARNING" for x in checks) else "PASS"
    return {"status":status,"project_id":project_id,"checks":checks,"manifest_fingerprint":manifest["fingerprint"]}

def export_project(workspace:Path,project_id:str):
    root=workspace/project_id; manifest=load_manifest(workspace,project_id); destination=root/f"{project_id}.convertin.zip"; temporary=destination.with_suffix(".tmp")
    files=[p for p in root.rglob("*") if p.is_file() and "backup" not in p.parts and p not in {destination,temporary}]
    with zipfile.ZipFile(temporary,"w",zipfile.ZIP_DEFLATED,compresslevel=9) as archive:
        archive.writestr(zipfile.ZipInfo("export.json",(1980,1,1,0,0,0)),canonical({"schema":EXPORT_SCHEMA,"project_id":project_id,"project_fingerprint":manifest["fingerprint"],"sensitive_source_included":True})+b"\n")
        for path in sorted(files,key=lambda p:p.relative_to(root).as_posix()):
            info=zipfile.ZipInfo(path.relative_to(root).as_posix(),(1980,1,1,0,0,0)); info.compress_type=zipfile.ZIP_DEFLATED; info.external_attr=0o100644<<16; archive.writestr(info,path.read_bytes())
    os.replace(temporary,destination); return destination

def import_project(workspace:Path,archive_path:Path):
    if archive_path.stat().st_size>MAX_ARCHIVE_BYTES: raise ValueError("Project archive exceeds compressed size limit")
    with zipfile.ZipFile(archive_path) as archive:
        infos=archive.infolist()
        if len(infos)>MAX_ARCHIVE_FILES or sum(x.file_size for x in infos)>MAX_EXPANDED_BYTES: raise ValueError("Project archive exceeds extraction limits")
        for info in infos:
            path=PurePosixPath(info.filename)
            if path.is_absolute() or ".." in path.parts or ":" in path.parts[0] or (info.external_attr>>16)&0o170000==0o120000: raise ValueError("Unsafe project archive path")
        export=json.loads(archive.read("export.json")); manifest=json.loads(archive.read("project.json"))
        if export.get("schema")!=EXPORT_SCHEMA or manifest.get("schema")!=SCHEMA: raise ValueError("Unsupported project export schema")
        origin=manifest["project_id"]; project_id=origin if not (workspace/origin).exists() else str(uuid4()); root=workspace/project_id; root.mkdir(parents=True)
        try:
            for info in infos:
                if info.is_dir() or info.filename=="export.json": continue
                target=root/PurePosixPath(info.filename); target.parent.mkdir(parents=True,exist_ok=True); target.write_bytes(archive.read(info))
            manifest["project_id"]=project_id
            if project_id!=origin: manifest["origin_project_id"]=origin
            if file_sha(root/"source.cfg")!=manifest["source"]["sha256"]: raise ValueError("Source SHA-256 mismatch")
            manifest["fingerprint"]=_fingerprint(manifest); atomic_json(root/"project.json",manifest)
            return load_manifest(workspace,project_id)
        except Exception:
            shutil.rmtree(root,ignore_errors=True); raise