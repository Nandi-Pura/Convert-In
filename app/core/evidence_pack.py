import hashlib
import json
import os
import shutil
import zipfile
from pathlib import Path

from app import __version__

SCHEMA="convert-in.evidence-pack/v1"
EXPECTED=(
    ("normalized","normalized/normalized-summary.json","normalized.json"),
    ("cp0","analysis/cp0-summary.json","cp0-summary.json"),
    ("cp1","analysis/cp1-summary.json","cp1-summary.json"),
    ("cp2","analysis/cp2-summary.json","cp2-summary.json"),
    ("lint_findings","analysis/lint-findings.json","migration/lint-findings.json"),
    ("semantic_diff","analysis/semantic-diff.json","migration/semantic-diff.json"),
    ("mappings","migration/mappings.json","migration/mappings.json"),
    ("review","migration/review.json","migration/review-decisions.json"),
    ("migration_plan","migration/migration-plan.json","migration/migration-plan.json"),
    ("migration_report","migration/migration-report.json","migration/migration-report.json"),
)

def canonical(value): return json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()

def digest(path:Path):
    result=hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda:stream.read(1024*1024),b""): result.update(chunk)
    return result.hexdigest()

def _inside(path:Path,root:Path):
    path=path.resolve(); root=root.resolve()
    if path!=root and root not in path.parents: raise ValueError("Path containment violation")
    if path.is_symlink(): raise ValueError("Symlinks are not allowed")
    return path

def _json(path:Path):
    try: return json.loads(path.read_text(encoding="utf-8"))
    except (OSError,UnicodeError,json.JSONDecodeError) as exc: raise ValueError(f"Invalid JSON artifact: {path.name}") from exc

def _counts(result,key,names):
    value=result.get(key) or {}
    if isinstance(value,list): value={name:sum(1 for item in value if item.get("severity")==name) for name in names}
    return {name:int(value.get(name,value.get(name.upper(),0)) or 0) for name in names}

def build(project_id:str,workspace:Path):
    base=workspace.resolve(); root=_inside(base/project_id,base)
    if not root.is_dir(): raise FileNotFoundError("Project not found")
    source=_inside(root/"source.cfg",root); context=_json(_inside(root/"evidence-context.json",root))
    result=_json(_inside(root/"workbench-result.json",root))
    final=root/"migration"/"evidence-pack"; temporary=root/"migration"/".evidence-pack.tmp"
    if temporary.exists(): shutil.rmtree(temporary)
    temporary.mkdir(parents=True)
    try:
        source_meta={"filename":context.get("source_filename") or "source.cfg","size_bytes":source.stat().st_size,"sha256":digest(source),"line_count":sum(1 for _ in source.open("rb")),**context["source"]}
        (temporary/"source").mkdir(); (temporary/"source"/"source-metadata.json").write_bytes(canonical(source_meta)+b"\n")
        inventory=[]
        generated={
            "normalized.json":result.get("normalized",{}),"cp0-summary.json":result.get("cp0_summary",{}),
            "cp1-summary.json":result.get("cp1_summary",{}),"cp2-summary.json":result.get("cp2_summary",{}),
        }
        for name,destination,relative in EXPECTED:
            origin=root/relative
            status="PRESENT" if origin.is_file() or relative in generated else "NOT_GENERATED"
            stale=False
            payload=None
            if origin.is_file():
                _inside(origin,root)
                if origin.suffix==".json":
                    payload=_json(origin)
                    artifact_source=payload.get("source",{}) if isinstance(payload,dict) else {}
                    artifact_target=payload.get("target",{}) if isinstance(payload,dict) else {}
                    stale=any(artifact_source.get(k) not in (None,context["source"].get(k)) for k in ("profile_id","exact_version")) or any(artifact_target.get(k) not in (None,context["target"].get(k)) for k in ("profile_id","exact_version"))
                if stale: status="STALE"
                else:
                    target=temporary/destination; target.parent.mkdir(parents=True,exist_ok=True); shutil.copyfile(origin,target)
            elif relative in generated:
                target=temporary/destination; target.parent.mkdir(parents=True,exist_ok=True); target.write_bytes(canonical(generated[relative])+b"\n")
            inventory.append({"name":name,"status":status,**({"path":destination} if status=="PRESENT" else {})})
        candidate_files=sorted((root/"migration").glob("candidate-*")) if (root/"migration").is_dir() else []
        if candidate_files:
            origin=_inside(candidate_files[0],root); target=temporary/"candidate"/origin.name; target.parent.mkdir(); shutil.copyfile(origin,target)
            inventory.append({"name":"candidate","status":"PRESENT","path":target.relative_to(temporary).as_posix(),"sha256":digest(target)})
        else: inventory.append({"name":"candidate","status":"NOT_GENERATED"})
        candidate=inventory[-1]
        semantic=result.get("semantic_diff",{}).get("summary",{})
        summary={"cp0":_counts(result,"cp0_summary",("normalized","recovered","unparsed","unsupported")),"cp1":_counts(result,"cp1_summary",("pass","warning","blocked")),"cp2":_counts(result,"cp2_summary",("exact","supported","partial","manual_review","unsupported","version_not_verified")),"semantic_diff":{k:int(semantic.get(k.upper(),semantic.get(k,0)) or 0) for k in ("preserved","changed","lost","review")},"lint":_counts(result,"lint_findings",("blocking","warning","info")),"candidate_generated":candidate["status"]=="PRESENT","migration_plan_present":any(x["name"]=="migration_plan" and x["status"]=="PRESENT" for x in inventory),"migration_report_present":any(x["name"]=="migration_report" and x["status"]=="PRESENT" for x in inventory)}
        manifest={"schema":SCHEMA,"project_id":project_id,"application":{"name":"Convert-In","version":__version__},"source":{**context["source"],"sha256":source_meta["sha256"]},"target":context["target"],"artifacts":inventory,"summary":summary}
        manifest["fingerprint"]="sha256:"+hashlib.sha256(canonical(manifest)).hexdigest()
        (temporary/"manifest.json").write_bytes(canonical(manifest)+b"\n")
        readme=f"Convert-In Migration Evidence Pack\n\nSource: {context['source']['vendor']} {context['source']['platform']} {context['source']['exact_version']}\nTarget: {context['target']['vendor']} {context['target']['platform']} {context['target']['exact_version']}\n\nRaw source configuration is intentionally excluded. Candidate files, when present, require engineer review. No device deployment occurred. REVIEW, UNSUPPORTED, and VERSION_NOT_VERIFIED preserve unresolved states. Validate with: sha256sum -c checksums.sha256\n"
        (temporary/"docs").mkdir(); (temporary/"docs"/"README.txt").write_text(readme,encoding="utf-8",newline="\n")
        files=sorted((p for p in temporary.rglob("*") if p.is_file()),key=lambda p:p.relative_to(temporary).as_posix())
        checks="".join(f"{digest(p)}  {p.relative_to(temporary).as_posix()}\n" for p in files)
        (temporary/"checksums.sha256").write_text(checks,encoding="ascii",newline="\n")
        if final.exists(): shutil.rmtree(final)
        os.replace(temporary,final)
        archive=root/"migration"/f"convert-in-evidence-pack-{project_id}.zip"; archive_tmp=archive.with_suffix(".tmp")
        with zipfile.ZipFile(archive_tmp,"w",zipfile.ZIP_DEFLATED,compresslevel=9) as bundle:
            for path in sorted((p for p in final.rglob("*") if p.is_file()),key=lambda p:p.relative_to(final).as_posix()):
                info=zipfile.ZipInfo(path.relative_to(final).as_posix(),(1980,1,1,0,0,0)); info.compress_type=zipfile.ZIP_DEFLATED; info.external_attr=0o100644<<16
                bundle.writestr(info,path.read_bytes(),compresslevel=9)
        os.replace(archive_tmp,archive)
        return manifest,archive
    except Exception:
        shutil.rmtree(temporary,ignore_errors=True)
        raise