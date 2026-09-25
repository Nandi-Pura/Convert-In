import json,zipfile
from concurrent.futures import ThreadPoolExecutor
from collections import Counter
from html import escape
from pathlib import Path
from uuid import NAMESPACE_URL, uuid4, uuid5
from fastapi import APIRouter, File, Form, HTTPException, Query, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, Response
from pydantic import BaseModel, Field
from app.config import settings
from app.core.models import FirewallConfig, Severity, Vendor
from app.core.analysis import AnalysisEngine
from app.core.graph import GraphScope, GraphSummary, serialize_graph, resolve_node
from app.core.parsing import detect_vendor, parse_config
from app.persistence.repositories import create_project
from app.persistence.repositories.projects import get_project
from app.core.migration import MigrationMappings, MigrationPlanner, build_plan_artifact, build_report, default_mappings, migration_pair, serialize_plan_artifact
from app.core.renderers import PaloAltoRenderer
from app.core.migration.validation import validate_candidate
from app.core.review import ReviewDecision,build_review,export_package,load_decisions,update_decision,validate_migration
from app.core.versions import resolve_context
from app.core.versions.models import VersionContext
from app.core.pan_lab import PanLabValidationResult
from app.core.reference_integrity import ReferenceIntegrityValidator
from app.core.domain_detection import detect_domain
from app.core.migration.quick_convert import convert as quick_convert, detect_source, profiles as quick_profiles, safe_filename
from app.core.workbench import build as build_workbench
from app.core.platforms import profiles_payload, platform_profile
from app.core.linting import build_lint_artifact, lint_config, serialize_lint_artifact
from app.core.semantic_diff import atomic_write, build_semantic_diff, serialize_semantic_diff
from app.core.evidence_pack import build as build_evidence_pack
from app.core.project_state import create_manifest,export_project,import_project,invalidate,load_manifest,validate_project_state
from app.core import operations

router = APIRouter(prefix="/api")
executor=ThreadPoolExecutor(max_workers=2,thread_name_prefix="convert")

class WorkbenchSource(BaseModel):
    source_text:str
    source_vendor:str="auto"
    source_version:str=""
    target_vendor:str="paloalto"
    target_version:str="11.1"
    source_profile:str|None=None
    target_profile:str|None=None
    mappings:dict=Field(default_factory=dict)

def ingest_source_text(source_text:str):
    if len(source_text.encode("utf-8"))>settings.max_input_bytes: raise HTTPException(413,"Configuration exceeds the 100 MiB limit.")
    return source_text

@router.post("/workbench/run")
def run_workbench(source:WorkbenchSource):
    config=ingest_source_text(source.source_text); source_vendor=source.source_vendor; source_version=source.source_version; target_version=source.target_version
    detected=detect_vendor(config)
    try: vendor=detected.vendor if source_vendor=="auto" else Vendor(source_vendor)
    except ValueError as exc: raise HTTPException(422,"Unsupported source platform.") from exc
    if vendor==Vendor.UNKNOWN: raise HTTPException(422,"Could not detect source platform.")
    context=resolve_context(config,vendor,source_version or None)
    selected=source_version or context.detected_family
    if not selected: raise HTTPException(422,"Source version was not verified. Select it explicitly.")
    target_profile=source.target_profile or ("router-huawei-vrp" if vendor==Vendor.CISCO_IOSXE else "firewall-paloalto-panos")
    target_version=source.target_version if source.target_profile else ("" if vendor==Vendor.CISCO_IOSXE else source.target_version)
    try:
        result=build_workbench(config,vendor,selected,target_version,source.source_profile,target_profile,source.mappings)
        project=str(uuid5(NAMESPACE_URL,json.dumps({"source":config,"source_profile":result["source_profile"],"target_profile":result["target_profile"]},sort_keys=True,default=str))); root=(settings.workspace_dir/project).resolve(); base=settings.workspace_dir.resolve()
        if base not in root.parents: raise HTTPException(400,"Invalid workspace path")
        root.mkdir(parents=True,exist_ok=True); (root/"source.cfg").write_text(config,encoding="utf-8")
        source_profile=platform_profile(result["source_profile"]["id"]); target=platform_profile(result["target_profile"]["id"])
        context={"source_filename":"source.cfg","source":{"domain":source_profile.domain.value,"vendor":source_profile.vendor.value,"platform":source_profile.platform.value,"exact_version":result["source_profile"]["version"],"profile_id":source_profile.id},"target":{"domain":target.domain.value,"vendor":target.vendor.value,"platform":target.platform.value,"exact_version":result["target_profile"]["version"],"profile_id":target.id}}
        (root/"evidence-context.json").write_text(json.dumps(context,sort_keys=True),encoding="utf-8"); (root/"workbench-result.json").write_text(json.dumps(result,sort_keys=True,default=str),encoding="utf-8")
        if result.get("candidate"):
            migration=root/"migration"; migration.mkdir(exist_ok=True); (migration/result["candidate_filename"]).write_text(result["candidate"],encoding="utf-8")
        create_manifest(root,project,context)
        result["project_id"]=project; return result
    except ValueError as exc: raise HTTPException(422,str(exc)) from exc

def _operation_worker(operation_id:str,source:WorkbenchSource):
    try:
        operations.update(operation_id,"VALIDATING_SOURCE","COMPLETE")
        result=run_workbench_instrumented(source,lambda stage,status="ACTIVE",counts=None:operations.update(operation_id,stage,status,counts))
        operations.finish(operation_id,result)
    except Exception as exc:
        stage=(operations.get(operation_id) or {}).get("stage","VALIDATING_SOURCE"); operations.fail(operation_id,stage,exc)

def run_workbench_instrumented(source:WorkbenchSource,progress):
    config=ingest_source_text(source.source_text); detected=detect_vendor(config)
    try: vendor=detected.vendor if source.source_vendor=="auto" else Vendor(source.source_vendor)
    except ValueError as exc: raise ValueError("Unsupported source platform.") from exc
    if vendor==Vendor.UNKNOWN:raise ValueError("Could not detect source platform.")
    selected=source.source_version or resolve_context(config,vendor,None).detected_family
    if not selected:raise ValueError("Source version was not verified. Select it explicitly.")
    target_profile=source.target_profile or ("router-huawei-vrp" if vendor==Vendor.CISCO_IOSXE else "firewall-paloalto-panos"); target_version=source.target_version if source.target_profile else ("" if vendor==Vendor.CISCO_IOSXE else source.target_version)
    result=build_workbench(config,vendor,selected,target_version,source.source_profile,target_profile,source.mappings,progress)
    result["source_text"]=config
    result["line_accounting"]=_line_accounting(config,result["entities"])
    for stage,counts in (("CP1",{"findings":result["cp1_summary"].get("blocking_findings",0)}),("CP2",result.get("cp2_summary") or {}),("RENDERING",{"commands":sum(len(x["commands"]) for x in result["entities"])}),("SEMANTIC_DIFF",{}),("FINDINGS",{"findings":len(result["lint_findings"])})):
        if stage=="RENDERING" and not result["renderer_available"]:continue
        progress(stage); progress(stage,"COMPLETE",counts)
    project=str(uuid5(NAMESPACE_URL,json.dumps({"source":config,"source_profile":result["source_profile"],"target_profile":result["target_profile"]},sort_keys=True,default=str))); root=(settings.workspace_dir/project).resolve(); root.mkdir(parents=True,exist_ok=True); (root/"source.cfg").write_text(config,encoding="utf-8")
    source_profile=platform_profile(result["source_profile"]["id"]); target=platform_profile(result["target_profile"]["id"]); context={"source_filename":"source.cfg","source":{"domain":source_profile.domain.value,"vendor":source_profile.vendor.value,"platform":source_profile.platform.value,"exact_version":result["source_profile"]["version"],"profile_id":source_profile.id},"target":{"domain":target.domain.value,"vendor":target.vendor.value,"platform":target.platform.value,"exact_version":result["target_profile"]["version"],"profile_id":target.id}}
    (root/"evidence-context.json").write_text(json.dumps(context,sort_keys=True),encoding="utf-8"); (root/"workbench-result.json").write_text(json.dumps(result,sort_keys=True,default=str),encoding="utf-8")
    if result.get("candidate"): migration=root/"migration"; migration.mkdir(exist_ok=True); (migration/result["candidate_filename"]).write_text(result["candidate"],encoding="utf-8")
    create_manifest(root,project,context); result["project_id"]=project; return result

def _line_accounting(source_text:str,entities:list[dict]):
    total=len(source_text.splitlines()); ranked={"UNCHANGED_OR_OTHER":0,"CONVERTED":1,"REVIEW_REQUIRED":2,"NOT_SUPPORTED":3}; lines={}
    for entity in entities:
        status="CONVERTED" if entity["user_status"]=="READY" else "NOT_SUPPORTED" if entity["user_status"]=="BLOCKED" else "REVIEW_REQUIRED"
        for line in entity.get("source_lines",[]):
            if 1<=line<=total and ranked[status]>ranked.get(lines.get(line,"UNCHANGED_OR_OTHER"),0): lines[line]=status
    counts=Counter(lines.values()); counts["UNCHANGED_OR_OTHER"]=total-len(lines)
    return {"total_analyzed_lines":total,"converted_lines":counts["CONVERTED"],"review_lines":counts["REVIEW_REQUIRED"],"unsupported_lines":counts["NOT_SUPPORTED"],"unchanged_lines":counts["UNCHANGED_OR_OTHER"],"method":"UNIQUE_PROVENANCE_ANCHORS_V1"}

@router.post("/workbench/operations",status_code=202)
def start_workbench_operation(source:WorkbenchSource):
    target=platform_profile(source.target_profile,source.target_version); render=bool(target and target.target_renderer)
    project=str(uuid5(NAMESPACE_URL,json.dumps({"source":source.source_text,"source_profile":source.source_profile,"target_profile":source.target_profile},sort_keys=True)))
    operation_id=operations.create(project,"CONVERT" if render else "ANALYZE",render,{"domain":target.domain.value if target else None,"source_profile":source.source_profile,"target_profile":source.target_profile})
    executor.submit(_operation_worker,operation_id,source); return {"operation_id":operation_id,"status":"RUNNING"}

@router.get("/operations/{operation_id}")
def operation_status(operation_id:str):
    state=operations.get(operation_id)
    if not state:raise HTTPException(404,"Operation not found")
    return state

@router.post("/projects/{project_id}/migration/evidence-pack")
def create_evidence_pack(project_id:str):
    try:
        result=build_evidence_pack(project_id,settings.workspace_dir)[0]; load_manifest(settings.workspace_dir,project_id); return result
    except FileNotFoundError as exc: raise HTTPException(404,str(exc)) from exc
    except (ValueError,OSError) as exc: raise HTTPException(409,str(exc)) from exc

@router.get("/projects/{project_id}/migration/evidence-pack")
def get_evidence_pack(project_id:str):
    path=settings.workspace_dir/project_id/"migration"/"evidence-pack"/"manifest.json"
    if not path.is_file(): raise HTTPException(404,"Evidence pack has not been generated")
    try: return json.loads(path.read_text(encoding="utf-8"))
    except (OSError,json.JSONDecodeError) as exc: raise HTTPException(409,"Evidence pack manifest is invalid") from exc

@router.get("/projects/{project_id}/migration/download/evidence-pack")
def download_evidence_pack(project_id:str):
    _,archive=build_evidence_pack(project_id,settings.workspace_dir) if not (settings.workspace_dir/project_id/"migration"/f"configmorph-evidence-pack-{project_id}.zip").is_file() else (None,settings.workspace_dir/project_id/"migration"/f"configmorph-evidence-pack-{project_id}.zip")
    return FileResponse(archive,media_type="application/zip",filename=f"configmorph-evidence-pack-{project_id}.zip")

@router.get("/projects/{project_id}")
def project_state(project_id:str):
    try:
        manifest=load_manifest(settings.workspace_dir,project_id); root=settings.workspace_dir/project_id
        return {"manifest":manifest,"source_text":(root/"source.cfg").read_text(encoding="utf-8"),"result":json.loads((root/"workbench-result.json").read_text(encoding="utf-8"))}
    except FileNotFoundError as exc: raise HTTPException(404,str(exc)) from exc
    except ValueError as exc: raise HTTPException(409,str(exc)) from exc

@router.post("/projects/{project_id}/validate")
def validate_project(project_id:str):
    try: return validate_project_state(settings.workspace_dir,project_id)
    except FileNotFoundError as exc: raise HTTPException(404,str(exc)) from exc
    except ValueError as exc: raise HTTPException(409,str(exc)) from exc

@router.get("/projects/{project_id}/export")
def project_export(project_id:str):
    try: path=export_project(settings.workspace_dir,project_id)
    except FileNotFoundError as exc: raise HTTPException(404,str(exc)) from exc
    return FileResponse(path,media_type="application/zip",filename=path.name,headers={"X-ConfigMorph-Sensitive":"source-configuration-included"})

@router.post("/projects/import")
async def project_import(project:UploadFile=File(...)):
    temporary=settings.workspace_dir/f".import-{uuid4()}.zip"; size=0
    try:
        with temporary.open("wb") as output:
            while chunk:=await project.read(1024*1024):
                size+=len(chunk)
                if size>settings.max_request_bytes: raise HTTPException(413,"Project archive exceeds request limit")
                output.write(chunk)
        return import_project(settings.workspace_dir,temporary)
    except (ValueError,zipfile.BadZipFile) as exc: raise HTTPException(422,str(exc)) from exc
    finally: temporary.unlink(missing_ok=True)

@router.get("/convert/profiles")
def quick_convert_profiles(): return {"profiles":quick_profiles()}

@router.get("/workbench/profiles")
def workbench_profiles(): return {"profiles":profiles_payload()}

@router.post("/convert")
def convert_configuration(config:str=Form(...),source_vendor:str=Form("auto"),source_version:str=Form(""),target_vendor:str=Form("paloalto"),target_version:str=Form("11.1"),management_mode:str=Form("LOCAL_FIREWALL"),source_filename:str=Form("converted.cfg")):
    ingest_source_text(config)
    try: result=quick_convert(config,source_vendor,source_version,target_vendor,target_version,management_mode)
    except ValueError as exc: raise HTTPException(422,str(exc)) from exc
    project_id=str(uuid4()); root=(settings.workspace_dir/project_id/"quick-convert").resolve(); base=settings.workspace_dir.resolve()
    if base not in root.parents: raise HTTPException(400,"Invalid workspace path")
    root.mkdir(parents=True,exist_ok=False); filename=safe_filename(source_filename); (root/filename).write_text("\n".join(result.lines)+"\n",encoding="utf-8")
    return {"project_id":project_id,"detected_source_vendor":result.source_vendor.value,"detected_source_version":result.source_version,"extraction_coverage":result.extraction_coverage.model_dump(mode="json"),"reference_integrity":result.reference_integrity.model_dump(mode="json"),"semantic_compatibility":result.semantic_compatibility,"conversion_summary":result.summary,"category_accounting":result.categories,"warnings":result.warnings,"candidate_filename":filename,"download_url":f"/api/convert/{project_id}/download"}

@router.post("/convert/detect")
def detect_configuration(source:WorkbenchSource):
    config=ingest_source_text(source.source_text)
    detected,version=detect_source(config)
    domain=detect_domain(config)
    return {"vendor":detected.vendor.value,"version":version,"confidence":detected.confidence,"domain":domain.primary.value if domain.primary else None,"capabilities":[x.value for x in sorted(domain.capabilities,key=lambda x:x.value)],"ambiguous_domain":domain.ambiguous}

@router.get("/convert/{project_id}/download")
def download_converted_config(project_id:str):
    if not __import__("re").fullmatch(r"[0-9a-f-]{36}",project_id): raise HTTPException(404,"Candidate not found")
    root=(settings.workspace_dir/project_id/"quick-convert").resolve(); base=settings.workspace_dir.resolve()
    if base not in root.parents or not root.is_dir(): raise HTTPException(404,"Candidate not found")
    files=list(root.glob("*.set"))
    if len(files)!=1 or files[0].parent!=root: raise HTTPException(404,"Candidate not found")
    return FileResponse(files[0],media_type="text/plain",filename=files[0].name)

@router.post("/analyze", response_class=HTMLResponse)
def analyze(source: str = Form(...), source_vendor: str = Form("auto"), target_vendor: str = Form(...), source_version: str|None = Form(None), target_version: str|None = Form(None)):
    source=ingest_source_text(source)
    if target_vendor not in {Vendor.PALO_ALTO.value, Vendor.FORTIGATE.value}: raise HTTPException(400, "Unsupported target vendor")
    detected = detect_vendor(source)
    try: vendor = detected.vendor if source_vendor == "auto" else Vendor(source_vendor)
    except ValueError: raise HTTPException(400, "Unsupported source vendor")
    if vendor is Vendor.UNKNOWN: raise HTTPException(422, "Vendor confidence too low; select source vendor manually")
    try: migration_pair(vendor,target_vendor)
    except ValueError: raise HTTPException(422,"Unsupported migration pair")
    cfg = parse_config(source, vendor)
    report, graph = AnalysisEngine().analyze(cfg)
    project = str(uuid4()); root = (settings.workspace_dir / project).resolve(); base = settings.workspace_dir.resolve()
    if base not in root.parents: raise HTTPException(400, "Invalid workspace path")
    root.mkdir(parents=True, exist_ok=False)
    (root / "source.cfg").write_text(source, encoding="utf-8")
    (root / "normalized.json").write_text(cfg.model_dump_json(indent=2), encoding="utf-8")
    (root / "analysis.json").write_text(report.model_dump_json(indent=2), encoding="utf-8")
    integrity=ReferenceIntegrityValidator().validate(cfg); (root/"reference-integrity.json").write_text(integrity.model_dump_json(indent=2),encoding="utf-8")
    versions={"source":resolve_context(source,vendor,source_version).model_dump(mode="json"),"target":resolve_context("",Vendor.PALO_ALTO,target_version).model_dump(mode="json")}
    (root/"versions.json").write_text(json.dumps(versions,indent=2),encoding="utf-8")
    create_project(project, vendor.value, target_vendor, str(Path(project) / "source.cfg"), len(cfg.warnings))
    critical = sum(x.severity is Severity.ERROR for x in cfg.warnings)
    summary = {"policies": len(cfg.security_policies), "objects": len(cfg.addresses)+len(cfg.address_groups)+len(cfg.services)+len(cfg.service_groups), "nat": len(cfg.nat_policies), "interfaces": len(cfg.interfaces), "routes": len(cfg.static_routes), "issues": len(cfg.warnings), "findings": report.counts.total_findings}
    safe_summary = json.dumps(summary)
    message = "Manual review recommended — critical parse errors." if critical else "Parsed with warnings — manual review recommended." if cfg.warnings else "Parsed successfully."
    analysis_cards={"unused":report.counts.unused_objects,"duplicates":report.counts.duplicate_objects,"unresolved":report.counts.unresolved_references,"broad rules":report.counts.broad_rules,"potential shadowing":report.counts.potential_shadowing}
    findings="".join(f'<li><b>{x.type}</b> — {escape(x.primary_object_name)}: {escape(x.description)} <small>{x.severity}/{x.confidence}</small></li>' for x in report.findings[:100]) or "<li>No findings.</li>"
    return f'<section class="results" data-project="{project}" data-summary=\'{safe_summary}\'><h2>Analysis complete</h2><p><strong>{vendor.value}</strong> detected ({detected.confidence:.0%} confidence).</p><div class="cards">' + "".join(f'<article><b>{v}</b><span>{k.title()}</span></article>' for k,v in summary.items()) + f'</div><p class="notice">{message}</p><h3>Analysis Findings</h3><div class="cards compact">'+"".join(f'<article><b>{v}</b><span>{k.title()}</span></article>' for k,v in analysis_cards.items())+f'</div><details><summary>Findings ({report.counts.total_findings})</summary><ul class="findings">{findings}</ul></details><h3>Impact Analysis</h3><form class="impact-search" data-project="{project}"><label>Search object <input name="object" required></label><button type="submit">Analyze impact</button></form><div class="impact-result" aria-live="polite"></div><p>Dependency graph: {len(graph.nodes)} objects, {len(graph.edges)} edges.</p><p>Project: <code>{project}</code></p></section>'

def _artifacts(project_id:str):
    root=(settings.workspace_dir/project_id).resolve(); base=settings.workspace_dir.resolve()
    if base not in root.parents or not (root/"normalized.json").is_file(): raise HTTPException(404,"Project not found")
    try: cfg=FirewallConfig.model_validate_json((root/"normalized.json").read_text(encoding="utf-8"))
    except (ValueError,OSError): raise HTTPException(422,"Normalized project artifact is invalid")
    return cfg,AnalysisEngine().analyze(cfg)

@router.get("/projects/{project_id}/analysis")
def project_analysis(project_id:str): return _artifacts(project_id)[1][0]

@router.get("/projects/{project_id}/extraction")
def project_extraction(project_id:str): return _artifacts(project_id)[0].extraction_coverage

@router.get("/projects/{project_id}/reference-integrity")
def project_reference_integrity(project_id:str): return ReferenceIntegrityValidator().validate(_artifacts(project_id)[0])

@router.get("/projects/{project_id}/graph")
def project_graph(project_id:str):
    cfg,(_,graph)=_artifacts(project_id); dto=serialize_graph(graph); counts={}
    for node in dto.nodes: counts[node.type]=counts.get(node.type,0)+1
    return GraphSummary(objects=len(cfg.addresses)+len(cfg.address_groups)+len(cfg.services)+len(cfg.service_groups),policies=len(cfg.security_policies)+len(cfg.nat_policies),edges=len(dto.edges),nodes_by_type=counts,graph=dto)

@router.get("/projects/{project_id}/impact/{object_id}")
def project_impact(project_id:str,object_id:str):
    _,(_,graph)=_artifacts(project_id); result=AnalysisEngine().impact(graph,object_id)
    if not result: raise HTTPException(404,"Object not found or ambiguous")
    return result

@router.get("/projects/{project_id}/graph/search")
def graph_search(project_id:str,q:str=Query(min_length=1,max_length=100),limit:int=Query(20,ge=1,le=50)):
    _,(_,graph)=_artifacts(project_id); needle=q.casefold()
    matches=[d["dto"] for _,d in graph.nodes(data=True) if needle in d["dto"].name.casefold() or needle in d["dto"].object_id.casefold()]
    return sorted(matches,key=lambda x:(not x.name.casefold().startswith(needle),x.name.casefold(),x.id))[:limit]

@router.get("/projects/{project_id}/graph/scope")
def graph_scope(project_id:str,root:str,mode:str="dependencies",depth:int=Query(2,ge=1,le=3),limit:int=Query(75,ge=2,le=100)):
    _,(_,graph)=_artifacts(project_id); node=resolve_node(graph,root)
    if not node: raise HTTPException(404,"Object not found or ambiguous")
    if mode not in {"dependencies","impact","object","policy"}: raise HTTPException(400,"Unsupported graph mode")
    direction="reverse" if mode=="impact" else "both" if mode=="object" else "forward"
    seen={node}; frontier=[node]
    for _ in range(depth):
        found=[]
        for current in frontier:
            adjacent=list(graph.predecessors(current)) if direction=="reverse" else list(graph.successors(current))
            if direction=="both": adjacent+=list(graph.predecessors(current))
            found.extend(sorted(set(adjacent)))
        frontier=[]
        for candidate in found:
            if candidate not in seen: seen.add(candidate); frontier.append(candidate)
    ordered=[node]+sorted(seen-{node}); total=len(ordered); selected=set(ordered[:limit])
    return GraphScope(root=graph.nodes[node]["dto"],mode=mode,depth=depth,truncated=total>limit,total_candidates=total,graph=serialize_graph(graph.subgraph(selected)))

@router.get("/projects/{project_id}/objects/{object_id}/references")
def project_references(project_id:str,object_id:str):
    _,(_,graph)=_artifacts(project_id); node=resolve_node(graph,object_id)
    if not node: raise HTTPException(404,"Object not found or ambiguous")
    return {"object":graph.nodes[node]["dto"],"references":[graph.nodes[x]["dto"] for x in graph.predecessors(node)]}

def _migration(project_id):
    cfg,_=_artifacts(project_id); project=get_project(project_id)
    if not project: raise HTTPException(404,"Project not found")
    try: migration_pair(project.source_vendor,project.target_vendor)
    except ValueError: raise HTTPException(422,"Unsupported migration pair")
    root=(settings.workspace_dir/project_id/"migration").resolve(); base=settings.workspace_dir.resolve()
    if base not in root.parents: raise HTTPException(400,"Invalid workspace path")
    root.mkdir(exist_ok=True)
    path=root/"mappings.json"
    mappings=MigrationMappings.model_validate_json(path.read_text(encoding="utf-8")) if path.is_file() else default_mappings(cfg)
    return cfg,mappings,root

def _versions(project_id):
    path=settings.workspace_dir/project_id/"versions.json"
    if not path.is_file(): return None,None
    data=json.loads(path.read_text(encoding="utf-8")); return VersionContext.model_validate(data["source"]),VersionContext.model_validate(data["target"])

def _lint(project_id):
    cfg,_=_artifacts(project_id); project=get_project(project_id)
    if not project: raise HTTPException(404,"Project not found")
    integrity=ReferenceIntegrityValidator().validate(cfg)
    root=(settings.workspace_dir/project_id/"migration").resolve(); base=settings.workspace_dir.resolve()
    if base not in root.parents: raise HTTPException(400,"Invalid workspace path")
    root.mkdir(exist_ok=True); path=root/"lint-findings.json"
    artifact=build_lint_artifact(lint_config(cfg,integrity),project_id)
    path.write_text(serialize_lint_artifact(artifact),encoding="utf-8")
    return path

@router.post("/projects/{project_id}/lint")
def generate_lint(project_id:str):
    return json.loads(_lint(project_id).read_text(encoding="utf-8"))

@router.get("/projects/{project_id}/lint")
def get_lint(project_id:str):
    path=settings.workspace_dir/project_id/"migration"/"lint-findings.json"
    if not path.is_file(): raise HTTPException(404,"Lint findings have not been generated")
    return json.loads(path.read_text(encoding="utf-8"))

@router.get("/projects/{project_id}/migration/download/lint")
def download_lint(project_id:str):
    path=settings.workspace_dir/project_id/"migration"/"lint-findings.json"
    if not path.is_file(): raise HTTPException(404,"Lint findings have not been generated")
    return FileResponse(path,media_type="application/json",filename="lint-findings.json")

@router.get("/projects/{project_id}/migration/mappings")
def migration_mappings(project_id:str): return _migration(project_id)[1]

@router.put("/projects/{project_id}/migration/mappings")
def update_migration_mappings(project_id:str,mappings:MigrationMappings):
    cfg,_,root=_migration(project_id); sources={x.name:x for x in cfg.interfaces}
    if len({x.source_interface for x in mappings.interfaces})!=len(mappings.interfaces) or any(x.source_interface not in sources for x in mappings.interfaces): raise HTTPException(422,"Unknown or duplicate source interface")
    atomic_write(root/"mappings.json",mappings.model_dump_json(indent=2)+"\n"); invalidate(settings.workspace_dir,project_id,"mapping"); return mappings

def _plan(project_id):
    cfg,mappings,root=_migration(project_id); source_version,target_version=_versions(project_id); plan=MigrationPlanner().plan(cfg,mappings,source_version,target_version,ReferenceIntegrityValidator().validate(cfg))
    (root/"compatibility.json").write_text(json.dumps([x.model_dump(mode="json") for x in plan.compatibility],indent=2),encoding="utf-8")
    artifact=build_plan_artifact(plan,cfg); (root/"migration-plan.json").write_text(serialize_plan_artifact(artifact),encoding="utf-8")
    return plan,root

@router.get("/projects/{project_id}/migration/compatibility")
def migration_compatibility(project_id:str):
    plan=_plan(project_id)[0]
    return {"source_vendor":plan.source_vendor,"target_vendor":plan.target_vendor,"items":plan.compatibility}

@router.get("/projects/{project_id}/semantic-compatibility")
def semantic_compatibility(project_id:str):
    plan=_plan(project_id)[0]
    counts=Counter(x.status.value for x in plan.compatibility)
    return {"summary":dict(counts),"items":plan.compatibility}

@router.post("/projects/{project_id}/migration/plan")
def migration_plan(project_id:str):
    plan,root=_plan(project_id)
    return json.loads((root/"migration-plan.json").read_text(encoding="utf-8"))

@router.get("/projects/{project_id}/migration/plan")
def get_migration_plan(project_id:str): return migration_plan(project_id)

def _semantic_diff_artifact(project_id):
    cfg,mappings,root=_migration(project_id); source_version,target_version=_versions(project_id); plan=MigrationPlanner().plan(cfg,mappings,source_version,target_version,ReferenceIntegrityValidator().validate(cfg)); project=get_project(project_id)
    context=lambda vendor,version:{"domain":getattr(getattr(cfg,"domain",None),"value","FIREWALL"),"vendor":vendor.value,"platform":None,"exact_version":version.selected_version if version else None}
    source=context(plan.source_vendor,source_version); target=context(plan.target_vendor,target_version); review={key:value.model_dump(mode="json") for key,value in load_decisions(root).items()}
    artifact=build_semantic_diff(cfg,plan.compatibility,source,target,project_id=project_id,mappings=mappings.model_dump(mode="json"),review=review)
    return root/"semantic-diff.json",artifact

@router.post("/projects/{project_id}/migration/semantic-diff")
def generate_semantic_diff(project_id:str):
    path,artifact=_semantic_diff_artifact(project_id); atomic_write(path,serialize_semantic_diff(artifact)); return artifact

def _existing_semantic_diff(project_id):
    path=settings.workspace_dir/project_id/"migration"/"semantic-diff.json"
    if not path.is_file(): raise HTTPException(404,"Semantic diff has not been generated")
    stored=json.loads(path.read_text(encoding="utf-8")); _,current=_semantic_diff_artifact(project_id)
    if stored.get("state_fingerprint")!=current.state_fingerprint: path.unlink(missing_ok=True); raise HTTPException(409,"Semantic diff is stale; regenerate it")
    return path,stored

@router.get("/projects/{project_id}/migration/semantic-diff")
def get_semantic_diff(project_id:str): return _existing_semantic_diff(project_id)[1]

@router.get("/projects/{project_id}/migration/download/semantic-diff")
def download_semantic_diff(project_id:str):
    path,_=_existing_semantic_diff(project_id)
    return FileResponse(path,media_type="application/json",filename="semantic-diff.json")

@router.post("/projects/{project_id}/migration/render")
def migration_render(project_id:str):
    plan,root=_plan(project_id); renderer=PaloAltoRenderer(); lines,report=renderer.render(plan) if not plan.blocked else ([],build_report(plan))
    errors=validate_candidate(lines)
    if errors: report.errors.extend(errors)
    candidate="\n".join(lines)+("\n" if lines else "")
    (root/"candidate-pan-os.set").write_text(candidate or "",encoding="utf-8"); (root/"migration-report.json").write_text(report.model_dump_json(indent=2),encoding="utf-8")
    ordering=getattr(renderer,"ordering_plan",None); ordering_path=root/"security-rule-ordering.json"
    if ordering: ordering_path.write_text(ordering.model_dump_json(indent=2),encoding="utf-8")
    elif ordering_path.exists(): ordering_path.unlink()
    cfg,_,_=_migration(project_id); review=build_review(cfg,plan,getattr(renderer,"commands",[]),load_decisions(root))
    status="BLOCKED" if report.errors else "REVIEW_REQUIRED" if report.manual_review or report.unsupported or report.partial else "CANDIDATE"
    return {"status":status,"generated_lines":len(lines),"generated_entities":report.generated_entities,"skipped_entities":report.skipped_entities,"manual_review":report.manual_review,"unsupported":report.unsupported,"candidate_path":"migration/candidate-pan-os.set","report":report,"candidate":candidate}

def _current_review(project_id):
    cfg,mappings,root=_migration(project_id); source_version,target_version=_versions(project_id); plan=MigrationPlanner().plan(cfg,mappings,source_version,target_version); renderer=PaloAltoRenderer(); lines,report=renderer.render(plan) if not plan.blocked else ([],build_report(plan)); review=build_review(cfg,plan,getattr(renderer,"commands",[]),load_decisions(root))
    return cfg,mappings,root,plan,lines,report,review

@router.get("/projects/{project_id}/migration/review")
def migration_review(project_id:str): return _current_review(project_id)[-1]

@router.get("/projects/{project_id}/migration/review/{item_id}")
def migration_review_item(project_id:str,item_id:str):
    review=_current_review(project_id)[-1]
    item=next((x for x in review.items if x.id==item_id),None)
    if not item: raise HTTPException(404,"Review item not found")
    return item

@router.put("/projects/{project_id}/migration/review/{item_id}")
def update_migration_review(project_id:str,item_id:str,decision:ReviewDecision):
    *_,root,plan,lines,report,review=_current_review(project_id)
    item=next((x for x in review.items if x.id==item_id),None)
    if not item: raise HTTPException(404,"Review item not found")
    if decision.semantic_hash!=item.semantic_hash: raise HTTPException(409,"Review item changed; reload before saving a decision")
    decision.semantic_hash=item.semantic_hash; decisions=update_decision(root,item_id,decision)
    invalidate(settings.workspace_dir,project_id,"review")
    return next(x for x in build_review(_migration(project_id)[0],plan,getattr(_review_renderer(plan),"commands",[]),decisions).items if x.id==item_id)

def _review_renderer(plan):
    renderer=PaloAltoRenderer(); renderer.render(plan); return renderer

@router.get("/projects/{project_id}/migration/validation")
def migration_validation(project_id:str):
    _,_,root,_,_,_,_=_current_review(project_id); path=root/"validation-report.json"
    if not path.is_file(): raise HTTPException(404,"Validation has not been run")
    return json.loads(path.read_text(encoding="utf-8"))

@router.post("/projects/{project_id}/migration/validate")
def run_migration_validation(project_id:str):
    cfg,_,root,plan,lines,_,review=_current_review(project_id); validation=validate_migration(cfg,plan,review,lines); (root/"validation-report.json").write_text(validation.model_dump_json(indent=2),encoding="utf-8"); return validation

@router.get("/projects/{project_id}/migration/pan-lab-validation")
def pan_lab_validation(project_id:str):
    _,_,root=_migration(project_id); path=root/"validation"/"pan-lab-validation.json"
    if path.is_file(): return json.loads(path.read_text(encoding="utf-8"))
    enabled=settings.pan_lab_validation_enabled and settings.pan_lab_isolated
    return {"status":"BLOCKED" if enabled else "NOT_CONFIGURED","message":"VERSION_NOT_VERIFIED: PAN-OS 11.1 local-firewall XPath and XML element mappings require version-matched device API Browser or debug evidence." if enabled else "PAN-OS lab validation requires enabled and isolated-lab acknowledgement."}

@router.post("/projects/{project_id}/migration/pan-lab-validation")
def run_pan_lab_validation(project_id:str):
    _migration(project_id)
    if not settings.pan_lab_validation_enabled or not settings.pan_lab_isolated: raise HTTPException(409,"PAN-OS lab validation requires FCS_PAN_LAB_VALIDATION_ENABLED=true and FCS_PAN_LAB_ISOLATED=true")
    raise HTTPException(501,"VERSION_NOT_VERIFIED: PAN-OS 11.1 local-firewall XPath and XML element mappings require version-matched device API Browser or debug evidence")

@router.get("/projects/{project_id}/migration/review-package")
def migration_review_package(project_id:str):
    cfg,mappings,root,plan,lines,report,review=_current_review(project_id); validation=validate_migration(cfg,plan,review,lines)
    if validation.status=="BLOCKING": raise HTTPException(409,"Final review package blocked by validation; candidate remains available")
    lab_path=root/"validation"/"pan-lab-validation.json"; lab=PanLabValidationResult.model_validate_json(lab_path.read_text(encoding="utf-8")) if lab_path.is_file() else None
    data=export_package("\n".join(lines)+("\n" if lines else ""),report.model_dump(mode="json"),review,validation,mappings,report.security_rule_ordering,lab)
    return Response(data,media_type="application/zip",headers={"Content-Disposition":'attachment; filename="migration-review-package.zip"'})

@router.get("/projects/{project_id}/migration/report")
def migration_report(project_id:str):
    _,_,root=_migration(project_id); path=root/"migration-report.json"
    if not path.is_file(): raise HTTPException(404,"Migration has not been rendered")
    return json.loads(path.read_text(encoding="utf-8"))

@router.get("/projects/{project_id}/migration/download/config")
def download_migration_config(project_id:str):
    _,_,root=_migration(project_id); path=root/"candidate-pan-os.set"
    if not path.is_file(): raise HTTPException(404,"Migration has not been rendered")
    return FileResponse(path,media_type="text/plain",filename="candidate-pan-os.set")

@router.get("/projects/{project_id}/migration/download/report")
def download_migration_report(project_id:str):
    _,_,root=_migration(project_id); path=root/"migration-report.json"
    if not path.is_file(): raise HTTPException(404,"Migration has not been rendered")
    return FileResponse(path,media_type="application/json",filename="migration-report.json")

@router.get("/projects/{project_id}/migration/download/plan")
def download_migration_plan(project_id:str):
    _,root=_plan(project_id)
    return FileResponse(root/"migration-plan.json",media_type="application/json",filename="migration-plan.json")
