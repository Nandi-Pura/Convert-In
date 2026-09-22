import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from app.core.models import ExtractionCoverageReport, Severity, Vendor
from app.core.parsing import detect_vendor, parse_config
from app.core.renderers import PaloAltoRenderer
from app.core.versions import resolve_context, version_profile
from .mappings import default_mappings
from .models import CompatibilityStatus, TargetManagementMode
from .planner import MigrationPlanner
from .registry import QUICK_CONVERT_PROFILES, QuickConvertRole

CATEGORY_LABELS={"address":"Addresses","address_group":"Address Groups","service":"Services","service_group":"Service Groups","security_policy":"Security Policies","nat_policy":"NAT","route":"Static Routes","interface":"Interfaces","zone":"Zones","vpn":"VPN"}

@dataclass(frozen=True)
class QuickConvertResult:
    source_vendor: Vendor
    source_version: str
    lines: list[str]
    summary: dict[str,int]
    categories: dict[str,dict[str,int]]
    warnings: list[str]
    extraction_coverage: ExtractionCoverageReport

def profiles():
    return [{"vendor":x.vendor.value,"label":x.label,"role":x.role.value,"versions":list(x.versions),"management_modes":list(x.management_modes)} for x in QUICK_CONVERT_PROFILES]

def safe_filename(value:str|None)->str:
    stem=Path(value or "converted").stem
    stem=re.sub(r"[^A-Za-z0-9._-]+","-",stem).strip(".-")[:80] or "converted"
    return f"{stem}-to-panos-11.1.set"

def detect_source(text:str):
    detected=detect_vendor(text)
    if detected.vendor not in {Vendor.ASA,Vendor.FORTIGATE}: return detected,None
    context=resolve_context(text,detected.vendor)
    return detected,context.detected_family if context.confidence=="HIGH" else None

def convert(text:str,source_vendor:str,source_version:str,target_vendor:str="paloalto",target_version:str="11.1",management_mode:str="LOCAL_FIREWALL")->QuickConvertResult:
    detected,detected_version=detect_source(text)
    try: vendor=detected.vendor if source_vendor=="auto" else Vendor(source_vendor)
    except ValueError as exc: raise ValueError("Unsupported source vendor.") from exc
    if vendor not in {Vendor.ASA,Vendor.FORTIGATE}: raise ValueError("Select Cisco ASA or FortiGate as the source vendor.")
    allowed=next(x.versions for x in QUICK_CONVERT_PROFILES if x.vendor==vendor and x.role==QuickConvertRole.SOURCE)
    selected=source_version or (detected_version if detected.vendor==vendor else None)
    if not selected: raise ValueError("Source version was not detected. Select it explicitly.")
    if selected not in allowed or not version_profile(vendor,selected): raise ValueError(f"Unsupported source version for {vendor.value}: {selected}.")
    if target_vendor!=Vendor.PALO_ALTO.value or target_version!="11.1": raise ValueError("Quick Convert supports only PAN-OS 11.1.")
    if management_mode!=TargetManagementMode.LOCAL_FIREWALL.value: raise ValueError("Quick Convert supports only LOCAL_FIREWALL.")
    cfg=parse_config(text,vendor)
    cfg.extraction_coverage.source_version=selected
    if any(x.severity==Severity.ERROR for x in cfg.warnings): raise ValueError("Configuration has blocking parser errors. Open Advanced Workbench for recovery details.")
    normalized=sum(len(x) for x in (cfg.interfaces,cfg.zones,cfg.addresses,cfg.address_groups,cfg.services,cfg.service_groups,cfg.security_policies,cfg.nat_policies,cfg.static_routes,cfg.vpn_objects))
    if not normalized: raise ValueError("No supported firewall constructs were parsed. Check the vendor, version, and configuration syntax.")
    mappings=default_mappings(cfg)
    plan=MigrationPlanner().plan(cfg,mappings,resolve_context(text,vendor,selected),resolve_context("",Vendor.PALO_ALTO,"11.1"))
    renderer=PaloAltoRenderer(); commands,report=renderer.render(plan)
    if report.errors: raise ValueError("Candidate generation was blocked: "+" ".join(report.errors))
    generated={x.entity_id for x in renderer.commands}
    states={}
    for item in plan.compatibility:
        states[item.entity_id]="GENERATED" if item.entity_id in generated else "VERSION_NOT_VERIFIED" if item.version_status!="VERIFIED" else "UNSUPPORTED" if item.status==CompatibilityStatus.UNSUPPORTED else "MANUAL_REVIEW"
    counts=Counter(states.values())
    if len(plan.compatibility)!=sum(counts.values()) or len(plan.compatibility)!=normalized: raise ValueError("Zero-loss accounting failed; candidate was not created.")
    categories={}
    for kind,label in CATEGORY_LABELS.items():
        items=[x for x in plan.compatibility if x.entity_type==kind]
        if items: categories[label]={"generated":sum(states[x.entity_id]=="GENERATED" for x in items),"review":sum(states[x.entity_id]!="GENERATED" for x in items)}
    summary={"generated":counts["GENERATED"],"manual_review":counts["MANUAL_REVIEW"],"unsupported":counts["UNSUPPORTED"],"version_not_verified":counts["VERSION_NOT_VERIFIED"],"total":len(plan.compatibility)}
    coverage=cfg.extraction_coverage
    header=["# Convert-In","# CANDIDATE CONFIGURATION — ENGINEER REVIEW REQUIRED","#",f"# Source Vendor: {'Cisco ASA' if vendor==Vendor.ASA else 'FortiGate'}",f"# Source Version: {selected}","# Target Vendor: Palo Alto Networks","# Target Version: PAN-OS 11.1","# Management Mode: LOCAL_FIREWALL","#","# Generated locally.","# No deployment performed.","#","# Source Extraction Coverage",f"# Semantic Constructs: {coverage.semantic_total}",f"# Normalized: {coverage.normalized}",f"# Recovered: {coverage.recovered}",f"# Unparsed: {coverage.unparsed}",f"# Source Unsupported: {coverage.unsupported}",f"# Coverage: {coverage.coverage_percent:.2f}%","#","# Conversion Summary",f"# Generated: {summary['generated']}",f"# Manual Review: {summary['manual_review']}",f"# Unsupported: {summary['unsupported']}",f"# Version Not Verified: {summary['version_not_verified']}","#"]
    header += [f"# {name}: {value['generated']} generated / {value['review']} review" for name,value in categories.items()]
    review=[]
    for item in plan.compatibility:
        state=states[item.entity_id]
        if state=="GENERATED": continue
        reason=" ".join(item.reasons) or "Target command omitted by the current documented scope."
        review += ["#",f"# [{state}] {CATEGORY_LABELS.get(item.entity_type,item.entity_type)}: {item.source_name}","# Target command omitted.",f"# Reason: {reason}"]
    for item in cfg.unparsed_constructs:
        review += ["#",f"# [MANUAL_REVIEW] Unparsed construct at line {item.line_number or 'unknown'}","# Source text omitted.",f"# Reason: {item.reason}"]
    if cfg.security_policies: review += ["#","# [MANUAL_REVIEW] Security rule ordering","# Source rule ordering intent was preserved for review.","# No automatic target move operation was executed."]
    lines=header+["#"]+commands+review
    warnings=[x.message for x in cfg.warnings]+plan.advisories
    return QuickConvertResult(vendor,selected,lines,summary,categories,warnings,coverage)