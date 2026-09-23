import hashlib
from collections import Counter

from app.core.models import (ExtractionCategoryBreakdown, ExtractionCoverageReport, ExtractionOutcome,
    RouterConfig, SourceExtractionItem, Vendor)
from app.core.reference_integrity import (ReferenceCategoryBreakdown, ReferenceFindingType,
    ReferenceIntegrityFinding, ReferenceIntegrityReport, ReferenceIntegrityStatus)
from app.core.models import Severity


def finalize_router_extraction(cfg: RouterConfig, ignored: int, version: str | None) -> RouterConfig:
    items=[]
    collections=(("interface",cfg.interfaces),("vrf",cfg.vrfs),("route",cfg.static_routes),
        ("prefix_list_entry",[e for p in cfg.prefix_lists for e in p.entries]),
        ("route_policy_term",[t for p in cfg.route_policies for t in p.terms]),
        ("ospf_process",cfg.ospf_processes),("bgp_neighbor",[n for p in cfg.bgp_processes for n in p.neighbors]),
        ("bgp_process",[p for p in cfg.bgp_processes if not p.neighbors]))
    for kind,entities in collections:
        for entity in entities:
            location=f"line {entity.provenance.source_line}" if entity.provenance and entity.provenance.source_line else "unknown"
            recovered=bool(getattr(entity,"vendor_extensions",{}).get("recovered"))
            raw=f"{kind}|{entity.id}|{location}"
            items.append(SourceExtractionItem(id=hashlib.sha256(raw.encode()).hexdigest()[:16],source_vendor=Vendor.CISCO_IOSXE,
                source_version=version,source_type=kind,source_name=entity.name,source_location=location,
                outcome=ExtractionOutcome.RECOVERED if recovered else ExtractionOutcome.NORMALIZED,
                normalized_entity_ids=[entity.id],reason="Safe fields retained from incomplete construct." if recovered else None))
    for entry in cfg.unparsed_constructs:
        outcome=ExtractionOutcome.SOURCE_UNSUPPORTED if entry.unsupported else ExtractionOutcome.UNPARSED
        location=f"line {entry.line_number}"; raw=f"{entry.category}|{entry.raw_text}|{location}"
        items.append(SourceExtractionItem(id=hashlib.sha256(raw.encode()).hexdigest()[:16],source_vendor=Vendor.CISCO_IOSXE,
            source_version=version,source_type=entry.category or "other",source_name=entry.section or "construct",
            source_location=location,outcome=outcome,reason=entry.reason))
    counts=Counter(x.outcome for x in items); total=sum(counts[x] for x in (ExtractionOutcome.NORMALIZED,ExtractionOutcome.RECOVERED,ExtractionOutcome.UNPARSED,ExtractionOutcome.SOURCE_UNSUPPORTED))
    categories={}
    field={ExtractionOutcome.NORMALIZED:"normalized",ExtractionOutcome.RECOVERED:"recovered",ExtractionOutcome.UNPARSED:"unparsed",ExtractionOutcome.SOURCE_UNSUPPORTED:"unsupported"}
    for item in items:
        row=categories.setdefault(item.source_type,ExtractionCategoryBreakdown()); row.semantic_total+=1
        setattr(row,field[item.outcome],getattr(row,field[item.outcome])+1)
    cfg.extraction_coverage=ExtractionCoverageReport(source_vendor=Vendor.CISCO_IOSXE,source_version=version,semantic_total=total,
        normalized=counts[ExtractionOutcome.NORMALIZED],recovered=counts[ExtractionOutcome.RECOVERED],unparsed=counts[ExtractionOutcome.UNPARSED],
        unsupported=counts[ExtractionOutcome.SOURCE_UNSUPPORTED],ignored_non_semantic=ignored,
        coverage_percent=round((counts[ExtractionOutcome.NORMALIZED]+counts[ExtractionOutcome.RECOVERED])/total*100,2) if total else None,
        category_breakdown=categories,items=items,warnings=[x.message for x in cfg.warnings])
    return cfg


class RouterReferenceIntegrityValidator:
    def validate(self,cfg:RouterConfig)->ReferenceIntegrityReport:
        indexes={"interface":{x.name:x for x in cfg.interfaces},"vrf":{x.name:x for x in cfg.vrfs},
            "prefix_list":{x.name:x for x in cfg.prefix_lists},"route_policy":{x.name:x for x in cfg.route_policies}}
        entities=[*(x for x in cfg.interfaces),*(x for x in cfg.vrfs),*(x for x in cfg.static_routes),*(x for x in cfg.prefix_lists),
            *(t for p in cfg.route_policies for t in p.terms),*(x for x in cfg.ospf_processes),*(x for x in cfg.bgp_processes),*(n for p in cfg.bgp_processes for n in p.neighbors)]
        findings=[]; refs=[]
        def check(source,ref,kind,context,finding_type):
            if not ref:return
            ok=ref in indexes[kind]; refs.append((context,ok))
            if ok:return
            raw=f"{finding_type}|{source.id}|{ref}|{context}"
            findings.append(ReferenceIntegrityFinding(finding_id=hashlib.sha256(raw.encode()).hexdigest()[:16],finding_type=finding_type,
                severity=Severity.ERROR,source_entity_id=source.id,source_entity_type=context.split("→")[0],source_entity_name=source.name,
                referenced_entity_name=ref,referenced_entity_type=kind,dependency_path=[source.name,ref],reason=f"Missing {kind.replace('_',' ')} reference.",blocking=True))
        for x in cfg.interfaces:check(x,x.vrf,"vrf","interface→vrf",ReferenceFindingType.MISSING_VRF)
        for x in cfg.static_routes:
            check(x,x.vrf,"vrf","route→vrf",ReferenceFindingType.MISSING_VRF); check(x,x.interface,"interface","route→interface",ReferenceFindingType.MISSING_INTERFACE)
        for p in cfg.route_policies:
            for t in p.terms:
                for ref in t.prefix_lists:check(t,ref,"prefix_list","route_policy→prefix_list",ReferenceFindingType.MISSING_PREFIX_LIST)
        for p in cfg.bgp_processes:
            check(p,p.vrf,"vrf","bgp_process→vrf",ReferenceFindingType.MISSING_VRF)
            for network in p.networks:
                check(p,network.route_policy,"route_policy","bgp_network→route_policy",ReferenceFindingType.MISSING_ROUTE_POLICY)
            for n in p.neighbors:
                check(n,n.route_policy_in,"route_policy","bgp_neighbor→route_policy",ReferenceFindingType.MISSING_ROUTE_POLICY)
                check(n,n.route_policy_out,"route_policy","bgp_neighbor→route_policy",ReferenceFindingType.MISSING_ROUTE_POLICY)
                check(n,n.update_source,"interface","bgp_neighbor→interface",ReferenceFindingType.MISSING_INTERFACE)
        for p in cfg.ospf_processes:check(p,p.vrf,"vrf","ospf_process→vrf",ReferenceFindingType.MISSING_VRF)
        counts=Counter(x for x,_ in refs); resolved=Counter(x for x,ok in refs if ok)
        categories={k:ReferenceCategoryBreakdown(total=v,resolved=resolved[k],unresolved=v-resolved[k]) for k,v in counts.items()}
        blocked={x.source_entity_id for x in findings}
        return ReferenceIntegrityReport(status=ReferenceIntegrityStatus.BLOCKED if findings else ReferenceIntegrityStatus.PASS,total_entities=len(entities),
            total_references=len(refs),resolved_references=sum(resolved.values()),unresolved_references=len(refs)-sum(resolved.values()),warnings=0,
            blocking_findings=len(findings),findings=sorted(findings,key=lambda x:x.finding_id),category_breakdown=categories,
            entity_statuses={x.id:ReferenceIntegrityStatus.BLOCKED if x.id in blocked else ReferenceIntegrityStatus.PASS for x in entities})