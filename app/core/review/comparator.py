import hashlib, json
from collections import defaultdict
from app.core.analysis import AnalysisEngine
from app.core.graph import DependencyGraphBuilder, resolve_node
from .models import MigrationReview,MigrationReviewItem,ReviewDecision,ReviewStatus,ReviewSummary

def semantic_hash(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=False,default=str).encode()).hexdigest()

def _source(entity,kind):
    d=entity.model_dump(mode="json",exclude={"vendor_extensions","tags"})
    if kind=="security_policy": return {k:d.get(k) for k in ("name","position","ingress_interfaces","source_zones","destination_zones","sources","destinations","services","action","enabled","log_start","log_end")}
    if kind=="nat_policy": return {k:d.get(k) for k in ("name","type","source_interfaces","destination_interfaces","source_zones","destination_zones","original_source","translated_source","original_destination","translated_destination","original_service","translated_service","position","identity")}
    return d

def build_review(cfg,plan,commands=(),decisions=None):
    decisions={k:(v if isinstance(v,ReviewDecision) else ReviewDecision.model_validate(v)) for k,v in (decisions or {}).items()}
    entities={x.id:x for xs in (cfg.interfaces,cfg.zones,cfg.addresses,cfg.address_groups,cfg.services,cfg.service_groups,cfg.security_policies,cfg.nat_policies,cfg.static_routes,cfg.vpn_objects) for x in xs}
    planned={x.entity_id:x for x in plan.generate}; names={x.entity_id:x.target_name for x in plan.names}; by_command=defaultdict(list)
    for number,c in enumerate(commands,1): by_command[c.entity_id].append({"id":semantic_hash({"entity":c.entity_id,"path":c.path,"values":c.values})[:16],"line":number,"text":c.text,"target_profile":c.target_profile,"capability_id":c.capability_id,"documentation_refs":c.documentation_refs,"context":c.management_context.model_dump(mode="json")})
    analysis,_=AnalysisEngine().analyze(cfg); findings=defaultdict(list)
    for f in analysis.findings:
        findings[f.primary_object_id].append(f.model_dump(mode="json"))
        for related in f.related_objects: findings[related.id].append(f.model_dump(mode="json"))
    graph=DependencyGraphBuilder().build(cfg); items=[]
    for c in plan.compatibility:
        entity=entities[c.entity_id]; source=_source(entity,c.entity_type); target=planned[c.entity_id].data if c.entity_id in planned else {}
        meaningful={"target_name":names.get(c.entity_id),"target":target,"commands":[x["text"] for x in by_command[c.entity_id]]}; digest=semantic_hash(meaningful)
        decision=decisions.get(c.entity_id,ReviewDecision())
        if decision.semantic_hash!=digest: decision=ReviewDecision()
        preserved=[k for k,v in source.items() if k in target and target[k]==v]
        changed={k:{"source":v,"target":target[k]} for k,v in source.items() if k in target and target[k]!=v}
        node=resolve_node(graph,c.entity_id); used=[]
        if node:
            used=[{"id":graph.nodes[n]["dto"].object_id,"name":graph.nodes[n]["dto"].name,"type":graph.nodes[n]["dto"].type.value} for n in graph.predecessors(node)]
        items.append(MigrationReviewItem(id=c.entity_id,entity_type=c.entity_type,source_id=c.entity_id,source_name=c.source_name,target_name=names.get(c.entity_id),compatibility_status=c.status,review_status=decision.status,note=decision.note,semantic_hash=digest,source_semantics=source,target_semantics=target,preserved_fields=preserved,changed_fields=changed,dropped_fields=[k for k in source if k not in target and source[k] not in (None,[],{},False)],manual_review_reasons=c.reasons,warnings=[],mapping_evidence={"required":c.required_mappings,"topology":c.topology},analysis_findings=findings[c.entity_id],generated_commands=by_command[c.entity_id],used_by=used,source_vendor=plan.source_vendor.value,source_version=c.source_version,target_version=c.target_version,documentation_refs=c.documentation_refs,version_status=c.version_status))
    reviewed=sum(x.review_status!=ReviewStatus.NOT_REVIEWED for x in items)
    review_states={"PARTIAL","MANUAL_REVIEW","VERSION_NOT_VERIFIED"}
    summary=ReviewSummary(total=len(items),generated=sum(bool(x.generated_commands) for x in items),manual_review=sum(x.compatibility_status in review_states for x in items),unsupported=sum(x.compatibility_status=="UNSUPPORTED" for x in items),reviewed=reviewed,accepted=sum(x.review_status==ReviewStatus.ACCEPTED for x in items),needs_changes=sum(x.review_status==ReviewStatus.NEEDS_CHANGES for x in items),blocked=sum(x.review_status==ReviewStatus.BLOCKED for x in items),manual_review_remaining=sum(x.compatibility_status in review_states and x.review_status==ReviewStatus.NOT_REVIEWED for x in items))
    refs=sorted({ref for item in items for ref in item.documentation_refs})
    return MigrationReview(source_vendor=plan.source_vendor.value,target_vendor=plan.target_vendor.value,items=items,summary=summary,source_version=plan.source_version,target_version=plan.target_version,documentation_refs=refs)