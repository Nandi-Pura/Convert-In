import hashlib
from .models import CompatibilityResult, CompatibilityStatus

SEMANTIC_FIELDS={
    "address":{"type":"type","value":"value"},
    "address_group":{"members":"members"},
    "service":{"protocol":"protocol","source_ports":"source_ports","destination_ports":"ports"},
    "service_group":{"members":"members"},
    "security_policy":{"source_zones":"from","destination_zones":"to","sources":"source","destinations":"destination","services":"service","action":"action","enabled":"enabled","log_start":"log_start","log_end":"log_end","position":"position"},
    "nat_policy":{"source_zones":"from","destination_zones":"to","original_source":"source","original_destination":"destination","original_service":"service","type":"type","translated_source":"translated_source","translated_destination":"translated_destination","translated_service":"translated_service","translation_target":"translation_target","position":"position"},
    "route":{"destination":"destination","next_hop":"next_hop","interface":"interface","metric":"metric"},
}

def result(entity,kind,status,*reasons,required=(),topology=None):
    context=None
    if entity.provenance: context=f"{entity.provenance.source_section or 'source'} line {entity.provenance.source_line or '?'}"
    return CompatibilityResult(entity_id=entity.id,entity_type=kind,source_name=entity.name,status=status,reasons=list(reasons),required_mappings=list(required),source_context=context,topology=topology or {})

def finalize(item,entity,source_profile,target_profile,capability,management_mode,target_data=None):
    source=source_profile.capabilities.get(capability) if source_profile else None
    target=target_profile.capabilities.get(capability) if target_profile else None
    item.source_semantic=entity.model_dump(mode="json",exclude={"provenance","vendor_extensions"})
    item.target_semantic=target_data or {}
    fields=SEMANTIC_FIELDS.get(item.entity_type,{})
    item.preserved_semantics=sorted(source_key for source_key,target_key in fields.items() if target_key in item.target_semantic)
    item.lost_semantics=sorted(source_key for source_key,target_key in fields.items() if item.source_semantic.get(source_key) not in (None,[],False) and target_key not in item.target_semantic)
    item.required_context=list(item.required_mappings)
    item.source_evidence_refs=list(source.documentation_refs) if source else []
    item.target_evidence_refs=list(target.documentation_refs) if target else []
    item.renderer_capability_id=f"{target_profile.id}:{capability}" if target_profile else None
    item.renderer_support=bool(target and target.renderer_support)
    item.test_refs=list(dict.fromkeys((source.test_refs if source else [])+(target.test_refs if target else [])))
    item.blocking=item.status not in {CompatibilityStatus.EXACT,CompatibilityStatus.SUPPORTED}
    basis="|".join((item.entity_id,target_profile.vendor.value if target_profile else "",item.target_version or "",management_mode,item.status.value,item.renderer_capability_id or ""))
    item.decision_id=hashlib.sha256(basis.encode()).hexdigest()[:16]
    return item