import hashlib
import json

from pydantic import BaseModel, Field, TypeAdapter

from app.core.graph import DependencyGraphBuilder
from app.core.models import FirewallConfig, Vendor
from app.core.versions import exact_profile

from .models import CompatibilityStatus, MigrationMappings, MigrationPlan, NameMapping

SCHEMA = "convert-in.migration-plan/v1"


class PlanVersionContext(BaseModel):
    vendor: Vendor
    family: str | None = None
    exact_version: str | None = None
    verification_state: str = "VERSION_NOT_VERIFIED"


class PlanSummary(BaseModel):
    total_entities: int
    render_eligible: int
    exact: int
    supported: int
    partial: int
    manual_review: int
    unsupported: int
    version_not_verified: int
    blocked: int


class EntityPlanRecord(BaseModel):
    entity_id: str
    entity_type: str
    source_name: str
    target_name: str | None = None
    compatibility_status: CompatibilityStatus
    render_eligible: bool
    blocking: bool
    reasons: list[str] = Field(default_factory=list)
    required_mappings: list[str] = Field(default_factory=list)
    dependencies: list[str] = Field(default_factory=list)
    capability_refs: list[str] = Field(default_factory=list)
    documentation_refs: list[str] = Field(default_factory=list)
    source_evidence_refs: list[str] = Field(default_factory=list)
    target_evidence_refs: list[str] = Field(default_factory=list)
    renderer_capability_id: str | None = None
    version_status: str = "VERSION_NOT_VERIFIED"
    preserved_semantics: list[str] = Field(default_factory=list)
    lost_semantics: list[str] = Field(default_factory=list)
    required_context: list[str] = Field(default_factory=list)


class BlockedPlanRecord(BaseModel):
    entity_id: str | None = None
    reason: str


class MigrationPlanArtifact(BaseModel):
    schema_: str = Field(alias="schema", serialization_alias="schema")
    plan_id: str
    source: PlanVersionContext
    target: PlanVersionContext
    context: MigrationMappings
    summary: PlanSummary
    mappings: list[NameMapping]
    entities: list[EntityPlanRecord]
    blocked: list[BlockedPlanRecord]
    advisories: list[str]
    documentation_refs: list[str]


def _version(vendor, context):
    exact = context.selected_version if context else None
    profile = exact_profile(vendor, exact) if exact else None
    return PlanVersionContext(
        vendor=vendor,
        family=context.selected_family if context else None,
        exact_version=exact,
        verification_state=profile.version_status.value if profile else "VERSION_NOT_VERIFIED",
    )


def _dependencies(cfg: FirewallConfig | None):
    if not cfg:
        return {}
    graph = DependencyGraphBuilder().build(cfg)
    result = {}
    for node, data in graph.nodes(data=True):
        entity_id = data["dto"].object_id
        values = [graph.nodes[target]["dto"].object_id for target in graph.successors(node)]
        if values:
            result[entity_id] = sorted(set(values))
    return result


def canonical_json(value) -> str:
    payload = value.model_dump(mode="json", by_alias=True) if isinstance(value, BaseModel) else TypeAdapter(type(value)).dump_python(value, mode="json")
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def build_plan_artifact(plan: MigrationPlan, cfg: FirewallConfig | None = None) -> MigrationPlanArtifact:
    names = {item.entity_id: item for item in plan.names}
    eligible = {item.entity_id for item in plan.generate}
    dependencies = _dependencies(cfg)
    positions = {item.entity_id: item.source_semantic.get("position") or 0 for item in plan.compatibility}
    records = []
    for item in plan.compatibility:
        records.append(EntityPlanRecord(
            entity_id=item.entity_id,
            entity_type=item.entity_type,
            source_name=item.source_name,
            target_name=names[item.entity_id].target_name if item.entity_id in names else None,
            compatibility_status=item.status,
            render_eligible=item.entity_id in eligible,
            blocking=item.blocking or item.entity_id not in eligible,
            reasons=sorted(item.reasons),
            required_mappings=sorted(item.required_mappings),
            dependencies=dependencies.get(item.entity_id, []),
            capability_refs=sorted(item.capability_refs),
            documentation_refs=sorted(item.documentation_refs),
            source_evidence_refs=sorted(item.source_evidence_refs),
            target_evidence_refs=sorted(item.target_evidence_refs),
            renderer_capability_id=item.renderer_capability_id,
            version_status=item.version_status,
            preserved_semantics=sorted(item.preserved_semantics),
            lost_semantics=sorted(item.lost_semantics),
            required_context=sorted(item.required_context),
        ))
    records.sort(key=lambda x: (x.entity_type, positions[x.entity_id] if x.entity_type in {"security_policy", "nat_policy"} else 0, x.entity_id, x.source_name))
    counts = {status: sum(x.compatibility_status == status for x in records) for status in CompatibilityStatus}
    summary = PlanSummary(
        total_entities=len(records), render_eligible=sum(x.render_eligible for x in records),
        exact=counts[CompatibilityStatus.EXACT], supported=counts[CompatibilityStatus.SUPPORTED],
        partial=counts[CompatibilityStatus.PARTIAL], manual_review=counts[CompatibilityStatus.MANUAL_REVIEW],
        unsupported=counts[CompatibilityStatus.UNSUPPORTED], version_not_verified=counts[CompatibilityStatus.VERSION_NOT_VERIFIED],
        blocked=sum(x.blocking for x in records),
    )
    blocked = [BlockedPlanRecord(reason=reason) for reason in sorted(plan.blocked)]
    blocked += [BlockedPlanRecord(entity_id=x.entity_id, reason="; ".join(x.reasons) or x.compatibility_status.value) for x in records if x.blocking]
    semantic = {
        "schema": SCHEMA, "source": _version(plan.source_vendor, plan.source_version),
        "target": _version(plan.target_vendor, plan.target_version), "context": plan.mappings,
        "summary": summary, "mappings": sorted(plan.names, key=lambda x: (x.entity_id, x.source_name)),
        "entities": records, "blocked": blocked, "advisories": sorted(plan.advisories),
        "documentation_refs": sorted({ref for item in records for ref in item.documentation_refs}),
    }
    plan_id = "sha256:" + hashlib.sha256(canonical_json(semantic).encode("utf-8")).hexdigest()
    return MigrationPlanArtifact(plan_id=plan_id, **semantic)


def serialize_plan_artifact(artifact: MigrationPlanArtifact, indent: int | None = 2) -> str:
    if indent is None:
        return canonical_json(artifact)
    return json.dumps(artifact.model_dump(mode="json", by_alias=True), sort_keys=True, indent=indent, ensure_ascii=False) + "\n"