import hashlib
import json
import os
import tempfile
from collections import Counter
from enum import StrEnum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field
from pydantic_core import to_jsonable_python

from app.core.migration.models import CompatibilityStatus

SCHEMA = "convert-in.semantic-diff/v2"
SET_FIELDS = {"members", "allowed_vlans", "source_zones", "destination_zones", "sources", "destinations", "services", "original_source", "original_destination", "translated_source", "translated_destination"}
IGNORE_FIELDS = {"id", "provenance", "vendor_extensions", "tags"}


class DiffClassification(StrEnum):
    PRESERVED = "PRESERVED"
    CHANGED = "CHANGED"
    LOST = "LOST"
    REVIEW = "REVIEW"


class PropertyDiff(BaseModel):
    property: str
    classification: DiffClassification
    source_value: Any = None
    target_value: Any = None
    evidence_ids: list[str] = Field(default_factory=list)
    reason: str
    required_action: str | None = None
    preserved_semantics: list[str] = Field(default_factory=list)
    lost_semantics: list[str] = Field(default_factory=list)


class EntityDiff(BaseModel):
    entity_id: str
    domain: str
    entity_type: str
    source_identity: str
    target_identity: str | None = None
    source_lineage: dict[str, Any] | None = None
    cp2_decision_id: str | None = None
    overall_classification: DiffClassification
    property_diffs: list[PropertyDiff]
    notes: list[str] = Field(default_factory=list)
    related_entity_ids: list[str] = Field(default_factory=list)


class SemanticDiffArtifact(BaseModel):
    schema_: str = Field(alias="schema", serialization_alias="schema")
    project_id: str | None = None
    source: dict[str, Any]
    target: dict[str, Any]
    summary: dict[str, int]
    entities: list[EntityDiff]
    state_fingerprint: str
    fingerprint: str


def canonical_json(value):
    payload = value.model_dump(mode="json", by_alias=True) if hasattr(value, "model_dump") else to_jsonable_python(value)
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _canonical_value(name, value):
    if name in SET_FIELDS and isinstance(value, list):
        return sorted(value, key=lambda item: canonical_json(item))
    return value


def _lineage(entity):
    provenance = getattr(entity, "provenance", None)
    return provenance.model_dump(mode="json", exclude_none=True) if provenance else None


def _properties(entity):
    return entity.model_dump(mode="json", exclude=IGNORE_FIELDS, exclude_none=True)


def _overall(properties):
    states = {item.classification for item in properties}
    for state in (DiffClassification.REVIEW, DiffClassification.LOST, DiffClassification.CHANGED):
        if state in states:
            return state
    return DiffClassification.PRESERVED if properties else DiffClassification.REVIEW


def state_fingerprint(cfg, cp2, source, target, mappings=None, review=None):
    state = {"ir": cfg.model_dump(mode="json"), "cp2": [x.model_dump(mode="json") for x in cp2], "source": source, "target": target, "mappings": mappings or {}, "review": review or {}}
    return "sha256:" + hashlib.sha256(canonical_json(state).encode()).hexdigest()


def build_semantic_diff(cfg, cp2, source, target, *, project_id=None, mappings=None, review=None):
    domain = getattr(getattr(cfg, "domain", None), "value", None) or source["domain"]
    entity_lists = ("interfaces", "zones", "addresses", "address_groups", "services", "service_groups", "security_policies", "nat_policies", "static_routes", "vpn_objects", "vlans", "ports", "lags", "svis", "vrfs", "prefix_lists", "route_policies", "ospf_processes")
    entities = {x.id: x for name in entity_lists for x in getattr(cfg, name, [])}
    for process in getattr(cfg, "bgp_processes", []):
        entities.update((x.id, x) for x in process.neighbors)
    output = []
    for decision in cp2:
        entity = entities[decision.entity_id]; source_values = decision.source_semantic or _properties(entity); target_values = decision.target_semantic or {}
        target_name = next((x.get("target_identity") or x.get("target_interface") for x in (mappings or {}).get("interfaces", []) if x.get("source_entity_id") == entity.id and x.get("confirmed")), None)
        property_diffs = []
        for name, raw_source in sorted(_properties(entity).items()):
            source_value = _canonical_value(name, raw_source); target_value = _canonical_value(name, target_values.get(name))
            evidence = sorted(set(decision.source_evidence_refs + decision.target_evidence_refs + decision.documentation_refs + decision.test_refs))
            if decision.entity_type == "nat_policy":
                classification, reason = DiffClassification.REVIEW, "NAT rendering remains non-emitting; target equivalence is not proven."
            elif decision.status in {CompatibilityStatus.VERSION_NOT_VERIFIED, CompatibilityStatus.MANUAL_REVIEW}:
                classification, reason = DiffClassification.REVIEW, "; ".join(decision.reasons) or decision.status.value
            elif name in decision.lost_semantics and decision.status == CompatibilityStatus.UNSUPPORTED:
                classification, reason = DiffClassification.LOST, "CP2 explicitly records this semantic as unsupported."
            elif name == "name" and target_name and target_name != source_value:
                target_value = target_name; classification, reason = DiffClassification.CHANGED, "Confirmed mapping preserves identity under a different target name."
            elif name in decision.preserved_semantics and name in target_values:
                classification = DiffClassification.PRESERVED if source_value == target_value else DiffClassification.CHANGED
                reason = "CP2 property evidence confirms equivalent modeled meaning." if classification == DiffClassification.PRESERVED else "CP2 records an explicit target transformation."
            else:
                classification, reason = DiffClassification.REVIEW, "Property-level target equivalence is not proven by existing CP2 metadata."
            property_diffs.append(PropertyDiff(property=name, classification=classification, source_value=source_value, target_value=target_value, evidence_ids=evidence, reason=reason, required_action="Review target behavior and mapping." if classification == DiffClassification.REVIEW else None, preserved_semantics=[name] if classification == DiffClassification.PRESERVED else [], lost_semantics=[name] if classification == DiffClassification.LOST else []))
        property_diffs.sort(key=lambda item: item.property)
        output.append(EntityDiff(entity_id=hashlib.sha256(f"{domain}|{decision.entity_type}|{entity.id}".encode()).hexdigest()[:16], domain=domain, entity_type=decision.entity_type, source_identity=entity.name, target_identity=target_name, source_lineage=_lineage(entity), cp2_decision_id=decision.decision_id or None, overall_classification=_overall(property_diffs), property_diffs=property_diffs, notes=sorted(decision.reasons)))
    output.sort(key=lambda item: (item.domain, item.entity_type, item.entity_id))
    counts = Counter(prop.classification.value.lower() for item in output for prop in item.property_diffs)
    semantic = {"schema": SCHEMA, "project_id": project_id, "source": source, "target": target, "summary": {"entities_total": len(output), "properties_total": sum(len(x.property_diffs) for x in output), "preserved": counts["preserved"], "changed": counts["changed"], "lost": counts["lost"], "review": counts["review"]}, "entities": output, "state_fingerprint": state_fingerprint(cfg, cp2, source, target, mappings, review)}
    fingerprint = "sha256:" + hashlib.sha256(canonical_json(semantic).encode()).hexdigest()
    return SemanticDiffArtifact(**semantic, fingerprint=fingerprint)


def serialize_semantic_diff(artifact):
    return json.dumps(artifact.model_dump(mode="json", by_alias=True), sort_keys=True, indent=2, ensure_ascii=False) + "\n"


def atomic_write(path: Path, content: str):
    path.parent.mkdir(exist_ok=True)
    fd, temporary = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(content); stream.flush(); os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary): os.unlink(temporary)