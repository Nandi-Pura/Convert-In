from datetime import datetime, timezone
from enum import StrEnum
from typing import Any
from pydantic import BaseModel, Field, field_validator, model_validator
from app.core.models import Vendor
from app.core.versions.models import VersionContext

class CompatibilityStatus(StrEnum):
    EXACT="EXACT"; SUPPORTED="SUPPORTED"; PARTIAL="PARTIAL"; MANUAL_REVIEW="MANUAL_REVIEW"; UNSUPPORTED="UNSUPPORTED"; VERSION_NOT_VERIFIED="VERSION_NOT_VERIFIED"

class CompatibilityResult(BaseModel):
    entity_id:str; entity_type:str; source_name:str; status:CompatibilityStatus
    reasons:list[str]=Field(default_factory=list); required_mappings:list[str]=Field(default_factory=list); source_context:str|None=None
    topology:dict[str,Any]=Field(default_factory=dict)
    source_version:str|None=None; target_version:str|None=None; capability_refs:list[str]=Field(default_factory=list); documentation_refs:list[str]=Field(default_factory=list); version_status:str="VERSION_NOT_VERIFIED"
    decision_id:str=""; source_semantic:dict[str,Any]=Field(default_factory=dict); target_semantic:dict[str,Any]=Field(default_factory=dict)
    preserved_semantics:list[str]=Field(default_factory=list); lost_semantics:list[str]=Field(default_factory=list); required_context:list[str]=Field(default_factory=list)
    source_evidence_refs:list[str]=Field(default_factory=list); target_evidence_refs:list[str]=Field(default_factory=list)
    renderer_capability_id:str|None=None; renderer_support:bool=False; test_refs:list[str]=Field(default_factory=list)
    blocking:bool=True; related_cp1_findings:list[str]=Field(default_factory=list)

class InterfaceMapping(BaseModel):
    source_interface:str; source_nameif:str|None=None; target_interface:str|None=None; target_zone:str|None=None; suggested_zone:str|None=None; confirmed:bool=False
    source_profile:str|None=None; source_version:str|None=None; target_profile:str|None=None; target_version:str|None=None; source_entity_id:str|None=None

class TargetManagementMode(StrEnum):
    LOCAL_FIREWALL="LOCAL_FIREWALL"; PANORAMA="PANORAMA"

class RulebaseScope(StrEnum):
    PRE="PRE"; POST="POST"

class SecurityRulePlacementMode(StrEnum):
    TOP="TOP"; BOTTOM="BOTTOM"; BEFORE="BEFORE"; AFTER="AFTER"

class SecurityRulePlacement(BaseModel):
    mode:SecurityRulePlacementMode; anchor_rule:str|None=None
    @model_validator(mode="after")
    def anchor_contract(self):
        needs_anchor=self.mode in {SecurityRulePlacementMode.BEFORE,SecurityRulePlacementMode.AFTER}
        if needs_anchor != bool(self.anchor_rule): raise ValueError("BEFORE/AFTER requires anchor_rule; TOP/BOTTOM forbids it")
        if self.anchor_rule and not __import__("re").fullmatch(r"[A-Za-z0-9._-]+",self.anchor_rule): raise ValueError("invalid anchor rule")
        return self

class NatRulePlacement(BaseModel):
    mode:SecurityRulePlacementMode; anchor_rule:str|None=None
    @model_validator(mode="after")
    def anchor_contract(self):
        needs_anchor=self.mode in {SecurityRulePlacementMode.BEFORE,SecurityRulePlacementMode.AFTER}
        if needs_anchor != bool(self.anchor_rule): raise ValueError("BEFORE/AFTER requires anchor_rule; TOP/BOTTOM forbids it")
        if self.anchor_rule and not __import__("re").fullmatch(r"[A-Za-z0-9._-]+",self.anchor_rule): raise ValueError("invalid anchor rule")
        return self

class NatRouteOutcome(BaseModel):
    nat_rule:str; nat_from_zone:str; nat_pre_translation_to_zone:str; security_post_translation_to_zone:str; confirmed:bool=False
    @field_validator("nat_rule","nat_from_zone","nat_pre_translation_to_zone","security_post_translation_to_zone")
    @classmethod
    def safe_name(cls,v):
        if not v.strip() or not __import__("re").fullmatch(r"[A-Za-z0-9._-]+",v): raise ValueError("invalid NAT route outcome value")
        return v

class MigrationMappings(BaseModel):
    management_mode:TargetManagementMode=TargetManagementMode.LOCAL_FIREWALL
    vsys:str="vsys1"; device_group:str|None=None; rulebase_scope:RulebaseScope|None=None; virtual_router:str="default"
    security_rule_placement:SecurityRulePlacement|None=None
    nat_rule_placement:NatRulePlacement|None=None; nat_route_outcomes:list[NatRouteOutcome]=Field(default_factory=list)
    interfaces:list[InterfaceMapping]=Field(default_factory=list)
    @model_validator(mode="before")
    @classmethod
    def legacy_mode(cls,v):
        if isinstance(v,dict) and "mode" in v and "management_mode" not in v:
            v=dict(v); v["management_mode"]="PANORAMA" if v.pop("mode")=="device_group" else "LOCAL_FIREWALL"
        return v
    @field_validator("vsys","virtual_router","device_group")
    @classmethod
    def safe_context(cls,v):
        if v is not None and (not v.strip() or not __import__("re").fullmatch(r"[A-Za-z0-9._-]+",v)): raise ValueError("invalid target context")
        return v
    @model_validator(mode="after")
    def panorama_context(self):
        if self.management_mode==TargetManagementMode.PANORAMA and not self.device_group: raise ValueError("Panorama requires device_group")
        if self.management_mode==TargetManagementMode.PANORAMA and not self.rulebase_scope: raise ValueError("Panorama requires rulebase_scope")
        names=[x.nat_rule for x in self.nat_route_outcomes]
        if len(names)!=len(set(names)): raise ValueError("duplicate NAT route outcome")
        return self

class NameMapping(BaseModel):
    entity_id:str; source_name:str; target_name:str; reason:str|None=None; collision:bool=False

class PlannedEntity(BaseModel):
    entity_id:str; entity_type:str; target_name:str; data:dict[str,Any]

class MigrationPlan(BaseModel):
    source_vendor:Vendor; target_vendor:Vendor=Vendor.PALO_ALTO; mappings:MigrationMappings
    compatibility:list[CompatibilityResult]; names:list[NameMapping]; generate:list[PlannedEntity]
    blocked:list[str]=Field(default_factory=list); advisories:list[str]=Field(default_factory=list)
    source_version:VersionContext|None=None; target_version:VersionContext|None=None

class SecurityRuleOrderRelation(StrEnum):
    TOP="TOP"; BOTTOM="BOTTOM"; BEFORE="BEFORE"; AFTER="AFTER"

class SecurityRuleOrderingAction(BaseModel):
    rule_name:str; relation:SecurityRuleOrderRelation; reference_rule:str|None=None
    target_profile:str; documentation_refs:list[str]; mechanism:str="PANOS_CONFIG_API_MOVE"; external_target_dependency:bool=False

class PolicyOrderingPlan(BaseModel):
    target_profile:str; placement:SecurityRulePlacement; source_order:list[str]
    actions:list[SecurityRuleOrderingAction]; documentation_refs:list[str]
    mechanism:str="PANOS_CONFIG_API_MOVE"; execution:str="ENGINEER_REVIEW_REQUIRED"
    @model_validator(mode="after")
    def complete_acyclic_order(self):
        names=[x.rule_name for x in self.actions]
        if len(names)!=len(set(names)): raise ValueError("duplicate ordering entry")
        if names!=self.source_order or len(names)!=len(self.source_order): raise ValueError("source-order mismatch or omitted rule")
        generated=set(names)
        for i,action in enumerate(self.actions):
            expected=self.placement.mode if i==0 else SecurityRuleOrderRelation.AFTER
            reference=self.placement.anchor_rule if i==0 else names[i-1]
            if action.relation!=expected or action.reference_rule!=reference: raise ValueError("ordering cycle, unknown rule, or invalid relation")
            if i and action.reference_rule not in generated: raise ValueError("unknown generated rule")
        return self

class CategoryCounts(BaseModel):
    objects:int=0; services:int=0; interfaces:int=0; zones:int=0; security_policies:int=0; nat_policies:int=0; routes:int=0

class MigrationReport(BaseModel):
    source_vendor:Vendor; target_vendor:Vendor; generated_at:str=Field(default_factory=lambda:datetime.now(timezone.utc).isoformat())
    total_entities:int; exact:int; supported:int; partial:int; manual_review:int; unsupported:int; version_not_verified:int=0
    categories:CategoryCounts; warnings:list[str]=Field(default_factory=list); errors:list[str]=Field(default_factory=list)
    required_mappings:list[str]=Field(default_factory=list); generated_entities:int=0; skipped_entities:int=0
    compatibility:list[CompatibilityResult]; names:list[NameMapping]
    source_version:VersionContext|None=None; target_version:VersionContext|None=None; documentation_refs:list[str]=Field(default_factory=list); version_validation_result:str="BLOCKING"
    security_rule_ordering:PolicyOrderingPlan|None=None

class PanSetCommand(BaseModel):
    operation:str="SET"; path:list[str]; values:list[str]=Field(default_factory=list); entity_id:str; text:str=""
    target_profile:str; capability_id:str; documentation_refs:list[str]
    management_context:MigrationMappings

class FortiOSOperation(BaseModel):
    verb:str="set"; key:str; values:list[str]

class FortiOSCommand(BaseModel):
    entity_id:str; source_entity_id:str; section:str; edit_key:str
    operations:list[FortiOSOperation]; capability_id:str; evidence_refs:list[str]
    text:str=""

class RenderResult(BaseModel):
    status:str; generated_lines:int; generated_entities:int; skipped_entities:int; manual_review:int; unsupported:int
    candidate_path:str|None=None; report:MigrationReport; candidate:str|None=None