from enum import StrEnum
from pydantic import BaseModel,Field
from app.core.models import ConfigDomain,Vendor

class VersionConfidence(StrEnum): HIGH="HIGH"; MEDIUM="MEDIUM"; LOW="LOW"; NONE="NONE"
class VersionDetectionStatus(StrEnum): EXACT="EXACT"; FAMILY_ONLY="FAMILY_ONLY"; UNKNOWN="UNKNOWN"; USER_SELECTED="USER_SELECTED"; USER_OVERRIDE="USER_OVERRIDE"
class CapabilityStatus(StrEnum):
    DOCUMENTED_IMPLEMENTED_TESTED="DOCUMENTED_IMPLEMENTED_TESTED"
    DOCUMENTED_IMPLEMENTED_UNTESTED="DOCUMENTED_IMPLEMENTED_UNTESTED"
    DOCUMENTED_NOT_IMPLEMENTED="DOCUMENTED_NOT_IMPLEMENTED"
    IMPLEMENTED_NOT_DOCUMENTATION_VERIFIED="IMPLEMENTED_NOT_DOCUMENTATION_VERIFIED"
    VERSION_NOT_VERIFIED="VERSION_NOT_VERIFIED"
    NOT_APPLICABLE="NOT_APPLICABLE"
    UNKNOWN="UNKNOWN"
class VersionStatus(StrEnum):
    LATEST_VERIFIED="LATEST_VERIFIED"
    LEGACY_VERIFIED="LEGACY_VERIFIED"
    VERSION_NOT_VERIFIED="VERSION_NOT_VERIFIED"

class VendorVersion(BaseModel): vendor:Vendor; os_name:str; value:str
class VersionFamily(BaseModel): vendor:Vendor; os_name:str; value:str
class Capability(BaseModel):
    status:CapabilityStatus; documentation_refs:list[str]=Field(default_factory=list); syntax_variant:str|None=None; limitation:str|None=None
    target_match_semantics_documented:bool=False; target_translation_semantics_documented:bool=False; route_lookup_semantics_documented:bool=False
    renderer_support:bool=False; test_refs:list[str]=Field(default_factory=list)

class EvidenceState(BaseModel):
    source_semantic_documented:bool=False; target_match_semantics_documented:bool=False; target_translation_semantics_documented:bool=False
    target_cli_documented:bool=False; route_lookup_semantics_documented:bool=False; renderer_syntax_verified:bool=False
    ordering_verified:bool=False; placement_verified:bool=False
    mapping_verified:bool=False; tests_verified:bool=False; version_verified:bool=False
    @property
    def complete(self): return all(self.model_dump().values())

class CommandContext(StrEnum):
    LOCAL_VSYS="LOCAL_VSYS"; PANORAMA_DEVICE_GROUP="PANORAMA_DEVICE_GROUP"; PRE_RULEBASE="PRE_RULEBASE"; POST_RULEBASE="POST_RULEBASE"

class CommandCapability(BaseModel):
    id:str; entity_type:str; operation:str; target_profile:str
    documentation_refs:list[str]=Field(default_factory=list)
    syntax_verified:bool=False; semantic_verified:bool=False; tests:list[str]=Field(default_factory=list)
    contexts:list[CommandContext]=Field(default_factory=list)
    @property
    def verified(self): return self.syntax_verified and self.semantic_verified and bool(self.documentation_refs) and bool(self.tests)
class VersionProfile(BaseModel):
    id:str; vendor:Vendor; os_name:str; version_family:str; documentation_refs:list[str]=Field(default_factory=list)
    capabilities:dict[str,Capability]=Field(default_factory=dict); syntax_variants:dict[str,str]=Field(default_factory=dict); known_limitations:list[str]=Field(default_factory=list); tested:bool=False
    platform:str|None=None; domain:ConfigDomain=ConfigDomain.FIREWALL; release_line:str|None=None; exact_version:str|None=None
    display_version:str|None=None; version_status:VersionStatus=VersionStatus.VERSION_NOT_VERIFIED; latest_in_line:bool=False
    release_date:str|None=None; release_evidence_ids:list[str]=Field(default_factory=list); source_parser_available:bool=False
    target_renderer_available:bool=False; target_capability:str="TARGET_NOT_IMPLEMENTED"; documentation_profile:list[str]=Field(default_factory=list)
    capability_ids:list[str]=Field(default_factory=list); audited_at:str|None=None; rank:int=0
class VersionDetectionResult(BaseModel):
    vendor:Vendor; os_name:str; detected_version:str|None=None; detected_family:str|None=None
    status:VersionDetectionStatus=VersionDetectionStatus.UNKNOWN; method:str="none"; confidence:VersionConfidence=VersionConfidence.NONE
class VersionContext(BaseModel):
    vendor:Vendor; os_name:str; detected_version:str|None=None; detected_family:str|None=None
    selected_version:str|None=None; selected_family:str|None=None; detection_method:str="none"
    confidence:VersionConfidence=VersionConfidence.NONE; override:bool=False; override_timestamp:str|None=None