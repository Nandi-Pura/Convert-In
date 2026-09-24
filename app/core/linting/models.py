from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

from app.core.models import ConfigDomain


class LintSeverity(StrEnum):
    INFO = "INFO"
    WARNING = "WARNING"
    BLOCKING = "BLOCKING"


class SourceLineage(BaseModel):
    source_line: int | None = None
    source_section: str | None = None


class LintFinding(BaseModel):
    id: str
    domain: ConfigDomain
    severity: LintSeverity
    category: str
    rule_id: str
    title: str
    description: str
    entity_type: str
    entity_id: str
    related_entity_ids: list[str] = Field(default_factory=list)
    evidence: dict[str, Any] = Field(default_factory=dict)
    deterministic: bool = True
    suggested_action: str | None = None
    source_lineage: SourceLineage | None = None


class LintSummary(BaseModel):
    total: int
    blocking: int
    warning: int
    info: int
    by_domain: dict[str, int] = Field(default_factory=dict)
    by_rule_id: dict[str, int] = Field(default_factory=dict)


class LintArtifact(BaseModel):
    schema_: str = Field(alias="schema", serialization_alias="schema")
    project_id: str | None = None
    findings: list[LintFinding]
    summary: LintSummary
    fingerprint: str