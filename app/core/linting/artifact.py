import hashlib
import json
from collections import Counter
from pydantic_core import to_jsonable_python

from .models import LintArtifact, LintSeverity, LintSummary

SCHEMA="convert-in.lint-findings/v1"
RANK={LintSeverity.BLOCKING:0,LintSeverity.WARNING:1,LintSeverity.INFO:2}


def canonical_json(value):
    payload=value.model_dump(mode="json",by_alias=True) if hasattr(value,"model_dump") else to_jsonable_python(value)
    return json.dumps(payload,sort_keys=True,separators=(",",":"),ensure_ascii=False)


def build_lint_artifact(findings,project_id=None):
    findings=sorted(findings,key=lambda x:(x.domain.value,RANK[x.severity],x.rule_id,x.entity_type,x.entity_id,x.id))
    severity=Counter(x.severity for x in findings); domains=Counter(x.domain.value for x in findings); rules=Counter(x.rule_id for x in findings)
    summary=LintSummary(total=len(findings),blocking=severity[LintSeverity.BLOCKING],warning=severity[LintSeverity.WARNING],info=severity[LintSeverity.INFO],by_domain=dict(sorted(domains.items())),by_rule_id=dict(sorted(rules.items())))
    semantic={"schema":SCHEMA,"project_id":project_id,"findings":findings,"summary":summary}
    fingerprint="sha256:"+hashlib.sha256(canonical_json(semantic).encode()).hexdigest()
    return LintArtifact(**semantic,fingerprint=fingerprint)


def serialize_lint_artifact(artifact):
    return json.dumps(artifact.model_dump(mode="json",by_alias=True),sort_keys=True,indent=2,ensure_ascii=False)+"\n"