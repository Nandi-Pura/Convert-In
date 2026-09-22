import json
from pathlib import Path
from .models import DocumentationReference

_ROOT=Path(__file__).resolve().parents[3]/"docs"/"vendor-reference"

def _load():
    refs=[]
    for path in sorted(_ROOT.glob("*.yaml")):
        refs.extend(DocumentationReference.model_validate(x) for x in json.loads(path.read_text(encoding="utf-8")))
    ids=[x.id for x in refs]
    if len(ids)!=len(set(ids)): raise ValueError("Duplicate documentation reference ID")
    return {x.id:x for x in refs}

DOCUMENTATION_REFERENCES=_load()

def documentation_reference(reference_id:str)->DocumentationReference:
    try: return DOCUMENTATION_REFERENCES[reference_id]
    except KeyError as exc: raise ValueError(f"Unknown documentation reference: {reference_id}") from exc

def validate_documentation_registry():
    allowed={"www.cisco.com","cisco.com","docs.fortinet.com","docs.paloaltonetworks.com","www.juniper.net","juniper.net"}
    errors=[]
    for ref in DOCUMENTATION_REFERENCES.values():
        if ref.official_url.host not in allowed: errors.append(f"{ref.id}: unofficial domain")
        if ref.official_url.scheme!="https": errors.append(f"{ref.id}: HTTPS required")
        if not ref.title.strip(): errors.append(f"{ref.id}: title required")
        if not ref.topic.strip(): errors.append(f"{ref.id}: topic required")
    from app.core.versions.registry import PROFILES
    for profile in PROFILES.values():
        for ref in profile.documentation_refs:
            if ref not in DOCUMENTATION_REFERENCES: errors.append(f"{profile.id}: unknown profile reference {ref}")
        for name,capability in profile.capabilities.items():
            for ref in capability.documentation_refs:
                if ref not in DOCUMENTATION_REFERENCES: errors.append(f"{profile.id}:{name}: unknown capability reference {ref}")
    return errors