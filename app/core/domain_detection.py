from dataclasses import dataclass
from app.core.models import ConfigDomain

@dataclass(frozen=True)
class DomainDetection:
    primary: ConfigDomain|None
    capabilities: frozenset[ConfigDomain]
    ambiguous: bool=False

def detect_domain(text:str)->DomainDetection:
    value=text.lower()
    scores={ConfigDomain.FIREWALL:sum(x in value for x in ("security policies","security zones","asa version","config firewall policy")),ConfigDomain.ROUTER:sum(x in value for x in ("protocols bgp","router bgp","router ospf","routing-options")),ConfigDomain.SWITCH:sum(x in value for x in ("ethernet-switching","switchport","port link-type","vlan "))}
    active=frozenset(k for k,v in scores.items() if v)
    if not active:return DomainDetection(None,active)
    best=max(scores.values()); winners=[k for k,v in scores.items() if v==best]
    return DomainDetection(winners[0] if len(winners)==1 else None,active,len(winners)>1)