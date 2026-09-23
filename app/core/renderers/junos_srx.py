import ipaddress
import re

from app.core.migration.models import CompatibilityStatus,JunosSrxCommand
from app.core.migration.report import build_report

_PLAIN=re.compile(r"[A-Za-z0-9._:/-]+")
_PORT=re.compile(r"(?:0|[1-9]\d{0,4})(?:-(?:0|[1-9]\d{0,4}))?")


def junos_token(value:str)->str:
    if not value or any(ord(c)<32 or ord(c)==127 for c in value): raise ValueError("unsafe Junos token")
    if _PLAIN.fullmatch(value): return value
    return '"'+value.replace("\\","\\\\").replace('"','\\"')+'"'


def _line(*tokens): return "set "+" ".join(junos_token(str(token)) for token in tokens)


class JunosSrxRenderer:
    domain="FIREWALL"; vendor="JUNIPER"; platform="SRX"; version="23.4R2"

    def render(self,plan,target_profile=None):
        if target_profile is None and plan.target_version:
            from app.core.versions import target_version_profile
            target_profile=target_version_profile(plan.target_vendor,plan.target_version.selected_family)
        if not target_profile or target_profile.id!="junos-23.4R2-srx-target":
            self.commands=[]
            return [],build_report(plan,(),["Exact Juniper SRX Junos 23.4R2 target profile is required."])
        compatibility={x.entity_id:x for x in plan.compatibility}; commands=[]; generated=set(); errors=[]
        pending={x.entity_id:x for x in plan.generate}
        order=("address","address_group","service","service_group","interface","security_policy","route")
        for kind in order:
            entities=[x for x in plan.generate if x.entity_type==kind]
            if kind=="security_policy": entities.sort(key=lambda x:x.data["position"])
            for entity in entities:
                evidence=compatibility[entity.entity_id]
                try:
                    if evidence.status not in {CompatibilityStatus.EXACT,CompatibilityStatus.SUPPORTED} or evidence.version_status!="VERIFIED" or not evidence.renderer_support or not evidence.target_evidence_refs: raise ValueError("complete CP2 target evidence required")
                    d=entity.data; name=entity.target_name; lines=[]; dependencies=[]
                    if kind=="address":
                        if d["type"]=="range":
                            start,end=d["value"].split("-",1); start=ipaddress.IPv4Address(start); end=ipaddress.IPv4Address(end)
                            if start>end: raise ValueError("address range start exceeds end")
                            lines=[_line("security","address-book","global","address",name,"range-address",str(start),"to",str(end))]
                        else:
                            network=ipaddress.IPv4Network(d["value"],strict=True)
                            lines=[_line("security","address-book","global","address",name,str(network))]
                    elif kind=="address_group":
                        if "group" in d["member_types"]: raise ValueError("nested address sets are review-only")
                        dependencies=[next(x.entity_id for x in pending.values() if x.target_name==member) for member in d["members"]]
                        lines=[_line("security","address-book","global","address-set",name,"address",member) for member in d["members"]]
                    elif kind=="service":
                        if len(d["ports"])!=1 or not _PORT.fullmatch(d["ports"][0]): raise ValueError("one destination port expression required")
                        ends=[int(x) for x in d["ports"][0].split("-")]
                        if any(x>65535 for x in ends): raise ValueError("port outside 0-65535")
                        port_tokens=[str(ends[0])] if len(ends)==1 else [str(ends[0]),"to",str(ends[1])]
                        lines=[_line("applications","application",name,"protocol",d["protocol"]),_line("applications","application",name,"destination-port",*port_tokens)]
                    elif kind=="service_group":
                        if "group" in d["member_types"]: raise ValueError("nested application sets are review-only")
                        dependencies=[next(x.entity_id for x in pending.values() if x.target_name==member) for member in d["members"]]
                        lines=[_line("applications","application-set",name,"application",member) for member in d["members"]]
                    elif kind=="interface":
                        lines=[_line("security","zones","security-zone",d["zone"],"interfaces",d["interface"])]
                    elif kind=="security_policy":
                        dependencies=list(d["dependency_ids"])
                        if any(dep not in generated for dep in dependencies): raise ValueError("policy dependency was not emitted")
                        base=("security","policies","from-zone",d["from"][0],"to-zone",d["to"][0],"policy",name)
                        lines=[*[_line(*base,"match","source-address",v) for v in d["source"]],*[_line(*base,"match","destination-address",v) for v in d["destination"]],*[_line(*base,"match","application",v) for v in d["service"]],_line(*base,"then","permit" if d["action"]=="allow" else "deny")]
                    elif kind=="route":
                        destination=ipaddress.IPv4Network(d["destination"],strict=True); next_hop=ipaddress.IPv4Address(d["next_hop"])
                        lines=[_line("routing-options","static","route",str(destination),"next-hop",str(next_hop))]
                    for text in lines:
                        commands.append(JunosSrxCommand(entity_id=entity.entity_id,source_entity_id=entity.entity_id,hierarchy=text.split()[1:-1],arguments=[text.split()[-1]],capability_id=evidence.renderer_capability_id,evidence_refs=evidence.target_evidence_refs,dependency_ids=dependencies,text=text))
                    generated.add(entity.entity_id)
                except (KeyError,StopIteration,TypeError,ValueError) as exc: errors.append(f"{entity.entity_id}: {exc}")
        self.commands=commands
        return [command.text for command in commands],build_report(plan,generated,errors)