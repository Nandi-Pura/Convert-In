import ipaddress
import re

from app.core.migration.models import AsaCommand,CompatibilityStatus
from app.core.migration.report import build_report

_TOKEN=re.compile(r"[A-Za-z0-9._-]{1,64}")
_PORT=re.compile(r"(?:[1-9]\d{0,4}|0)(?:-(?:[1-9]\d{0,4}|0))?")


def asa_token(value:str)->str:
    if not _TOKEN.fullmatch(value): raise ValueError("unsupported ASA token")
    return value


class AsaRenderer:
    domain="FIREWALL"; vendor="CISCO"; platform="ASA"; version="9.24"

    def render(self,plan,target_profile=None):
        if target_profile is None and plan.target_version:
            from app.core.versions import target_version_profile
            target_profile=target_version_profile(plan.target_vendor,plan.target_version.selected_family)
        if not target_profile or target_profile.id!="asa-9.24-target":
            self.commands=[]
            return [],build_report(plan,(),["Exact Cisco ASA 9.24 target profile is required."])
        compatibility={x.entity_id:x for x in plan.compatibility}; commands=[]; generated=set(); errors=[]
        for entity in plan.generate:
            evidence=compatibility[entity.entity_id]
            try:
                if entity.entity_type not in {"address","address_group","service","service_group"}: continue
                if evidence.status not in {CompatibilityStatus.EXACT,CompatibilityStatus.SUPPORTED} or evidence.version_status!="VERIFIED" or not evidence.renderer_support or not evidence.target_evidence_refs: raise ValueError("complete CP2 target evidence required")
                name=asa_token(entity.target_name); d=entity.data; operations=[]
                if entity.entity_type=="address":
                    if d["type"]=="range":
                        start,end=d["value"].split("-",1); ipaddress.IPv4Address(start); ipaddress.IPv4Address(end); operations=[["range",start,end]]
                    else:
                        network=ipaddress.IPv4Network(d["value"],strict=False)
                        operations=[["host",str(network.network_address)]] if network.prefixlen==32 else [["subnet",str(network.network_address),str(network.netmask)]]
                    mode="object network"
                elif entity.entity_type=="address_group":
                    operations=[["group-object",asa_token(member)] if kind=="group" else ["network-object","object",asa_token(member)] for member,kind in zip(d["members"],d["member_types"],strict=True)]; mode="object-group network"
                elif entity.entity_type=="service":
                    port=d["ports"][0]
                    if not _PORT.fullmatch(port): raise ValueError("unsupported ASA port expression")
                    values=["range",*port.split("-",1)] if "-" in port else ["eq",port]
                    if any(not 0<=int(x)<=65535 for x in values[1:]): raise ValueError("ASA port outside 0-65535")
                    operations=[["service",asa_token(d["protocol"]),"destination",*values]]; mode="object service"
                else:
                    operations=[["group-object",asa_token(member)] if kind=="group" else ["service-object","object",asa_token(member)] for member,kind in zip(d["members"],d["member_types"],strict=True)]; mode="object-group service"
                text="\n".join([f"{mode} {name}",*(" "+" ".join(operation) for operation in operations)])
                commands.append(AsaCommand(entity_id=entity.entity_id,source_entity_id=entity.entity_id,mode=mode,name=name,operations=operations,capability_id=evidence.renderer_capability_id,evidence_refs=evidence.target_evidence_refs,text=text)); generated.add(entity.entity_id)
            except (KeyError,TypeError,ValueError) as exc: errors.append(f"{entity.entity_id}: {exc}")
        self.commands=commands
        return [line for command in commands for line in command.text.splitlines()],build_report(plan,generated,errors)