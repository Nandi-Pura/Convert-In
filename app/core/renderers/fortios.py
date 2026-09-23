import ipaddress
import re

from app.core.migration.models import CompatibilityStatus,FortiOSCommand,FortiOSOperation
from app.core.migration.report import build_report

_SAFE=re.compile(r"[A-Za-z0-9._:/,-]+")
_NAME=re.compile(r"[A-Za-z0-9._-]{1,79}")


def encode_fortios_value(value:str)->str:
    if any(ord(c)<32 or ord(c)==127 for c in value):
        raise ValueError("FortiOS value contains a control character")
    if _SAFE.fullmatch(value):
        return value
    return '"'+value.replace("\\","\\\\").replace('"','\\"')+'"'


class FortiOSRenderer:
    domain="FIREWALL"; vendor="FORTINET"; platform="FORTIGATE"; version="7.6.4"

    def render(self,plan,target_profile=None):
        if target_profile is None and plan.target_version:
            from app.core.versions import version_profile
            target_profile=version_profile(plan.target_vendor,plan.target_version.selected_family)
        if not target_profile or target_profile.id!="fortios-7.6.4":
            self.commands=[]
            return [],build_report(plan,(),["Exact FortiOS 7.6.4 target profile is required."])
        compatibility={x.entity_id:x for x in plan.compatibility}; generated=set(); errors=[]; commands=[]
        sections={"address":"firewall address","address_group":"firewall addrgrp","service":"firewall service custom","service_group":"firewall service group","route":"router static","security_policy":"firewall policy"}
        policy_id=0; route_id=0
        for entity in plan.generate:
            evidence=compatibility[entity.entity_id]
            try:
                if evidence.status not in {CompatibilityStatus.EXACT,CompatibilityStatus.SUPPORTED} or evidence.version_status!="VERIFIED" or not evidence.renderer_support or not evidence.target_evidence_refs:
                    raise ValueError("complete CP2 target evidence required")
                if not _NAME.fullmatch(entity.target_name):
                    raise ValueError("unsupported FortiOS object name")
                d=entity.data; operations=[]; edit_key=entity.target_name
                if entity.entity_type=="address":
                    if d["type"]=="range":
                        start,end=d["value"].split("-",1); ipaddress.IPv4Address(start); ipaddress.IPv4Address(end)
                        operations=[FortiOSOperation(key="type",values=["iprange"]),FortiOSOperation(key="start-ip",values=[start]),FortiOSOperation(key="end-ip",values=[end])]
                    else:
                        network=ipaddress.IPv4Network(d["value"],strict=False)
                        operations=[FortiOSOperation(key="subnet",values=[str(network.network_address),str(network.netmask)])]
                elif entity.entity_type in {"address_group","service_group"}:
                    operations=[FortiOSOperation(key="member",values=d["members"])]
                elif entity.entity_type=="service":
                    if d["protocol"] not in {"tcp","udp"}: raise ValueError("unsupported service protocol")
                    operations=[FortiOSOperation(key=f'{d["protocol"]}-portrange',values=d["ports"])]
                elif entity.entity_type=="security_policy":
                    policy_id+=1; edit_key=str(policy_id)
                    operations=[FortiOSOperation(key="name",values=[entity.target_name]),FortiOSOperation(key="srcintf",values=d["from"]),FortiOSOperation(key="dstintf",values=d["to"]),FortiOSOperation(key="srcaddr",values=d["source"]),FortiOSOperation(key="dstaddr",values=d["destination"]),FortiOSOperation(key="action",values=["accept" if d["action"]=="allow" else "deny"]),FortiOSOperation(key="schedule",values=["always"]),FortiOSOperation(key="service",values=d["service"])]
                    if not d["enabled"]: operations.append(FortiOSOperation(key="status",values=["disable"]))
                    if d.get("description"): operations.append(FortiOSOperation(key="comments",values=[d["description"]]))
                elif entity.entity_type=="route":
                    route_id+=1; edit_key=str(route_id); network=ipaddress.IPv4Network(d["destination"],strict=False); ipaddress.IPv4Address(d["next_hop"])
                    operations=[FortiOSOperation(key="dst",values=[str(network.network_address),str(network.netmask)]),FortiOSOperation(key="gateway",values=[d["next_hop"]]),FortiOSOperation(key="device",values=[d["interface"]])]
                else: continue
                command=FortiOSCommand(entity_id=entity.entity_id,source_entity_id=entity.entity_id,section=sections[entity.entity_type],edit_key=edit_key,operations=operations,capability_id=evidence.renderer_capability_id,evidence_refs=evidence.target_evidence_refs)
                body=[f"    edit {encode_fortios_value(edit_key)}",*(f"        {op.verb} {encode_fortios_value(op.key)} {' '.join(encode_fortios_value(v) for v in op.values)}" for op in operations),"    next"]
                command.text="\n".join(body); commands.append(command); generated.add(entity.entity_id)
            except (KeyError,TypeError,ValueError) as exc: errors.append(f"{entity.entity_id}: {exc}")
        self.commands=commands
        lines=[]
        for section in sections.values():
            items=[x for x in commands if x.section==section]
            if items: lines.extend([f"config {section}",*(line for item in items for line in item.text.splitlines()),"end"])
        return lines,build_report(plan,generated,errors)