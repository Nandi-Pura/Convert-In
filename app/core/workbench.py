from collections import Counter, defaultdict
from enum import StrEnum

from app.core.migration import MigrationPlanner, default_mappings
from app.core.migration.registry import SUPPORTED_MIGRATION_PAIRS
from app.core.models import RouterConfig, Vendor
from app.core.parsing import parse_config
from app.core.platforms import PLATFORM_PROFILES, Platform
from app.core.reference_integrity import ReferenceIntegrityValidator
from app.core.renderers import PaloAltoRenderer
from app.core.router_assurance import RouterReferenceIntegrityValidator
from app.core.versions import resolve_context


class WorkbenchMode(StrEnum):
    CONVERT="CONVERT"; ANALYZE="ANALYZE"


LABELS={Vendor.ASA:"Cisco ASA",Vendor.FORTIGATE:"FortiGate",Vendor.JUNIPER_SRX:"Juniper SRX",Vendor.CISCO_IOSXE:"Cisco"}
TYPE_LABELS={"address":"Address","address_group":"Address Group","service":"Service","service_group":"Service Group","security_policy":"Security Rule","nat_policy":"NAT Rule","route":"Static Route","interface":"Interface","vrf":"VRF","prefix_list":"Prefix List","route_policy":"Route Map","ospf_process":"OSPF Process","bgp_neighbor":"BGP Neighbor"}


def capability(vendor:Vendor):
    platform=next((x for x in PLATFORM_PROFILES if x.parser and ((vendor==Vendor.CISCO_IOSXE and x.platform==Platform.IOS_XE) or (vendor==Vendor.ASA and x.platform==Platform.ASA) or (vendor==Vendor.FORTIGATE and x.platform==Platform.FORTIGATE) or (vendor==Vendor.JUNIPER_SRX and x.platform==Platform.SRX))),None)
    convertible=(vendor,Vendor.PALO_ALTO) in SUPPORTED_MIGRATION_PAIRS
    return WorkbenchMode.CONVERT if convertible else WorkbenchMode.ANALYZE,platform


def _snippet(lines,entity):
    line=getattr(getattr(entity,"provenance",None),"source_line",None)
    return lines[line-1] if line and line<=len(lines) else entity.name


def _normalized(entity):
    data=entity.model_dump(exclude={"id","provenance","vendor_extensions"},exclude_none=True)
    return "\n".join(f"{k.replace('_',' ').title()}: {', '.join(map(str,v)) if isinstance(v,list) else v}" for k,v in data.items())


def build(text:str,vendor:Vendor,source_version:str,target_version:str="11.1"):
    mode,profile=capability(vendor); cfg=parse_config(text,vendor); lines=text.splitlines()
    if mode==WorkbenchMode.ANALYZE:
        if not isinstance(cfg,RouterConfig): raise ValueError("No analysis workbench is registered for this platform.")
        integrity=RouterReferenceIntegrityValidator().validate(cfg); findings=defaultdict(list)
        for finding in integrity.findings: findings[finding.source_entity_id].append(finding.reason+f" {finding.referenced_entity_name or ''}".rstrip())
        collections=(("interface",cfg.interfaces),("vrf",cfg.vrfs),("route",cfg.static_routes),("prefix_list",cfg.prefix_lists),("route_policy",cfg.route_policies),("ospf_process",cfg.ospf_processes),("bgp_neighbor",[n for p in cfg.bgp_processes for n in p.neighbors]))
        entities=[]
        for kind,items in collections:
            for entity in items:
                related_ids=[key for key in integrity.entity_statuses if key==entity.id or key.startswith(f"{entity.id}:")]
                blocked=any(integrity.entity_statuses[key]=="BLOCKED" for key in related_ids)
                related_findings=[message for key in related_ids for message in findings[key]]
                entities.append(_row(entity,kind,_snippet(lines,entity),_normalized(entity),"BLOCKED" if blocked else "READY","CP1: BLOCKED" if blocked else "CP1: PASS",related_findings))
        return _result(mode,vendor,profile,source_version,None,cfg.extraction_coverage,integrity,None,entities,None)
    integrity=ReferenceIntegrityValidator().validate(cfg); source=resolve_context(text,vendor,source_version); target=resolve_context("",Vendor.PALO_ALTO,target_version)
    plan=MigrationPlanner().plan(cfg,default_mappings(cfg),source,target,integrity); renderer=PaloAltoRenderer(); candidate,_=renderer.render(plan)
    commands=defaultdict(list)
    for command in renderer.commands: commands[command.entity_id].append(command.text)
    source_entities={x.id:x for xs in (cfg.interfaces,cfg.zones,cfg.addresses,cfg.address_groups,cfg.services,cfg.service_groups,cfg.security_policies,cfg.nat_policies,cfg.static_routes,cfg.vpn_objects) for x in xs}
    names={x.entity_id:x.target_name for x in plan.names}; entities=[]
    for item in plan.compatibility:
        emitted=commands[item.entity_id]; ready=bool(emitted) and item.status in {"EXACT","SUPPORTED"} and not item.blocking
        status="READY" if ready else "BLOCKED" if item.status in {"UNSUPPORTED","VERSION_NOT_VERIFIED"} or item.related_cp1_findings else "REVIEW REQUIRED"
        detail=f"CP2: {item.status.value}"; reasons=item.reasons or (["Intent preserved"] if ready else ["No generated target config"])
        entities.append(_row(source_entities[item.entity_id],item.entity_type,_snippet(lines,source_entities[item.entity_id]),"\n".join(emitted) or "No generated target config",status,detail,reasons,names.get(item.entity_id),emitted))
    cp2=Counter(x.status.value for x in plan.compatibility)
    return _result(mode,vendor,profile,source_version,target_version,cfg.extraction_coverage,integrity,dict(cp2),entities,"\n".join(candidate)+"\n")


def _row(entity,kind,source,target,status,detail,findings,target_title=None,commands=None):
    return {"id":entity.id,"entity_type":TYPE_LABELS.get(kind,kind.replace("_"," ").title()),"source_title":entity.name,"source_snippet":source,"target_title":target_title,"target_snippet":target,"user_status":status,"detailed_status":detail,"copyable":status=="READY" and bool(commands),"findings":findings,"semantic_fields":[],"commands":commands or []}


def _result(mode,vendor,profile,source_version,target_version,cp0,cp1,cp2,entities,candidate):
    return {"mode":mode,"source_profile":{"vendor":LABELS[vendor],"platform":profile.os_family if profile else vendor.value,"domain":profile.domain.value if profile else "FIREWALL","version":source_version},"target_profile":{"vendor":"Palo Alto Networks","platform":"PAN-OS","version":target_version} if mode==WorkbenchMode.CONVERT else None,"cp0_summary":cp0.model_dump(mode="json"),"cp1_summary":cp1.model_dump(mode="json"),"cp2_summary":cp2,"entities":entities,"candidate":candidate}