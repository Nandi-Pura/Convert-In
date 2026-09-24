from collections import Counter, defaultdict
from enum import StrEnum

from app.core.migration import MigrationPlanner, default_mappings
from app.core.migration.models import MigrationMappings
from app.core.migration.registry import SUPPORTED_MIGRATION_PAIRS
from app.core.models import RouterConfig, SwitchConfig, Vendor
from app.core.parsing import parse_config
from app.core.parsing.registry import parse_profile
from app.core.platforms import platform_profile
from app.core.reference_integrity import ReferenceIntegrityValidator
from app.core.renderers import PaloAltoRenderer
from app.core.router_assurance import RouterReferenceIntegrityValidator
from app.core.versions import resolve_context
from app.core.router_migration import RouterCompatibilityEvaluator, RouterMigrationMappings
from app.core.renderers.registry import lookup_renderer
from app.core.switch_assurance import SwitchCompatibilityEvaluator, SwitchReferenceIntegrityValidator


class WorkbenchMode(StrEnum):
    CONVERT="CONVERT"; ANALYZE="ANALYZE"


LABELS={Vendor.ASA:"Cisco ASA",Vendor.FORTIGATE:"FortiGate",Vendor.JUNIPER_SRX:"Juniper SRX",Vendor.CISCO_IOSXE:"Cisco"}
TYPE_LABELS={"address":"Address","address_group":"Address Group","service":"Service","service_group":"Service Group","security_policy":"Security Rule","nat_policy":"NAT Rule","route":"Static Route","interface":"Interface","vlan":"VLAN","lag":"LAG","svi":"SVI","vrf":"VRF","prefix_list":"Prefix List","route_policy":"Route Map","ospf_process":"OSPF Process","bgp_neighbor":"BGP Neighbor"}


def _snippet(lines,entity):
    line=getattr(getattr(entity,"provenance",None),"source_line",None)
    return lines[line-1] if line and line<=len(lines) else entity.name


def _normalized(entity):
    data=entity.model_dump(exclude={"id","provenance","vendor_extensions"},exclude_none=True)
    return "\n".join(f"{k.replace('_',' ').title()}: {', '.join(map(str,v)) if isinstance(v,list) else v}" for k,v in data.items())


def build(text:str,vendor:Vendor,source_version:str,target_version:str="11.1",source_profile_id:str|None=None,target_profile_id:str="firewall-paloalto-panos",mappings:dict|None=None):
    source_profile_id=source_profile_id or {Vendor.ASA:"firewall-cisco-asa",Vendor.FORTIGATE:"firewall-fortinet-fortigate",Vendor.PALO_ALTO:"firewall-paloalto-panos",Vendor.JUNIPER_SRX:"firewall-juniper-srx",Vendor.CISCO_IOSXE:"router-cisco-iosxe"}.get(vendor)
    profile=platform_profile(source_profile_id,source_version); target_profile=platform_profile(target_profile_id,target_version)
    if not profile or not profile.source_parser:raise ValueError("Invalid source platform or version profile.")
    if not target_profile:
        target_profile=platform_profile(target_profile_id)
    if not target_profile or target_profile.domain!=profile.domain:raise ValueError("Source and target domains must match.")
    mode=WorkbenchMode.CONVERT if lookup_renderer(target_profile.domain,target_profile.vendor,target_profile.platform,target_version) else WorkbenchMode.ANALYZE
    cfg=parse_profile(text,profile.id,source_version); lines=text.splitlines()
    if isinstance(cfg,SwitchConfig):
        integrity=SwitchReferenceIntegrityValidator().validate(cfg);cp2=SwitchCompatibilityEvaluator().evaluate(cfg,profile,target_profile,mappings or {},integrity);renderer_type=lookup_renderer(target_profile.domain,target_profile.vendor,target_profile.platform,target_version);commands=defaultdict(list);candidate=None
        if renderer_type:
            renderer=renderer_type();rendered=renderer.render(cp2);candidate="\n".join(rendered)+"\n" if rendered else None
            for command in renderer.commands:commands[command.entity_id].append(command.text)
        source_entities={x.id:x for xs in (cfg.vlans,cfg.ports,cfg.lags,cfg.svis) for x in xs};entities=[]
        for item in cp2:
            emitted=commands[item.entity_id];ready=bool(emitted) and item.status in {"EXACT","SUPPORTED"};status="READY" if ready else "BLOCKED" if item.entity_id in integrity.blocked_entity_ids else "REVIEW REQUIRED";entity=source_entities[item.entity_id]
            entities.append(_row(entity,item.entity_type,_snippet(lines,entity),"\n".join(emitted) or "No generated target config",status,f"CP2: {item.status.value}",item.reasons or (["Intent preserved"] if ready else ["No generated target config"]),commands=emitted))
        return _result(mode,profile,target_profile,source_version,target_version,cfg.extraction_coverage,integrity,dict(Counter(x.status.value for x in cp2)),entities,candidate)
    if isinstance(cfg,RouterConfig) and mode==WorkbenchMode.CONVERT:
        integrity=RouterReferenceIntegrityValidator().validate(cfg); cp2=RouterCompatibilityEvaluator().evaluate(cfg,profile,target_profile,RouterMigrationMappings.model_validate(mappings or {}),integrity)
        renderer_type=lookup_renderer(target_profile.domain,target_profile.vendor,target_profile.platform,target_version); renderer=renderer_type(); candidate=renderer.render(cp2); commands=defaultdict(list)
        for command in renderer.commands:commands[command.entity_id].append(command.text)
        source_entities={x.id:x for xs in (cfg.interfaces,cfg.vrfs,cfg.static_routes,cfg.prefix_lists,cfg.route_policies,cfg.ospf_processes,[n for p in cfg.bgp_processes for n in p.neighbors]) for x in xs}; entities=[]
        for item in cp2:
            emitted=commands[item.entity_id]; ready=bool(emitted) and item.status in {"EXACT","SUPPORTED"}
            status="READY" if ready else "BLOCKED" if item.status in {"UNSUPPORTED","VERSION_NOT_VERIFIED"} else "REVIEW REQUIRED"; entity=source_entities[item.entity_id]
            entities.append(_row(entity,item.entity_type,_snippet(lines,entity),"\n".join(emitted) or "No generated target config",status,f"CP2: {item.status.value}",item.reasons,commands=emitted))
        header=[f"# Domain: {profile.domain.value}",f"# Source: {profile.vendor.value.title()} {profile.platform.value.replace('_','-')} {source_version}",f"# Target: {target_profile.vendor.value.title()} {target_profile.platform.value} {target_version}"]
        return _result(mode,profile,target_profile,source_version,target_version,cfg.extraction_coverage,integrity,dict(Counter(x.status.value for x in cp2)),entities,"\n".join(header+candidate)+"\n" if candidate else None)
    if mode==WorkbenchMode.ANALYZE:
        integrity=(RouterReferenceIntegrityValidator() if isinstance(cfg,RouterConfig) else ReferenceIntegrityValidator()).validate(cfg); findings=defaultdict(list)
        for finding in integrity.findings: findings[finding.source_entity_id].append(finding.reason+f" {finding.referenced_entity_name or ''}".rstrip())
        collections=(("interface",cfg.interfaces),("vrf",cfg.vrfs),("route",cfg.static_routes),("prefix_list",cfg.prefix_lists),("route_policy",cfg.route_policies),("ospf_process",cfg.ospf_processes),("bgp_neighbor",[n for p in cfg.bgp_processes for n in p.neighbors])) if isinstance(cfg,RouterConfig) else (("interface",cfg.interfaces),("zone",cfg.zones),("address",cfg.addresses),("address_group",cfg.address_groups),("service",cfg.services),("service_group",cfg.service_groups),("security_policy",cfg.security_policies),("nat_policy",cfg.nat_policies),("route",cfg.static_routes))
        entities=[]
        for kind,items in collections:
            for entity in items:
                related_ids=[key for key in integrity.entity_statuses if key==entity.id or key.startswith(f"{entity.id}:")]
                blocked=any(integrity.entity_statuses[key]=="BLOCKED" for key in related_ids)
                related_findings=[message for key in related_ids for message in findings[key]]
                entities.append(_row(entity,kind,_snippet(lines,entity),_normalized(entity),"BLOCKED" if blocked else "READY","CP1: BLOCKED" if blocked else "CP1: PASS",related_findings))
        return _result(mode,profile,target_profile,source_version,target_version,cfg.extraction_coverage,integrity,None,entities,None)
    integrity=ReferenceIntegrityValidator().validate(cfg); target_vendor={"firewall-paloalto-panos":Vendor.PALO_ALTO,"firewall-fortinet-fortigate":Vendor.FORTIGATE,"firewall-cisco-asa":Vendor.ASA,"firewall-juniper-srx":Vendor.JUNIPER_SRX}.get(target_profile.id)
    if not target_vendor: raise ValueError("Target firewall renderer is not implemented.")
    source=resolve_context(text,vendor,source_version); target=resolve_context("",target_vendor,target_version)
    plan=MigrationPlanner().plan(cfg,MigrationMappings.model_validate(mappings or default_mappings(cfg)),source,target,integrity,target_vendor)
    renderer_type=lookup_renderer(target_profile.domain,target_profile.vendor,target_profile.platform,target_version); renderer=renderer_type(); candidate,_=renderer.render(plan)
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
    header=["# Convert-In","# CANDIDATE CONFIGURATION — ENGINEER REVIEW REQUIRED","#",f"# Domain: {profile.domain.value.title()}",f"# Source: {profile.vendor.value.title()} {profile.platform.value.replace('_','-')} {source_version}",f"# Target: {target_profile.vendor.value.title()} {target_profile.platform.value} / {target_profile.os_family} {target_version}","#","# Application-level validation only","# No device deployment performed",f"# CP0: {cfg.extraction_coverage.normalized} normalized; {cfg.extraction_coverage.recovered} recovered; {cfg.extraction_coverage.unparsed} unparsed; {cfg.extraction_coverage.unsupported} source unsupported",f"# CP1: {integrity.blocking_findings} blocking findings",f"# CP2: {dict(cp2)}",f"# Conversion: {len(set(c.entity_id for c in renderer.commands))} generated; {sum(v for k,v in cp2.items() if k in {'MANUAL_REVIEW','PARTIAL'})} manual review; {cp2.get('UNSUPPORTED',0)} unsupported; {cp2.get('VERSION_NOT_VERIFIED',0)} version not verified",""]
    return _result(mode,profile,target_profile,source_version,target_version,cfg.extraction_coverage,integrity,dict(cp2),entities,"\n".join(header+candidate)+"\n")


def _row(entity,kind,source,target,status,detail,findings,target_title=None,commands=None):
    return {"id":entity.id,"entity_type":TYPE_LABELS.get(kind,kind.replace("_"," ").title()),"source_title":entity.name,"source_snippet":source,"target_title":target_title,"target_snippet":target,"user_status":status,"detailed_status":detail,"copyable":status=="READY" and bool(commands),"findings":findings,"semantic_fields":[],"commands":commands or []}


def _result(mode,source,target,source_version,target_version,cp0,cp1,cp2,entities,candidate):
    profile=lambda p,v:{"id":p.id,"vendor":p.vendor.value,"platform":p.platform.value,"domain":p.domain.value,"version":v,"capability":p.target_capability.value}
    slug={"PAN_OS":"panos","FORTIGATE":"fortios","ASA":"asa","SRX":"srx"}.get(target.platform.value,target.platform.value.lower().replace("_","-"))
    extension="conf" if target.platform.value in {"FORTIGATE","ASA"} else "set"
    renderer_available=lookup_renderer(target.domain,target.vendor,target.platform,target_version) is not None
    return {"mode":mode,"renderer_available":renderer_available,"source_profile":profile(source,source_version),"target_profile":profile(target,target_version),"cp0":cp0.model_dump(mode="json"),"cp1":cp1.model_dump(mode="json"),"cp2":cp2,"cp0_summary":cp0.model_dump(mode="json"),"cp1_summary":cp1.model_dump(mode="json"),"cp2_summary":cp2,"entities":entities,"candidate":candidate,"candidate_filename":f"candidate-{slug}-{target_version}.{extension}" if candidate else None}