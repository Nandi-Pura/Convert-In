import hashlib
import re
from enum import StrEnum
from pydantic import BaseModel, Field

from app.core.migration.models import CompatibilityResult, CompatibilityStatus


class RouterSemanticCapability(StrEnum):
    INTERFACE_IPV4="interface_ipv4"; STATIC_ROUTE="static_route"; PREFIX_LIST="prefix_list"; ROUTE_POLICY="route_policy"; VRF="vrf"; OSPF="ospf"; BGP="bgp"


class RouterInterfaceMapping(BaseModel):
    source_profile:str; source_version:str; target_profile:str; target_version:str
    source_entity_id:str; target_identity:str; confirmed:bool=False

    def matches(self,source_profile,target_profile,entity_id):
        return self.confirmed and self.source_profile==source_profile.id and self.source_version in source_profile.supported_versions and self.target_profile==target_profile.id and self.target_version in target_profile.supported_versions and self.source_entity_id==entity_id


class RouterMigrationMappings(BaseModel):
    interfaces:list[RouterInterfaceMapping]=Field(default_factory=list)


class RouterCompatibilityEvaluator:
    refs={
        RouterSemanticCapability.INTERFACE_IPV4:("JUNOS-INTERFACE-ADDRESS","JUNOS-INTERFACE-DESCRIPTION","JUNOS-INTERFACE-DISABLE"),
        RouterSemanticCapability.STATIC_ROUTE:("JUNOS-STATIC-ROUTES",),
        RouterSemanticCapability.PREFIX_LIST:("JUNOS-PREFIX-LISTS",),
    }

    def evaluate(self,cfg,source_profile,target_profile,mappings,cp1):
        blocked={k for k,v in cp1.entity_statuses.items() if v=="BLOCKED"}; results=[]
        def add(entity,kind,status,reasons,capability,commands=()):
            refs=list(self.refs.get(capability,()))
            item=CompatibilityResult(entity_id=entity.id,entity_type=kind,source_name=entity.name,status=status,reasons=list(reasons),source_version=source_profile.supported_versions[0],target_version=target_profile.supported_versions[0],capability_refs=[f"iosxe17_12_1_to_junos23_4R2.{capability.value}"],documentation_refs=refs,version_status="VERIFIED" if refs else "VERSION_NOT_VERIFIED",renderer_capability_id=capability.value,renderer_support=bool(commands),blocking=status not in {CompatibilityStatus.EXACT,CompatibilityStatus.SUPPORTED})
            item.target_semantic={"commands":list(commands)}; item.decision_id=hashlib.sha256(f"{entity.id}|{target_profile.id}|{item.target_version}|{status}".encode()).hexdigest()[:16]; results.append(item)
        for x in cfg.interfaces:
            mapping=next((m for m in mappings.interfaces if m.matches(source_profile,target_profile,x.id)),None)
            physical=not re.search(r"(?:Loopback|\.)",x.name,re.I)
            if x.id in blocked:add(x,"interface",CompatibilityStatus.MANUAL_REVIEW,["CP1 reference integrity is blocked."],RouterSemanticCapability.INTERFACE_IPV4)
            elif not physical:add(x,"interface",CompatibilityStatus.MANUAL_REVIEW,["Loopbacks and subinterfaces require explicit target context."],RouterSemanticCapability.INTERFACE_IPV4)
            elif not mapping:add(x,"interface",CompatibilityStatus.MANUAL_REVIEW,["Confirmed target interface mapping is required."],RouterSemanticCapability.INTERFACE_IPV4)
            else:
                q=lambda v:'"'+v.replace('\\','\\\\').replace('"','\\"')+'"'
                commands=([f"set interfaces {mapping.target_identity} description {q(x.description)}"] if x.description else [])+[f"set interfaces {mapping.target_identity} disable"]*(not x.enabled)+[f"set interfaces {mapping.target_identity} unit 0 family inet address {a}" for a in x.addresses]
                add(x,"interface",CompatibilityStatus.SUPPORTED,[],RouterSemanticCapability.INTERFACE_IPV4,commands)
        for x in cfg.vrfs:add(x,"vrf",CompatibilityStatus.VERSION_NOT_VERIFIED,["Routing-instance hierarchy requires a separate verified capability."],RouterSemanticCapability.VRF)
        for x in cfg.static_routes:
            if x.id in blocked or x.vrf or x.distance is not None or x.interface:add(x,"route",CompatibilityStatus.MANUAL_REVIEW,["Only global next-hop routes without distance or interface binding are supported."],RouterSemanticCapability.STATIC_ROUTE)
            else:add(x,"route",CompatibilityStatus.SUPPORTED,[],RouterSemanticCapability.STATIC_ROUTE,[f"set routing-options static route {x.destination} next-hop {x.next_hop}"])
        for x in cfg.prefix_lists:
            simple=all(e.action=="permit" and e.ge is None and e.le is None for e in x.entries)
            commands=[f"set policy-options prefix-list {x.name} {e.prefix}" for e in sorted(x.entries,key=lambda e:e.sequence)] if simple else []
            add(x,"prefix_list",CompatibilityStatus.SUPPORTED if commands else CompatibilityStatus.MANUAL_REVIEW,[] if commands else ["Only exact permit prefix-list entries are supported."],RouterSemanticCapability.PREFIX_LIST,commands)
        for x in cfg.route_policies:add(x,"route_policy",CompatibilityStatus.MANUAL_REVIEW,["Usage context and complete term semantics are required."],RouterSemanticCapability.ROUTE_POLICY)
        for x in cfg.ospf_processes:add(x,"ospf_process",CompatibilityStatus.MANUAL_REVIEW,["OSPF rendering is not implemented."],RouterSemanticCapability.OSPF)
        for p in cfg.bgp_processes:
            for x in p.neighbors:add(x,"bgp_neighbor",CompatibilityStatus.MANUAL_REVIEW,["BGP rendering is not implemented."],RouterSemanticCapability.BGP)
        return results