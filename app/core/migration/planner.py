import ipaddress
from app.core.models import Severity, Vendor
from app.core.analysis import AnalysisEngine
from .compatibility import result
from .mappings import confirmed_maps, normalize_names
from .models import CompatibilityStatus as S, MigrationMappings, MigrationPlan, PlannedEntity
from .registry import migration_pair
from app.core.versions import emitted_capability_fully_evidenced,evidence_state,version_profile
from app.core.versions.models import CapabilityStatus,VersionContext

class MigrationPlanner:
    def plan(self,cfg,mappings:MigrationMappings,source_version:VersionContext|None=None,target_version:VersionContext|None=None,reference_integrity=None):
        source=cfg.metadata.get("source_vendor")
        source=Vendor(source); pair=migration_pair(source,Vendor.PALO_ALTO); cfg=pair.source_adapter().adapt(cfg)
        entities=cfg.interfaces+cfg.zones+cfg.addresses+cfg.address_groups+cfg.services+cfg.service_groups+cfg.security_policies+cfg.nat_policies+cfg.static_routes+cfg.vpn_objects
        names=normalize_names(entities); targets={x.entity_id:x.target_name for x in names}; by_name={x.name:x for x in cfg.addresses+cfg.address_groups+cfg.services+cfg.service_groups}
        interface_maps,zone_maps=confirmed_maps(mappings); compatibility=[]; generate=[]
        source_profile=version_profile(source,source_version.selected_family) if source_version else None
        target_profile=version_profile(Vendor.PALO_ALTO,target_version.selected_family) if target_version else None
        analysis,_=AnalysisEngine().analyze(cfg); cycles={x.primary_object_id for x in analysis.findings if x.type=="GROUP_CYCLE"}
        def add(entity,kind,status,data=None,*reasons,required=(),topology=None):
            capability={"nat_policy":getattr(entity,"type","nat_policy"),"route":"route"}.get(kind,kind)
            source_cap=source_profile.capabilities.get(capability) if source_profile else None; target_cap=target_profile.capabilities.get(capability) if target_profile else None
            refs=list(dict.fromkeys((source_cap.documentation_refs if source_cap else [])+(target_cap.documentation_refs if target_cap else [])))
            version_status="VERIFIED" if emitted_capability_fully_evidenced(source_profile,target_profile,capability) else "VERSION_NOT_VERIFIED"
            if status in {S.EXACT,S.SUPPORTED,S.PARTIAL} and version_status!="VERIFIED":
                status=S.MANUAL_REVIEW; data=None; reasons=(*reasons,"Source and target capability documentation/test evidence is incomplete for selected versions.")
            item=result(entity,kind,status,*reasons,required=required,topology=topology)
            item.source_version=source_version.selected_version if source_version else None; item.target_version=target_version.selected_version if target_version else None
            item.capability_refs=[f"{source_profile.id}:{capability}" for _ in [0] if source_profile]+[f"{target_profile.id}:{capability}" for _ in [0] if target_profile]
            item.documentation_refs=refs; item.version_status=version_status; compatibility.append(item)
            if data is not None and status in {S.EXACT,S.SUPPORTED,S.PARTIAL}: generate.append(PlannedEntity(entity_id=entity.id,entity_type=kind,target_name=targets[entity.id],data=data))
        for x in cfg.interfaces: add(x,"interface",S.MANUAL_REVIEW,None,"Source interfaces are mapping-only; no interface command generated.",required=[f"interface:{x.name}"] if x.name not in interface_maps else [])
        for x in cfg.zones: add(x,"zone",S.MANUAL_REVIEW,None,"Zone creation is not automatic; confirmed mappings are used by dependent rules.",required=[f"zone:{x.name}"] if x.name not in zone_maps else [])
        for x in cfg.addresses:
            try:
                if x.type=="host": value=str(ipaddress.ip_address(x.value)); value+=f"/{32 if ':' not in value else 128}"
                elif x.type=="network": value=str(ipaddress.ip_network(x.value,strict=False))
                elif x.type=="range":
                    a,b=x.value.split("-",1); ipaddress.ip_address(a); ipaddress.ip_address(b); value=x.value
                elif x.type=="fqdn" and x.value and " " not in x.value: value=x.value
                else: raise ValueError
                add(x,"address",S.SUPPORTED,{"type":x.type,"value":value})
            except (ValueError,TypeError,AttributeError): add(x,"address",S.MANUAL_REVIEW,None,"Invalid or unsupported normalized address value.")
        for x in cfg.address_groups:
            missing=[m for m in x.members if m not in by_name]; cycle=x.id in cycles
            if missing or cycle: add(x,"address_group",S.MANUAL_REVIEW,None,"Group cycle detected." if cycle else f"Missing members: {', '.join(missing)}")
            else: add(x,"address_group",S.SUPPORTED,{"members":[targets[by_name[m].id] for m in x.members]})
        for x in cfg.services:
            if x.vendor_extensions.get("source_operator") or x.vendor_extensions.get("destination_operator"): add(x,"service",S.MANUAL_REVIEW,None,"Source service operator cannot be represented exactly.")
            elif x.protocol not in {"tcp","udp"}: add(x,"service",S.UNSUPPORTED,None,f"Protocol {x.protocol} is not supported.")
            elif x.source_ports: add(x,"service",S.MANUAL_REVIEW,None,"Source-port restrictions are not safely represented by this renderer.")
            elif not x.destination_ports: add(x,"service",S.MANUAL_REVIEW,None,"Destination port is required.")
            else: add(x,"service",S.SUPPORTED,{"protocol":x.protocol,"ports":x.destination_ports})
        for x in cfg.service_groups:
            missing=[m for m in x.members if m not in by_name]
            if missing or x.id in cycles: add(x,"service_group",S.MANUAL_REVIEW,None,"Group dependency is unresolved or cyclic.")
            else: add(x,"service_group",S.SUPPORTED,{"members":[targets[by_name[m].id] for m in x.members]})
        policy_positions=[x.position for x in cfg.security_policies]
        duplicate_positions=len(policy_positions)!=len(set(policy_positions))
        for x in sorted(cfg.security_policies,key=lambda p:p.position):
            topology=x.vendor_extensions.get("topology",{})
            required=[f"zone:{z}" for z in x.source_zones+x.destination_zones if z not in zone_maps]
            refs=x.sources+x.destinations+x.services; missing=[r for r in refs if r.lower() not in {"any","any4","any6","application-default","service-http","service-https"} and r not in by_name]
            profiles=x.vendor_extensions.get("security_profiles",[])
            if duplicate_positions: add(x,"security_policy",S.MANUAL_REVIEW,None,"Source effective policy order is ambiguous: duplicate positions.",topology=topology)
            elif x.vendor_extensions.get("manual_review"): add(x,"security_policy",S.MANUAL_REVIEW,None,x.vendor_extensions["manual_review"],topology=topology)
            elif profiles: add(x,"security_policy",S.MANUAL_REVIEW,None,f"Security profiles are preserved for review and not migrated: {', '.join(profiles)}",required=required,topology=topology)
            elif x.vendor_extensions.get("attached") is False: add(x,"security_policy",S.MANUAL_REVIEW,None,"ACL is not attached and is not proven active.",topology=topology)
            elif x.vendor_extensions.get("attachment",{}).get("direction")=="out": add(x,"security_policy",S.MANUAL_REVIEW,None,"Outbound ASA ACL semantics require engineer review.",topology=topology)
            elif missing: add(x,"security_policy",S.MANUAL_REVIEW,None,f"Unresolved references: {', '.join(missing)}",topology=topology)
            elif not x.source_zones or not x.destination_zones: add(x,"security_policy",S.MANUAL_REVIEW,None,topology.get("reason") or "Normalized rule has no explicit source/destination zones.",required=["source_zone","destination_zone"],topology=topology)
            elif required: add(x,"security_policy",S.MANUAL_REVIEW,None,"Confirmed zone mapping is required.",required=required,topology=topology)
            elif x.action not in {"allow","deny"}: add(x,"security_policy",S.UNSUPPORTED,None,f"Action {x.action} is not safely implemented.")
            elif not mappings.security_rule_placement: add(x,"security_policy",S.MANUAL_REVIEW,None,"Explicit target security-rule placement is required.",topology=topology)
            elif target_profile and target_profile.version_family!="11.1": add(x,"security_policy",S.MANUAL_REVIEW,None,"Security policy generation is limited to PAN-OS 11.1.",topology=topology)
            else:
                resolve=lambda values:[v if v.lower() in {"any","application-default","service-http","service-https"} else targets[by_name[v].id] for v in values]
                add(x,"security_policy",S.SUPPORTED,{"from":[zone_maps[z] for z in x.source_zones],"to":[zone_maps[z] for z in x.destination_zones],"source":resolve(x.sources),"destination":resolve(x.destinations),"service":resolve(x.services),"action":x.action,"enabled":x.enabled,"description":x.description,"log_start":x.log_start,"log_end":x.log_end,"position":x.position},topology=topology)
        for x in cfg.nat_policies:
            required=[f"zone:{z}" for z in x.source_zones+x.destination_zones if z not in zone_maps]
            refs=x.original_source+x.original_destination+x.translated_source+x.translated_destination
            missing=[r for r in refs if r not in {"any","interface"} and r not in by_name and not self._ip_value(r)]
            subtype=("interface_address_pat" if x.type=="dynamic_pat" and x.translation_target=="INTERFACE_ADDRESS" or x.type=="dynamic_pat" and x.translated_source==["interface"] else "destination_port_translation" if x.type=="destination_nat" and x.translated_service else "destination_static_nat" if x.type=="destination_nat" else "dynamic_ip_and_port" if x.type=="dynamic_pat" else x.type)
            route_outcome=next((o for o in mappings.nat_route_outcomes if o.nat_rule==x.id),None)
            if x.vendor_extensions.get("manual_review"): add(x,"nat_policy",S.MANUAL_REVIEW,None,x.vendor_extensions["manual_review"])
            elif x.identity: add(x,"nat_policy",S.MANUAL_REVIEW,None,"Identity NAT is preserved but not rendered.")
            elif subtype in {"twice_nat","identity_nat","central_nat","ip_pool_snat"}: add(x,"nat_policy",S.MANUAL_REVIEW,None,f"NAT subtype {subtype} is preserved but not rendered.")
            elif target_profile:
                evidence=evidence_state(source_profile,target_profile,subtype)
                yes=lambda value:"Verified" if value else "Not verified"
                add(x,"nat_policy",S.MANUAL_REVIEW,None,f"Target match semantics: {yes(evidence.target_match_semantics_documented)}; translated address semantics: {yes(evidence.target_translation_semantics_documented)}; destination-zone route-lookup semantics: {yes(evidence.route_lookup_semantics_documented)}; explicit route outcome: {yes(bool(route_outcome and route_outcome.confirmed))}; ordering: {yes(evidence.ordering_verified)}; placement: {yes(evidence.placement_verified)}; result: MANUAL_REVIEW.")
            elif missing: add(x,"nat_policy",S.MANUAL_REVIEW,None,f"Unresolved NAT references: {', '.join(missing)}")
            elif required: add(x,"nat_policy",S.MANUAL_REVIEW,None,"Confirmed source and destination zone mappings are required.",required=required)
            else:
                resolve=lambda values:[targets[by_name[v].id] if v in by_name else v for v in values]
                add(x,"nat_policy",S.SUPPORTED,{"from":[zone_maps[z] for z in x.source_zones],"to":[zone_maps[z] for z in x.destination_zones],"source":resolve(x.original_source or ["any"]),"destination":resolve(x.original_destination or ["any"]),"service":resolve(x.original_service)[0] if x.original_service else "any","type":x.type,"translated_source":resolve(x.translated_source),"translated_destination":resolve(x.translated_destination),"translated_service":resolve(x.translated_service)[0] if x.translated_service else None,"translation_target":x.translation_target,"position":x.position})
        for x in cfg.static_routes:
            if x.vendor_extensions.get("manual_review"): add(x,"route",S.MANUAL_REVIEW,None,x.vendor_extensions["manual_review"]); continue
            try: ipaddress.ip_network(x.destination,strict=False); ipaddress.ip_address(x.next_hop)
            except ValueError: add(x,"route",S.MANUAL_REVIEW,None,"Invalid route destination or next hop."); continue
            mapping=interface_maps.get(x.interface)
            if x.interface and (not mapping or not mapping.target_interface): add(x,"route",S.MANUAL_REVIEW,None,"Confirmed target interface mapping is required.",required=[f"interface:{x.interface}"])
            else: add(x,"route",S.SUPPORTED,{"destination":x.destination,"next_hop":x.next_hop,"interface":mapping.target_interface if mapping else None,"virtual_router":mappings.virtual_router,"metric":x.metric})
        for x in cfg.vpn_objects: add(x,"vpn",S.UNSUPPORTED,None,"VPN migration is outside Phase F scope.")
        advisories=[f"Analysis: {x.description}" for x in analysis.findings if x.type=="POTENTIAL_SHADOWING"]
        if mappings.security_rule_placement and mappings.security_rule_placement.anchor_rule: advisories.append(f"External target dependency: confirm security rule anchor {mappings.security_rule_placement.anchor_rule!r} exists before executing ordering actions.")
        for x in cfg.unparsed_constructs: advisories.append(f"Preserved unparsed {source.value} construct at line {x.line_number}: {x.reason}")
        blocked=[x.message for x in cfg.warnings if x.severity==Severity.ERROR]
        if not source_profile: advisories.append("Source version not verified. Select a verified source OS version before candidate generation.")
        if not target_profile: blocked.append("Explicit verified target PAN-OS version is required.")
        if reference_integrity:
            blocked_ids=reference_integrity.blocked_entity_ids
            generate=[x for x in generate if x.entity_id not in blocked_ids]
            for item in compatibility:
                if item.entity_id in blocked_ids:
                    item.status=S.MANUAL_REVIEW; item.reasons.append("Reference integrity blocked generation.")
        return MigrationPlan(source_vendor=source,mappings=mappings,compatibility=compatibility,names=names,generate=generate,blocked=blocked,advisories=advisories,source_version=source_version,target_version=target_version)

    @staticmethod
    def _ip_value(value):
        try: ipaddress.ip_address(value); return True
        except ValueError: return False