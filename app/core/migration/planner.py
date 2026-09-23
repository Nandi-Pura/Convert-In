import ipaddress
from app.core.models import Severity, Vendor
from app.core.analysis import AnalysisEngine
from .compatibility import finalize, result
from .mappings import confirmed_maps, normalize_names
from .models import CompatibilityStatus as S, MigrationMappings, MigrationPlan, PlannedEntity
from .registry import source_adapter
from app.core.versions import emitted_capability_fully_evidenced,evidence_state,target_version_profile,version_profile
from app.core.versions.models import CapabilityStatus,VersionContext

class MigrationPlanner:
    def plan(self,cfg,mappings:MigrationMappings,source_version:VersionContext|None=None,target_version:VersionContext|None=None,reference_integrity=None,target_vendor:Vendor=Vendor.PALO_ALTO):
        mappings=mappings.model_copy(deep=True)
        source=cfg.metadata.get("source_vendor")
        source=Vendor(source); cfg=source_adapter(source)().adapt(cfg)
        entities=cfg.interfaces+cfg.zones+cfg.addresses+cfg.address_groups+cfg.services+cfg.service_groups+cfg.security_policies+cfg.nat_policies+cfg.static_routes+cfg.vpn_objects
        names=normalize_names(entities); targets={x.entity_id:x.target_name for x in names}; by_name={x.name:x for x in cfg.addresses+cfg.address_groups+cfg.services+cfg.service_groups}
        interface_maps,zone_maps=confirmed_maps(mappings); compatibility=[]; generate=[]
        source_profile=version_profile(source,source_version.selected_family) if source_version else None
        target_profile=target_version_profile(target_vendor,target_version.selected_family) if target_version else None
        fortios=target_vendor==Vendor.FORTIGATE; asa=target_vendor==Vendor.ASA
        if fortios:
            scoped=[m for m in mappings.interfaces if m.confirmed and (m.target_profile or m.target_version)]
            for m in scoped:
                if m.target_profile!="firewall-fortinet-fortigate" or m.target_version!="7.6.4":
                    m.confirmed=False
            target_names=[m.target_interface.casefold() for m in mappings.interfaces if m.confirmed and m.target_interface]
            if len(target_names)!=len(set(target_names)):
                for m in mappings.interfaces: m.confirmed=False
            interface_maps,zone_maps=confirmed_maps(mappings)
        analysis,_=AnalysisEngine().analyze(cfg); cycles={x.primary_object_id for x in analysis.findings if x.type=="GROUP_CYCLE"}
        def add(entity,kind,status,data=None,*reasons,required=(),topology=None):
            capability={"nat_policy":getattr(entity,"type","nat_policy"),"route":"route"}.get(kind,kind)
            source_cap=source_profile.capabilities.get(capability) if source_profile else None; target_cap=target_profile.capabilities.get(capability) if target_profile else None
            refs=list(dict.fromkeys((source_cap.documentation_refs if source_cap else [])+(target_cap.documentation_refs if target_cap else [])))
            version_status="VERIFIED" if emitted_capability_fully_evidenced(source_profile,target_profile,capability) else "VERSION_NOT_VERIFIED"
            if status in {S.EXACT,S.SUPPORTED,S.PARTIAL} and version_status!="VERIFIED":
                status=S.VERSION_NOT_VERIFIED; data=None; reasons=(*reasons,"Selected source/target version lacks complete semantic, syntax, renderer, or test evidence.")
            item=result(entity,kind,status,*reasons,required=required,topology=topology)
            item.source_version=source_version.selected_version if source_version else None; item.target_version=target_version.selected_version if target_version else None
            item.capability_refs=[f"{source_profile.id}:{capability}" for _ in [0] if source_profile]+[f"{target_profile.id}:{capability}" for _ in [0] if target_profile]
            item.documentation_refs=refs; item.version_status=version_status
            finalize(item,entity,source_profile,target_profile,capability,mappings.management_mode.value,data)
            compatibility.append(item)
            if data is not None and status in {S.EXACT,S.SUPPORTED} and kind!="nat_policy": generate.append(PlannedEntity(entity_id=entity.id,entity_type=kind,target_name=targets[entity.id],data=data))
        for x in cfg.interfaces: add(x,"interface",S.MANUAL_REVIEW,None,"Source interfaces are mapping-only; no interface command generated.",required=[f"interface:{x.name}"] if x.name not in interface_maps else [])
        for x in cfg.zones: add(x,"zone",S.MANUAL_REVIEW,None,"Zone creation is not automatic; confirmed mappings are used by dependent rules.",required=[f"zone:{x.name}"] if x.name not in zone_maps else [])
        for x in cfg.addresses:
            if (fortios or asa) and targets[x.id]!=x.name: add(x,"address",S.MANUAL_REVIEW,None,f"{target_profile.os_name} object name requires an explicit engineer-confirmed mapping."); continue
            try:
                if x.type=="host": value=str(ipaddress.ip_address(x.value)); value+=f"/{32 if ':' not in value else 128}"
                elif x.type=="network": value=str(ipaddress.ip_network(x.value,strict=False))
                elif x.type=="range":
                    a,b=x.value.split("-",1); ipaddress.ip_address(a); ipaddress.ip_address(b); value=x.value
                elif x.type=="fqdn" and x.value and " " not in x.value: value=x.value
                else: raise ValueError
                if (fortios or asa) and (":" in value or x.type=="fqdn"): raise ValueError
                add(x,"address",S.SUPPORTED,{"type":x.type,"value":value})
            except (ValueError,TypeError,AttributeError): add(x,"address",S.MANUAL_REVIEW,None,"Invalid or unsupported normalized address value.")
        for x in cfg.address_groups:
            if (fortios or asa) and targets[x.id]!=x.name: add(x,"address_group",S.MANUAL_REVIEW,None,f"{target_profile.os_name} group name requires an explicit engineer-confirmed mapping."); continue
            missing=[m for m in x.members if m not in by_name]; cycle=x.id in cycles
            if missing or cycle: add(x,"address_group",S.MANUAL_REVIEW,None,"Group cycle detected." if cycle else f"Missing members: {', '.join(missing)}")
            else: add(x,"address_group",S.SUPPORTED,{"members":[targets[by_name[m].id] for m in x.members],"member_types":["group" if by_name[m] in cfg.address_groups else "object" for m in x.members]})
        for x in cfg.services:
            if (fortios or asa) and targets[x.id]!=x.name: add(x,"service",S.MANUAL_REVIEW,None,f"{target_profile.os_name} service name requires an explicit engineer-confirmed mapping."); continue
            if x.vendor_extensions.get("source_operator") or x.vendor_extensions.get("destination_operator"): add(x,"service",S.MANUAL_REVIEW,None,"Source service operator cannot be represented exactly.")
            elif x.protocol not in {"tcp","udp"}: add(x,"service",S.UNSUPPORTED,None,f"Protocol {x.protocol} is not supported.")
            elif x.source_ports: add(x,"service",S.MANUAL_REVIEW,None,"Source-port restrictions are not safely represented by this renderer.")
            elif not x.destination_ports: add(x,"service",S.MANUAL_REVIEW,None,"Destination port is required.")
            elif asa and len(x.destination_ports)!=1: add(x,"service",S.MANUAL_REVIEW,None,"ASA service objects require one destination port expression.")
            else: add(x,"service",S.SUPPORTED,{"protocol":x.protocol,"ports":x.destination_ports})
        for x in cfg.service_groups:
            if (fortios or asa) and targets[x.id]!=x.name: add(x,"service_group",S.MANUAL_REVIEW,None,f"{target_profile.os_name} service-group name requires an explicit engineer-confirmed mapping."); continue
            missing=[m for m in x.members if m not in by_name]
            if missing or x.id in cycles: add(x,"service_group",S.MANUAL_REVIEW,None,"Group dependency is unresolved or cyclic.")
            else: add(x,"service_group",S.SUPPORTED,{"members":[targets[by_name[m].id] for m in x.members],"member_types":["group" if by_name[m] in cfg.service_groups else "object" for m in x.members]})
        policy_positions=[x.position for x in cfg.security_policies]
        duplicate_positions=len(policy_positions)!=len(set(policy_positions))
        for x in sorted(cfg.security_policies,key=lambda p:p.position):
            if asa: add(x,"security_policy",S.MANUAL_REVIEW,None,"ASA ACL name, binding direction, interface nameif, and placement require explicit target context."); continue
            if fortios and targets[x.id]!=x.name: add(x,"security_policy",S.MANUAL_REVIEW,None,"FortiOS policy name requires an explicit engineer-confirmed mapping."); continue
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
            elif x.log_start or x.log_end: add(x,"security_policy",S.MANUAL_REVIEW,None,"Logging semantics are preserved for review and not invented on the target.",topology=topology)
            elif not fortios and not mappings.security_rule_placement: add(x,"security_policy",S.MANUAL_REVIEW,None,"Explicit target security-rule placement is required.",topology=topology)
            elif target_profile and not fortios and target_profile.version_family!="11.1": add(x,"security_policy",S.MANUAL_REVIEW,None,"Security policy generation is limited to PAN-OS 11.1.",topology=topology)
            else:
                if fortios and any(v.lower() in {"any","any4","any6","application-default","service-http","service-https"} for v in refs):
                    add(x,"security_policy",S.MANUAL_REVIEW,None,"Built-in address and service mappings require explicit evidence.",topology=topology); continue
                resolve=lambda values:[v if v.lower() in {"any","application-default","service-http","service-https"} else targets[by_name[v].id] for v in values]
                add(x,"security_policy",S.SUPPORTED,{"from":[zone_maps[z] for z in x.source_zones],"to":[zone_maps[z] for z in x.destination_zones],"source":resolve(x.sources),"destination":resolve(x.destinations),"service":resolve(x.services),"action":x.action,"enabled":x.enabled,"description":x.description,"log_start":x.log_start,"log_end":x.log_end,"position":x.position},topology=topology)
        for x in cfg.nat_policies:
            if asa: add(x,"nat_policy",S.MANUAL_REVIEW,None,"ASA NAT generation is disabled."); continue
            if fortios:
                add(x,"nat_policy",S.MANUAL_REVIEW,None,"FortiOS NAT and VIP generation is disabled for Q8."); continue
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
            if asa: add(x,"route",S.MANUAL_REVIEW,None,"ASA route interface nameif and routing context require explicit target context."); continue
            if x.vendor_extensions.get("manual_review"): add(x,"route",S.MANUAL_REVIEW,None,x.vendor_extensions["manual_review"]); continue
            try: ipaddress.ip_network(x.destination,strict=False); ipaddress.ip_address(x.next_hop)
            except ValueError: add(x,"route",S.MANUAL_REVIEW,None,"Invalid route destination or next hop."); continue
            if fortios and (x.distance is not None or x.metric is not None): add(x,"route",S.MANUAL_REVIEW,None,"Cross-vendor route distance or metric is not mapped."); continue
            mapping=interface_maps.get(x.interface)
            if x.interface and (not mapping or not mapping.target_interface): add(x,"route",S.MANUAL_REVIEW,None,"Confirmed target interface mapping is required.",required=[f"interface:{x.interface}"])
            elif fortios and not x.interface: add(x,"route",S.MANUAL_REVIEW,None,"Confirmed target route interface is required.",required=["route_interface"])
            else: add(x,"route",S.SUPPORTED,{"destination":x.destination,"next_hop":x.next_hop,"interface":mapping.target_interface if mapping else None,"virtual_router":mappings.virtual_router,"metric":x.metric})
        for x in cfg.vpn_objects: add(x,"vpn",S.UNSUPPORTED,None,"VPN migration is outside Phase F scope.")
        advisories=[f"Analysis: {x.description}" for x in analysis.findings if x.type=="POTENTIAL_SHADOWING"]
        if mappings.security_rule_placement and mappings.security_rule_placement.anchor_rule: advisories.append(f"External target dependency: confirm security rule anchor {mappings.security_rule_placement.anchor_rule!r} exists before executing ordering actions.")
        for x in cfg.unparsed_constructs: advisories.append(f"Preserved unparsed {source.value} construct at line {x.line_number}: {x.reason}")
        blocked=[x.message for x in cfg.warnings if x.severity==Severity.ERROR]
        if not source_profile: advisories.append("Source version not verified. Select a verified source OS version before candidate generation.")
        if not target_profile: blocked.append("Explicit verified target version is required.")
        if reference_integrity:
            blocked_ids=reference_integrity.blocked_entity_ids
            generate=[x for x in generate if x.entity_id not in blocked_ids]
            for item in compatibility:
                if item.entity_id in blocked_ids:
                    item.status=S.MANUAL_REVIEW; item.blocking=True; item.reasons.append("Source semantics cannot be validated because CP1 reference integrity is blocked.")
                    item.related_cp1_findings=[x.finding_id for x in reference_integrity.findings if x.source_entity_id==item.entity_id and x.blocking]
                    capability=item.renderer_capability_id or ""
                    basis="|".join((item.entity_id,target_vendor.value,item.target_version or "",mappings.management_mode.value,item.status.value,capability))
                    item.decision_id=__import__("hashlib").sha256(basis.encode()).hexdigest()[:16]
        return MigrationPlan(source_vendor=source,target_vendor=target_vendor,mappings=mappings,compatibility=compatibility,names=names,generate=generate,blocked=blocked,advisories=advisories,source_version=source_version,target_version=target_version)

    @staticmethod
    def _ip_value(value):
        try: ipaddress.ip_address(value); return True
        except ValueError: return False