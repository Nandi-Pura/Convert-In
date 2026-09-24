import hashlib
import ipaddress
import json
from collections import defaultdict

from app.core.models import ConfigDomain, FirewallConfig, RouterConfig, SwitchConfig
from app.core.reference_integrity import ReferenceIntegrityReport

from .models import LintFinding, LintSeverity, SourceLineage


TITLES = {
    "DUPLICATE_ADDRESS_OBJECT": "Duplicate address definition", "DUPLICATE_SERVICE_OBJECT": "Duplicate service definition",
    "UNUSED_ADDRESS_OBJECT": "Unused address object", "UNUSED_SERVICE_OBJECT": "Unused service object",
    "ORPHAN_GROUP": "Group has no consumers", "EMPTY_GROUP": "Group has no usable members",
    "DISABLED_POLICY": "Disabled policy", "BROAD_ANY_POLICY": "Broad policy scope",
    "INVALID_REFERENCE": "Unresolved reference", "ADDRESS_RANGE_OVERLAP": "Address ranges overlap",
    "POLICY_SHADOW_CANDIDATE": "Potential policy shadowing", "UNREFERENCED_VLAN": "Unreferenced VLAN",
    "ACCESS_VLAN_UNDEFINED": "Access VLAN is undefined", "TRUNK_VLAN_UNDEFINED": "Trunk VLAN is undefined",
    "NATIVE_VLAN_UNDEFINED": "Native VLAN is undefined", "EMPTY_ALLOWED_VLAN_SET": "Allowed VLAN set is empty",
    "LAG_WITHOUT_MEMBERS": "LAG has no members", "DUPLICATE_LAG_MEMBERSHIP": "Conflicting LAG membership",
    "SVI_WITHOUT_VLAN": "SVI VLAN is undefined", "DISABLED_INTERFACE": "Disabled interface",
    "VLAN_NAME_CONFLICT": "VLAN name conflict", "DUPLICATE_STATIC_ROUTE": "Duplicate static route",
    "UNRESOLVED_ROUTE_REFERENCE": "Unresolved route reference", "UNUSED_PREFIX_LIST": "Unused prefix list",
    "EMPTY_PREFIX_LIST": "Empty prefix list", "UNUSED_ROUTE_POLICY": "Unused route policy",
    "ROUTE_POLICY_REFERENCE_GAP": "Route policy reference gap", "STATIC_ROUTE_SELF_CONFLICT": "Static route conflicts with itself",
}


def _lineage(entity):
    p = getattr(entity, "provenance", None)
    return SourceLineage(source_line=p.source_line, source_section=p.source_section) if p else None


def _finding(domain, rule, entity, entity_type, description, *, severity=LintSeverity.WARNING, related=(), evidence=None, action=None):
    related_ids = sorted({x.id if hasattr(x, "id") else str(x) for x in related})
    identity = json.dumps([domain.value, rule, entity_type, entity.id, related_ids, evidence or {}], sort_keys=True, separators=(",", ":"), default=str)
    return LintFinding(id=hashlib.sha256(identity.encode()).hexdigest()[:16], domain=domain, severity=severity,
        category=rule.split("_", 1)[0].lower(), rule_id=rule, title=TITLES[rule], description=description,
        entity_type=entity_type, entity_id=entity.id, related_entity_ids=related_ids, evidence=evidence or {},
        suggested_action=action, source_lineage=_lineage(entity))


def _cp1(domain, report):
    if not report:
        return []
    out=[]
    for item in report.findings:
        if domain == ConfigDomain.SWITCH:
            reason=item.reason.casefold()
            rule=("SVI_WITHOUT_VLAN" if item.source_entity_type=="svi" and "undefined vlan" in reason else
                "ACCESS_VLAN_UNDEFINED" if "undefined vlan" in reason and "access" in item.source_entity_name.casefold() else
                "NATIVE_VLAN_UNDEFINED" if "undefined vlan" in reason and "native" in item.source_entity_name.casefold() else
                "TRUNK_VLAN_UNDEFINED" if "undefined vlan" in reason else
                "VLAN_NAME_CONFLICT" if "conflicting vlan" in reason else "INVALID_REFERENCE")
        else:
            rule = "ROUTE_POLICY_REFERENCE_GAP" if domain == ConfigDomain.ROUTER and item.referenced_entity_type == "route_policy" else "INVALID_REFERENCE"
        out.append(_finding(domain, rule, type("E", (), {"id": item.source_entity_id, "provenance": None})(), item.source_entity_type,
            item.reason, severity=LintSeverity.BLOCKING if item.blocking else LintSeverity.WARNING,
            related=item.related_entity_ids, evidence={"cp1_finding_id": item.finding_id, "reference": item.referenced_entity_name},
            action="Resolve the CP1 finding before conversion. CP1 remains authoritative."))
    return out


def lint_firewall(cfg: FirewallConfig, cp1: ReferenceIntegrityReport | None = None):
    out=[]; refs=set()
    for group in cfg.address_groups+cfg.service_groups: refs.update(group.members)
    for policy in cfg.security_policies: refs.update(policy.sources+policy.destinations+policy.services)
    for nat in cfg.nat_policies: refs.update(nat.original_source+nat.translated_source+nat.original_destination+nat.translated_destination+nat.original_service+nat.translated_service)
    for items,kind,rule,key in ((cfg.addresses,"address","DUPLICATE_ADDRESS_OBJECT",lambda x:(x.type,_address_key(x))),
        (cfg.services,"service","DUPLICATE_SERVICE_OBJECT",lambda x:(x.protocol,tuple(sorted(x.source_ports)),tuple(sorted(x.destination_ports))))):
        seen={}
        for item in items:
            semantic=key(item)
            if semantic in seen: out.append(_finding(ConfigDomain.FIREWALL,rule,item,kind,"Another object has the same normalized semantics.",related=[seen[semantic]],evidence={"semantic_key":semantic},action="Review names and consumers; consolidate manually if appropriate."))
            else: seen[semantic]=item
            unused="UNUSED_ADDRESS_OBJECT" if kind=="address" else "UNUSED_SERVICE_OBJECT"
            if item.name not in refs: out.append(_finding(ConfigDomain.FIREWALL,unused,item,kind,"No normalized group, policy, or NAT construct references this object.",severity=LintSeverity.INFO,action="Confirm the object is intentionally retained."))
    known={x.name for x in cfg.addresses+cfg.address_groups+cfg.services+cfg.service_groups}
    for group,kind in [(x,"address_group") for x in cfg.address_groups]+[(x,"service_group") for x in cfg.service_groups]:
        usable=[x for x in group.members if x in known]
        if not usable: out.append(_finding(ConfigDomain.FIREWALL,"EMPTY_GROUP",group,kind,"The group resolves to no known normalized members.",evidence={"members":sorted(group.members)},action="Resolve missing members or remove the group manually."))
        if group.name not in refs: out.append(_finding(ConfigDomain.FIREWALL,"ORPHAN_GROUP",group,kind,"No normalized policy, NAT construct, or group consumes this group.",severity=LintSeverity.INFO,action="Confirm the group is intentionally retained."))
    for policy in cfg.security_policies:
        if not policy.enabled: out.append(_finding(ConfigDomain.FIREWALL,"DISABLED_POLICY",policy,"security_policy","The normalized policy is explicitly disabled.",severity=LintSeverity.INFO,action="Confirm whether the disabled policy should remain in scope."))
        if _any(policy.sources) and _any(policy.destinations): out.append(_finding(ConfigDomain.FIREWALL,"BROAD_ANY_POLICY",policy,"security_policy","Source and destination use normalized any semantics. This is advisory, not an operational security claim.",action="Review the intended policy scope."))
    out.extend(_overlaps(cfg)); out.extend(_shadows(cfg)); out.extend(_cp1(ConfigDomain.FIREWALL,cp1))
    return out


def _address_key(item):
    try:
        if item.type == "host": return str(ipaddress.ip_address(item.value))
        if item.type == "network": return str(ipaddress.ip_network(item.value, strict=False))
        if item.type == "range":
            a,b=item.value.split("-",1); return f"{ipaddress.ip_address(a)}-{ipaddress.ip_address(b)}"
    except (ValueError, AttributeError): pass
    return (item.value or "").casefold()


def _range(item):
    try:
        if item.type == "host": a=ipaddress.ip_address(item.value); return a.version,int(a),int(a)
        if item.type == "network": n=ipaddress.ip_network(item.value,strict=False); return n.version,int(n.network_address),int(n.broadcast_address)
        if item.type == "range": a,b=map(ipaddress.ip_address,item.value.split("-",1)); return a.version,int(a),int(b)
    except (ValueError, AttributeError): return None


def _overlaps(cfg):
    out=[]
    for version in (4,6):
        rows=sorted(((*r,x) for x in cfg.addresses if (r:=_range(x)) and r[0]==version),key=lambda x:(x[1],x[2],x[3].id))
        furthest=None
        for _,start,end,item in rows:
            if furthest and start<=furthest[0] and (start,end)!=(furthest[1],furthest[0]):
                out.append(_finding(ConfigDomain.FIREWALL,"ADDRESS_RANGE_OVERLAP",item,"address","The normalized IP range overlaps another address object.",related=[furthest[2]],evidence={"ip_version":version},action="Review whether both ranges are intentional."))
            if not furthest or end>furthest[0]: furthest=(end,start,item)
    return out


def _any(values): return not values or any(x.casefold() in {"any","any4","any6","all"} for x in values)
def _covers(left,right): return _any(left) or (not _any(right) and set(right)<=set(left))


def _shadows(cfg):
    out=[]; prior=[]
    for policy in sorted(cfg.security_policies,key=lambda x:(x.position,x.id)):
        incomplete=policy.vendor_extensions or policy.log_start or policy.log_end or not policy.source_zones or not policy.destination_zones or policy.action=="unknown"
        if policy.enabled and not incomplete:
            earlier=next((x for x in prior if x.action==policy.action and all(_covers(a,b) for a,b in zip((x.source_zones,x.destination_zones,x.sources,x.destinations,x.services),(policy.source_zones,policy.destination_zones,policy.sources,policy.destinations,policy.services)))),None)
            if earlier: out.append(_finding(ConfigDomain.FIREWALL,"POLICY_SHADOW_CANDIDATE",policy,"security_policy","An earlier comparable policy covers every modeled match dimension.",related=[earlier],evidence={"earlier_position":earlier.position,"later_position":policy.position},action="Review ordering and unmodeled device context before changing either policy."))
            prior.append(policy)
    return out


def lint_switch(cfg: SwitchConfig, cp1: ReferenceIntegrityReport | None = None):
    out=[]; vlans={x.vlan_id for x in cfg.vlans}; used=set(); memberships=defaultdict(set)
    for port in cfg.ports:
        used.update(x for x in [port.access_vlan,port.native_vlan,*port.allowed_vlans] if x is not None)
        if not port.enabled: out.append(_finding(ConfigDomain.SWITCH,"DISABLED_INTERFACE",port,"interface","The normalized interface is explicitly disabled.",severity=LintSeverity.INFO,action="Confirm the disabled state is intentional."))
        if port.lag: memberships[port.name].add(port.lag)
        if port.mode=="trunk" and not port.allowed_vlans and port.vendor_extensions.get("allowed_vlans_explicit"):
            out.append(_finding(ConfigDomain.SWITCH,"EMPTY_ALLOWED_VLAN_SET",port,"interface","The source explicitly normalized an empty allowed VLAN set.",action="Review the intended trunk VLAN set."))
    for lag in cfg.lags:
        used.update(x for x in [lag.native_vlan,*lag.allowed_vlans] if x is not None)
        if not lag.members: out.append(_finding(ConfigDomain.SWITCH,"LAG_WITHOUT_MEMBERS",lag,"lag","The normalized LAG contains no member interfaces.",action="Assign members or remove the LAG manually."))
        for member in lag.members: memberships[member].add(lag.name)
    for svi in cfg.svis: used.add(svi.vlan_id)
    for vlan in cfg.vlans:
        if vlan.vlan_id not in used: out.append(_finding(ConfigDomain.SWITCH,"UNREFERENCED_VLAN",vlan,"vlan","No interface, LAG, or SVI references this VLAN.",severity=LintSeverity.INFO,action="Confirm the VLAN is intentionally retained."))
    for member,names in memberships.items():
        if len(names)>1:
            entity=next((x for x in cfg.ports if x.name==member),type("E",(),{"id":member,"provenance":None})())
            out.append(_finding(ConfigDomain.SWITCH,"DUPLICATE_LAG_MEMBERSHIP",entity,"interface","The member appears in conflicting normalized LAGs.",severity=LintSeverity.BLOCKING,related=names,evidence={"lags":sorted(names)},action="Resolve the CP1 integrity conflict."))
    out.extend(_cp1(ConfigDomain.SWITCH,cp1))
    return out


def lint_router(cfg: RouterConfig, cp1: ReferenceIntegrityReport | None = None):
    out=[]; seen={}
    for route in cfg.static_routes:
        key=(route.destination,route.vrf,route.next_hop,route.interface,route.distance)
        if key in seen: out.append(_finding(ConfigDomain.ROUTER,"DUPLICATE_STATIC_ROUTE",route,"static_route","Another static route has identical normalized destination, context, and next-hop semantics.",related=[seen[key]],evidence={"route_key":key},action="Review whether both route statements are required."))
        else: seen[key]=route
        if route.interface and route.next_hop==route.interface: out.append(_finding(ConfigDomain.ROUTER,"STATIC_ROUTE_SELF_CONFLICT",route,"static_route","The normalized next hop equals the referenced interface name.",action="Review the normalized route fields."))
    used_prefixes={name for policy in cfg.route_policies for term in policy.terms for name in term.prefix_lists}
    used_policies={name for bgp in cfg.bgp_processes for n in bgp.neighbors for name in (n.route_policy_in,n.route_policy_out) if name}|{n.route_policy for bgp in cfg.bgp_processes for n in bgp.networks if n.route_policy}
    for item in cfg.prefix_lists:
        if not item.entries: out.append(_finding(ConfigDomain.ROUTER,"EMPTY_PREFIX_LIST",item,"prefix_list","The normalized prefix list contains no entries.",action="Add intended entries or remove the list manually."))
        if item.name not in used_prefixes: out.append(_finding(ConfigDomain.ROUTER,"UNUSED_PREFIX_LIST",item,"prefix_list","No normalized route policy references this prefix list.",severity=LintSeverity.INFO,action="Confirm the prefix list is intentionally retained."))
    for item in cfg.route_policies:
        if item.name not in used_policies: out.append(_finding(ConfigDomain.ROUTER,"UNUSED_ROUTE_POLICY",item,"route_policy","No normalized BGP network or neighbor references this route policy.",severity=LintSeverity.INFO,action="Confirm the route policy is intentionally retained."))
    out.extend(_cp1(ConfigDomain.ROUTER,cp1)); return out


def lint_config(cfg, cp1=None):
    if isinstance(cfg, FirewallConfig): return lint_firewall(cfg,cp1)
    if isinstance(cfg, SwitchConfig): return lint_switch(cfg,cp1)
    if isinstance(cfg, RouterConfig): return lint_router(cfg,cp1)
    raise TypeError("Unsupported normalized configuration type")