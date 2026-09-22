import hashlib
import ipaddress
from collections import Counter, defaultdict
from enum import StrEnum

import networkx as nx
from pydantic import BaseModel, Field

from app.core.models import FirewallConfig, Severity, Vendor


class ReferenceIntegrityStatus(StrEnum):
    PASS = "PASS"
    WARNING = "WARNING"
    BLOCKED = "BLOCKED"


class ReferenceFindingType(StrEnum):
    UNRESOLVED_REFERENCE = "UNRESOLVED_REFERENCE"
    DUPLICATE_NAME = "DUPLICATE_NAME"
    TYPE_MISMATCH = "TYPE_MISMATCH"
    SELF_REFERENCE = "SELF_REFERENCE"
    REFERENCE_CYCLE = "REFERENCE_CYCLE"
    AMBIGUOUS_REFERENCE = "AMBIGUOUS_REFERENCE"
    ORPHANED_OBJECT = "ORPHANED_OBJECT"
    INVALID_BINDING = "INVALID_BINDING"
    MISSING_INTERFACE = "MISSING_INTERFACE"
    MISSING_ZONE = "MISSING_ZONE"
    MISSING_SERVICE = "MISSING_SERVICE"
    MISSING_ADDRESS = "MISSING_ADDRESS"
    MISSING_GROUP_MEMBER = "MISSING_GROUP_MEMBER"
    INVALID_NEXT_HOP_REFERENCE = "INVALID_NEXT_HOP_REFERENCE"


class ReferenceIntegrityFinding(BaseModel):
    finding_id: str
    finding_type: ReferenceFindingType
    severity: Severity
    source_entity_id: str
    source_entity_type: str
    source_entity_name: str
    referenced_entity_name: str | None = None
    referenced_entity_type: str | None = None
    dependency_path: list[str] = Field(default_factory=list)
    reason: str
    blocking: bool
    related_extraction_ids: list[str] = Field(default_factory=list)
    related_entity_ids: list[str] = Field(default_factory=list)


class ReferenceCategoryBreakdown(BaseModel):
    total: int = 0
    resolved: int = 0
    unresolved: int = 0


class ReferenceIntegrityReport(BaseModel):
    status: ReferenceIntegrityStatus
    total_entities: int
    total_references: int
    resolved_references: int
    unresolved_references: int
    warnings: int
    blocking_findings: int
    findings: list[ReferenceIntegrityFinding] = Field(default_factory=list)
    category_breakdown: dict[str, ReferenceCategoryBreakdown] = Field(default_factory=dict)
    entity_statuses: dict[str, ReferenceIntegrityStatus] = Field(default_factory=dict)
    cycles_detected: int = 0
    orphans: int = 0
    duplicates: int = 0

    @property
    def blocked_entity_ids(self) -> set[str]:
        return {entity_id for entity_id, status in self.entity_statuses.items() if status == ReferenceIntegrityStatus.BLOCKED}


class ReferenceResolver:
    """Exact-name, typed IR index. Vendor case semantics remain unmodified."""

    def __init__(self, cfg: FirewallConfig):
        self.namespaces = {
            "address": self._index(cfg.addresses), "address_group": self._index(cfg.address_groups),
            "service": self._index(cfg.services), "service_group": self._index(cfg.service_groups),
            "interface": self._index(cfg.interfaces), "zone": self._index(cfg.zones),
            "security_policy": self._index(cfg.security_policies), "nat_policy": self._index(cfg.nat_policies),
            "route": self._index(cfg.static_routes), "vpn": self._index(cfg.vpn_objects),
        }
        self.all_by_name: dict[str, list[tuple[str, object]]] = defaultdict(list)
        for kind, index in self.namespaces.items():
            for name, entities in index.items():
                self.all_by_name[name].extend((kind, entity) for entity in entities)

    @staticmethod
    def _index(items):
        result = defaultdict(list)
        for item in items: result[item.name].append(item)
        return dict(result)

    def resolve(self, name: str, allowed: tuple[str, ...]):
        matches = [(kind, entity) for kind in allowed for entity in self.namespaces[kind].get(name, [])]
        return matches, self.all_by_name.get(name, [])


class ReferenceIntegrityValidator:
    TYPES = (("interface", "interfaces"), ("zone", "zones"), ("address", "addresses"),
             ("address_group", "address_groups"), ("service", "services"),
             ("service_group", "service_groups"), ("security_policy", "security_policies"),
             ("nat_policy", "nat_policies"), ("route", "static_routes"), ("vpn", "vpn_objects"))

    def validate(self, cfg: FirewallConfig) -> ReferenceIntegrityReport:
        resolver = ReferenceResolver(cfg); findings = []; graph = nx.DiGraph(); references = []; referenced = set()
        entities = [(kind, entity) for kind, attr in self.TYPES for entity in getattr(cfg, attr)]
        entity_by_id = {entity.id: (kind, entity) for kind, entity in entities}
        graph.add_nodes_from(entity_by_id)
        extraction = {entity_id: item.id for item in (cfg.extraction_coverage.items if cfg.extraction_coverage else []) for entity_id in item.normalized_entity_ids}
        vendor = Vendor(cfg.metadata.get("source_vendor", Vendor.UNKNOWN))
        builtins = self._builtins(vendor)

        def add(kind, source_kind, source, ref, expected, context, reason, blocking=True, path=None, related=()):
            raw = "|".join((kind.value, source.id, ref or "", context))
            findings.append(ReferenceIntegrityFinding(finding_id=hashlib.sha256(raw.encode()).hexdigest()[:16], finding_type=kind,
                severity=Severity.ERROR if blocking else Severity.WARNING, source_entity_id=source.id, source_entity_type=source_kind,
                source_entity_name=source.name, referenced_entity_name=ref, referenced_entity_type="/".join(expected) if expected else None,
                dependency_path=path or [f"{source_kind}:{source.name}", f"{('/'.join(expected) or 'entity')}:{ref}"], reason=reason,
                blocking=blocking, related_extraction_ids=[extraction[source.id]] if source.id in extraction else [], related_entity_ids=sorted(set(related))))

        def check(source_kind, source, ref, expected, context, missing_type=ReferenceFindingType.UNRESOLVED_REFERENCE):
            if not ref or self._is_builtin(ref, expected, builtins) or self._is_literal(ref, expected): return
            matches, all_matches = resolver.resolve(ref, expected); references.append((context, bool(len(matches) == 1)))
            if len(matches) == 1:
                target = matches[0][1]; graph.add_edge(source.id, target.id, context=context); referenced.add(target.id); return
            if len(matches) > 1:
                add(ReferenceFindingType.AMBIGUOUS_REFERENCE, source_kind, source, ref, expected, context, f"Reference resolves to {len(matches)} entities.", related=[x.id for _, x in matches]); return
            if all_matches:
                add(ReferenceFindingType.TYPE_MISMATCH, source_kind, source, ref, expected, context, f"Reference exists as {', '.join(sorted({x[0] for x in all_matches}))}, not the required type.", related=[x.id for _, x in all_matches]); return
            add(missing_type, source_kind, source, ref, expected, context, f"Required {'/'.join(expected)} reference does not exist.")

        for namespace, index in resolver.namespaces.items():
            for name, matches in index.items():
                if len(matches) > 1:
                    for entity in matches: add(ReferenceFindingType.DUPLICATE_NAME, namespace, entity, name, (namespace,), f"duplicate:{namespace}:{name}", "Name is not unique in its normalized namespace.", related=[x.id for x in matches])

        for group in cfg.address_groups:
            for member in group.members:
                if member == group.name: add(ReferenceFindingType.SELF_REFERENCE, "address_group", group, member, ("address", "address_group"), "member", "Address group contains itself.")
                else: check("address_group", group, member, ("address", "address_group"), "member", ReferenceFindingType.MISSING_GROUP_MEMBER)
        for group in cfg.service_groups:
            for member in group.members:
                if member == group.name: add(ReferenceFindingType.SELF_REFERENCE, "service_group", group, member, ("service", "service_group"), "member", "Service group contains itself.")
                else: check("service_group", group, member, ("service", "service_group"), "member", ReferenceFindingType.MISSING_GROUP_MEMBER)
        for zone in cfg.zones:
            for interface in zone.interfaces: check("zone", zone, interface, ("interface",), "zone-interface", ReferenceFindingType.MISSING_INTERFACE)
        for interface in cfg.interfaces:
            if interface.parent: check("interface", interface, interface.parent, ("interface",), "interface-parent", ReferenceFindingType.MISSING_INTERFACE)
            if interface.zone: check("interface", interface, interface.zone, ("zone",), "interface-zone", ReferenceFindingType.MISSING_ZONE)
        for rule in cfg.security_policies:
            for value in rule.sources: check("security_policy", rule, value, ("address", "address_group"), "policy-source", ReferenceFindingType.MISSING_ADDRESS)
            for value in rule.destinations: check("security_policy", rule, value, ("address", "address_group"), "policy-destination", ReferenceFindingType.MISSING_ADDRESS)
            for value in rule.services: check("security_policy", rule, value, ("service", "service_group"), "policy-service", ReferenceFindingType.MISSING_SERVICE)
            for value in rule.source_zones: check("security_policy", rule, value, ("zone",), "policy-source-zone", ReferenceFindingType.MISSING_ZONE)
            for value in rule.destination_zones: check("security_policy", rule, value, ("zone",), "policy-destination-zone", ReferenceFindingType.MISSING_ZONE)
            interface_types=("interface", "zone") if vendor==Vendor.ASA else ("interface",)
            for value in rule.ingress_interfaces + rule.egress_interfaces: check("security_policy", rule, value, interface_types, "policy-interface", ReferenceFindingType.MISSING_INTERFACE)
        for rule in cfg.nat_policies:
            for value in rule.original_source + rule.original_destination + rule.translated_source + rule.translated_destination: check("nat_policy", rule, value, ("address", "address_group"), "nat-address", ReferenceFindingType.MISSING_ADDRESS)
            for value in rule.original_service + rule.translated_service: check("nat_policy", rule, value, ("service", "service_group"), "nat-service", ReferenceFindingType.MISSING_SERVICE)
            for value in rule.source_zones + rule.destination_zones: check("nat_policy", rule, value, ("zone",), "nat-zone", ReferenceFindingType.MISSING_ZONE)
            for value in (rule.ingress_interface, rule.egress_interface):
                if value: check("nat_policy", rule, value, interface_types, "nat-interface", ReferenceFindingType.MISSING_INTERFACE)
        for route in cfg.static_routes:
            if route.interface: check("route", route, route.interface, interface_types, "route-interface", ReferenceFindingType.MISSING_INTERFACE)
            try: ipaddress.ip_network(route.destination, strict=False); ipaddress.ip_address(route.next_hop)
            except ValueError: add(ReferenceFindingType.INVALID_NEXT_HOP_REFERENCE, "route", route, route.next_hop, (), "route-next-hop", "Route destination or next hop is invalid.")

        group_ids = {x.id for x in cfg.address_groups + cfg.service_groups}
        for cycle in sorted(nx.simple_cycles(graph.subgraph(group_ids)), key=lambda x: tuple(x)):
            canonical = self._canonical_cycle(cycle); source_kind, source = entity_by_id[canonical[0]]
            names = [entity_by_id[x][1].name for x in canonical]
            add(ReferenceFindingType.REFERENCE_CYCLE, source_kind, source, names[0], (source_kind,), "cycle", "Recursive group dependency is invalid.", path=[f"{entity_by_id[x][0]}:{entity_by_id[x][1].name}" for x in canonical + canonical[:1]], related=canonical)

        orphan_types = {"address", "address_group", "service", "service_group"}
        for kind, entity in entities:
            if kind in orphan_types and entity.id not in referenced:
                add(ReferenceFindingType.ORPHANED_OBJECT, kind, entity, None, (), "orphan", "Object is not referenced by another normalized entity.", False)

        # A bad dependency blocks every transitive dependent. Shortest paths use sorted successors for stable output.
        direct_findings = [x for x in findings if x.blocking]; direct_blocked = {x.source_entity_id for x in direct_findings}; reverse = graph.reverse(copy=False)
        blocked = set(direct_blocked)
        for source in sorted(direct_blocked): blocked.update(nx.descendants(reverse, source))
        propagated = []
        for finding in direct_findings:
            for dependent in sorted(nx.descendants(reverse, finding.source_entity_id)):
                path = list(reversed(nx.shortest_path(reverse, finding.source_entity_id, dependent)))
                source_kind, source = entity_by_id[dependent]
                labels = [f"{entity_by_id[x][0]}:{entity_by_id[x][1].name}" for x in path] + finding.dependency_path[1:]
                raw = "|".join((finding.finding_type.value, dependent, finding.referenced_entity_name or "", "impact:" + "/".join(path)))
                propagated.append(finding.model_copy(update={"finding_id": hashlib.sha256(raw.encode()).hexdigest()[:16], "source_entity_id": dependent,
                    "source_entity_type": source_kind, "source_entity_name": source.name, "dependency_path": labels,
                    "related_extraction_ids": [extraction[dependent]] if dependent in extraction else [], "related_entity_ids": sorted(set(finding.related_entity_ids + path))}))
        findings.extend(propagated)
        findings.sort(key=lambda x: (not x.blocking, x.finding_type.value, x.source_entity_type, x.source_entity_name, x.referenced_entity_name or "", x.finding_id))
        statuses = {entity.id: ReferenceIntegrityStatus.BLOCKED if entity.id in blocked else ReferenceIntegrityStatus.WARNING if any(x.source_entity_id == entity.id for x in findings) else ReferenceIntegrityStatus.PASS for _, entity in entities}
        counts = Counter(context for context, _ in references); resolved = Counter(context for context, ok in references if ok)
        categories = {key: ReferenceCategoryBreakdown(total=value, resolved=resolved[key], unresolved=value-resolved[key]) for key, value in sorted(counts.items())}
        blocking = sum(x.blocking for x in findings); warnings = len(findings)-blocking
        return ReferenceIntegrityReport(status=ReferenceIntegrityStatus.BLOCKED if blocking else ReferenceIntegrityStatus.WARNING if warnings else ReferenceIntegrityStatus.PASS,
            total_entities=len(entities), total_references=len(references), resolved_references=sum(resolved.values()), unresolved_references=len(references)-sum(resolved.values()),
            warnings=warnings, blocking_findings=blocking, findings=findings, category_breakdown=categories, entity_statuses=statuses,
            cycles_detected=sum(x.finding_type == ReferenceFindingType.REFERENCE_CYCLE for x in findings), orphans=sum(x.finding_type == ReferenceFindingType.ORPHANED_OBJECT for x in findings), duplicates=sum(x.finding_type == ReferenceFindingType.DUPLICATE_NAME for x in findings))

    @staticmethod
    def _builtins(vendor):
        return {Vendor.ASA: {"address": {"any", "any4", "any6"}, "service": {"ip", "icmp", "tcp", "udp"}}, Vendor.FORTIGATE: {"address": {"any"}, "service": {"any"}}}.get(vendor, {"address": {"any"}, "service": {"any"}})

    @staticmethod
    def _is_builtin(name, expected, builtins):
        return ((set(expected) & {"address", "address_group"}) and name in builtins["address"]) or ((set(expected) & {"service", "service_group"}) and name in builtins["service"])

    @staticmethod
    def _is_literal(name, expected):
        if not set(expected) & {"address", "address_group"}: return False
        try: ipaddress.ip_address(name); return True
        except ValueError: return False

    @staticmethod
    def _canonical_cycle(cycle):
        rotations = [cycle[i:] + cycle[:i] for i in range(len(cycle))]
        return min(rotations, key=lambda x: tuple(x))