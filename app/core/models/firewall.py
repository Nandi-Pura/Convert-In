from enum import StrEnum
import hashlib
from typing import Any
from pydantic import BaseModel, Field, field_validator, model_validator


class Vendor(StrEnum):
    ASA = "cisco_asa"
    FORTIGATE = "fortigate"
    PALO_ALTO = "paloalto"
    JUNIPER_SRX = "juniper_srx"
    CISCO_IOSXE = "cisco_iosxe"
    UNKNOWN = "unknown"


class ConfigDomain(StrEnum):
    FIREWALL = "FIREWALL"
    ROUTER = "ROUTER"
    SWITCH = "SWITCH"


class Severity(StrEnum):
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"


class ExtractionOutcome(StrEnum):
    NORMALIZED = "NORMALIZED"
    UNPARSED = "UNPARSED"
    SOURCE_UNSUPPORTED = "SOURCE_UNSUPPORTED"
    RECOVERED = "RECOVERED"
    IGNORED_NON_SEMANTIC = "IGNORED_NON_SEMANTIC"


class SourceExtractionItem(BaseModel):
    id: str
    source_vendor: Vendor
    source_version: str | None = None
    source_type: str
    source_name: str
    source_location: str | None = None
    outcome: ExtractionOutcome
    normalized_entity_ids: list[str] = Field(default_factory=list)
    reason: str | None = None
    parser_warning_ids: list[str] = Field(default_factory=list)


class ExtractionCategoryBreakdown(BaseModel):
    semantic_total: int = 0
    normalized: int = 0
    recovered: int = 0
    unparsed: int = 0
    unsupported: int = 0


class ExtractionCoverageReport(BaseModel):
    source_vendor: Vendor
    source_version: str | None = None
    semantic_total: int
    normalized: int
    recovered: int
    unparsed: int
    unsupported: int
    ignored_non_semantic: int
    coverage_percent: float | None
    category_breakdown: dict[str, ExtractionCategoryBreakdown] = Field(default_factory=dict)
    warnings: list[str] = Field(default_factory=list)
    blocking_issues: list[str] = Field(default_factory=list)
    items: list[SourceExtractionItem] = Field(default_factory=list)


class Provenance(BaseModel):
    source_vendor: Vendor
    source_version: str | None = None
    original_name: str | None = None
    original_reference: str | None = None
    source_line: int | None = None
    source_section: str | None = None


class Entity(BaseModel):
    id: str
    name: str
    description: str | None = None
    tags: list[str] = Field(default_factory=list)
    provenance: Provenance | None = None
    vendor_extensions: dict[str, Any] = Field(default_factory=dict)

    @field_validator("id", "name")
    @classmethod
    def non_empty(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("must not be empty")
        return value


class Address(Entity):
    type: str
    value: str | None = None
    members: list[str] = Field(default_factory=list)

    @field_validator("type")
    @classmethod
    def valid_type(cls, value: str) -> str:
        if value not in {"host", "network", "range", "fqdn", "group", "any"}:
            raise ValueError("unsupported address type")
        return value


class Service(Entity):
    protocol: str
    source_ports: list[str] = Field(default_factory=list)
    destination_ports: list[str] = Field(default_factory=list)
    members: list[str] = Field(default_factory=list)

    @field_validator("protocol")
    @classmethod
    def normalize_protocol(cls, value: str) -> str:
        value = value.lower()
        return value if value in {"tcp", "udp", "icmp", "ip", "any", "group", "tcp-udp"} else "ip"

    @field_validator("source_ports", "destination_ports")
    @classmethod
    def valid_ports(cls, values: list[str]) -> list[str]:
        for value in values:
            for part in value.split(","):
                bounds = part.strip().split("-", 1)
                if not all(x.isdigit() and 0 <= int(x) <= 65535 for x in bounds):
                    raise ValueError(f"invalid port range: {part}")
                if len(bounds) == 2 and int(bounds[0]) > int(bounds[1]):
                    raise ValueError(f"reversed port range: {part}")
        return values


class Interface(Entity):
    type: str = "physical"
    ipv4: list[str] = Field(default_factory=list)
    ipv6: list[str] = Field(default_factory=list)
    zone: str | None = None
    enabled: bool = True
    vlan: int | None = None
    parent: str | None = None


class Zone(Entity):
    interfaces: list[str] = Field(default_factory=list)


class SecurityRule(Entity):
    position: int
    ingress_interfaces: list[str] = Field(default_factory=list)
    egress_interfaces: list[str] = Field(default_factory=list)
    source_zones: list[str] = Field(default_factory=list)
    destination_zones: list[str] = Field(default_factory=list)
    sources: list[str] = Field(default_factory=lambda: ["any"])
    destinations: list[str] = Field(default_factory=lambda: ["any"])
    services: list[str] = Field(default_factory=lambda: ["any"])
    action: str = "unknown"
    enabled: bool = True
    log_start: bool = False
    log_end: bool = False

    @field_validator("position")
    @classmethod
    def positive_position(cls, value: int) -> int:
        if value < 1: raise ValueError("position must be positive")
        return value

    @field_validator("action")
    @classmethod
    def normalize_action(cls, value: str) -> str:
        return {"permit": "allow", "accept": "allow", "drop": "deny"}.get(value.lower(), value.lower()) if value.lower() in {"allow", "permit", "accept", "deny", "drop", "reject", "unknown"} else "unknown"


class NatRule(Entity):
    type: str
    position: int | None = None
    ingress_interface: str | None = None
    egress_interface: str | None = None
    source_zones: list[str] = Field(default_factory=list)
    destination_zones: list[str] = Field(default_factory=list)
    original_source: list[str] = Field(default_factory=list)
    translated_source: list[str] = Field(default_factory=list)
    original_destination: list[str] = Field(default_factory=list)
    translated_destination: list[str] = Field(default_factory=list)
    original_service: list[str] = Field(default_factory=list)
    translated_service: list[str] = Field(default_factory=list)
    translation_target: str | None = None
    identity: bool = False
    status: str = "MANUAL_REVIEW"


class StaticRoute(Entity):
    destination: str
    next_hop: str
    interface: str | None = None
    metric: int | None = None
    distance: int | None = None
    enabled: bool = True


class VpnObject(Entity):
    migration_status: str = "MANUAL_REVIEW"


class ParseIssue(BaseModel):
    severity: Severity
    vendor: Vendor
    section: str | None = None
    line: int | None = None
    object: str | None = None
    message: str
    raw_text: str | None = None


class UnparsedConstruct(BaseModel):
    vendor: Vendor
    section: str | None = None
    line_number: int | None = None
    raw_text: str
    reason: str
    severity: Severity = Severity.WARNING
    source_version: str | None = None
    category: str | None = None
    source_extraction_id: str | None = None
    unsupported: bool = False


class FirewallConfig(BaseModel):
    metadata: dict[str, Any] = Field(default_factory=dict)
    interfaces: list[Interface] = Field(default_factory=list)
    zones: list[Zone] = Field(default_factory=list)
    addresses: list[Address] = Field(default_factory=list)
    address_groups: list[Address] = Field(default_factory=list)
    services: list[Service] = Field(default_factory=list)
    service_groups: list[Service] = Field(default_factory=list)
    security_policies: list[SecurityRule] = Field(default_factory=list)
    nat_policies: list[NatRule] = Field(default_factory=list)
    static_routes: list[StaticRoute] = Field(default_factory=list)
    vpn_objects: list[VpnObject] = Field(default_factory=list)
    raw_vendor_extensions: dict[str, Any] = Field(default_factory=dict)
    warnings: list[ParseIssue] = Field(default_factory=list)
    unparsed_constructs: list[UnparsedConstruct] = Field(default_factory=list)
    extraction_coverage: ExtractionCoverageReport | None = None

    @model_validator(mode="after")
    def warn_duplicate_ids(self):
        collections = (self.interfaces, self.zones, self.addresses, self.address_groups, self.services, self.service_groups, self.security_policies, self.nat_policies, self.static_routes)
        for items in collections:
            seen: set[str] = set()
            for item in items:
                if item.id in seen:
                    self.warnings.append(ParseIssue(severity=Severity.WARNING, vendor=item.provenance.source_vendor if item.provenance else Vendor.UNKNOWN, object=item.id, message="Duplicate entity ID"))
                seen.add(item.id)
        return self

    def finalize_metrics(self, total: int) -> "FirewallConfig":
        collections = (self.interfaces, self.zones, self.addresses, self.address_groups, self.services, self.service_groups, self.security_policies, self.nat_policies, self.static_routes)
        existing = {(x.object, x.message) for x in self.warnings}
        for items in collections:
            seen: set[str] = set()
            for item in items:
                key = (item.id, "Duplicate entity ID")
                if item.id in seen and key not in existing:
                    self.warnings.append(ParseIssue(severity=Severity.WARNING, vendor=item.provenance.source_vendor if item.provenance else Vendor.UNKNOWN, object=item.id, message=key[1]))
                seen.add(item.id)
        self.metadata["parser_metrics"] = {
            "total_lines_or_nodes": total,
            "parsed_entities": sum(len(x) for x in (self.interfaces, self.zones, self.addresses, self.address_groups, self.services, self.service_groups, self.security_policies, self.nat_policies, self.static_routes)),
            "addresses": len(self.addresses), "groups": len(self.address_groups) + len(self.service_groups),
            "services": len(self.services), "policies": len(self.security_policies),
            "nat_rules": len(self.nat_policies), "routes": len(self.static_routes),
            "warnings": sum(x.severity == Severity.WARNING for x in self.warnings),
            "errors": sum(x.severity == Severity.ERROR for x in self.warnings),
            "unparsed": len(self.unparsed_constructs),
        }
        return self

    def finalize_extraction(self, vendor: Vendor, version: str | None, ignored: int = 0) -> "FirewallConfig":
        kinds = (("interfaces", "interface"), ("zones", "zone"), ("addresses", "address"), ("address_groups", "address_group"), ("services", "service"), ("service_groups", "service_group"), ("security_policies", "security_policy"), ("nat_policies", "nat"), ("static_routes", "route"), ("vpn_objects", "vpn"))
        items: list[SourceExtractionItem] = []
        def stable(kind: str, name: str, location: str) -> str:
            key = f"{vendor.value}|{kind}|{name}|{location}".encode()
            return "src-" + hashlib.sha256(key).hexdigest()[:16]
        by_location: dict[str, SourceExtractionItem] = {}
        for attr, kind in kinds:
            for entity in getattr(self, attr):
                p = entity.provenance; line = p.source_line if p else None; location = f"line {line}" if line else (p.source_section if p else None) or "unknown"
                recovered = bool(entity.vendor_extensions.get("truncated_block"))
                if location in by_location:
                    by_location[location].normalized_entity_ids.append(entity.id)
                    if recovered: by_location[location].outcome=ExtractionOutcome.RECOVERED; by_location[location].reason="Parser recovered an incomplete construct."
                else:
                    item=SourceExtractionItem(id=stable(kind, entity.name, location), source_vendor=vendor, source_version=version, source_type=kind, source_name=entity.name, source_location=location, outcome=ExtractionOutcome.RECOVERED if recovered else ExtractionOutcome.NORMALIZED, normalized_entity_ids=[entity.id], reason="Parser recovered an incomplete construct." if recovered else None)
                    by_location[location]=item; items.append(item)
        for entry in self.unparsed_constructs:
            location = f"line {entry.line_number}" if entry.line_number else entry.section or "unknown"; kind = entry.category or entry.section or "other/unparsed"; name = entry.section or "construct"
            if location in by_location and entry.reason == "Unsupported field preserved":
                by_location[location].outcome=ExtractionOutcome.RECOVERED; by_location[location].reason="Normalized with unsupported source fields preserved for review."
                entry.source_extraction_id=by_location[location].id; entry.source_version=version; entry.category=kind
                continue
            outcome = ExtractionOutcome.SOURCE_UNSUPPORTED if entry.unsupported else ExtractionOutcome.UNPARSED
            item_id = stable(kind, name, location); entry.source_extraction_id = item_id; entry.source_version = version; entry.category = kind
            items.append(SourceExtractionItem(id=item_id, source_vendor=vendor, source_version=version, source_type=kind, source_name=name, source_location=location, outcome=outcome, reason=entry.reason))
        counts = {outcome: sum(x.outcome == outcome for x in items) for outcome in ExtractionOutcome}
        semantic_total = counts[ExtractionOutcome.NORMALIZED] + counts[ExtractionOutcome.RECOVERED] + counts[ExtractionOutcome.UNPARSED] + counts[ExtractionOutcome.SOURCE_UNSUPPORTED]
        categories: dict[str, ExtractionCategoryBreakdown] = {}
        for item in items:
            if item.outcome == ExtractionOutcome.IGNORED_NON_SEMANTIC: continue
            row = categories.setdefault(item.source_type, ExtractionCategoryBreakdown()); row.semantic_total += 1
            setattr(row, {ExtractionOutcome.NORMALIZED:"normalized", ExtractionOutcome.RECOVERED:"recovered", ExtractionOutcome.UNPARSED:"unparsed", ExtractionOutcome.SOURCE_UNSUPPORTED:"unsupported"}[item.outcome], getattr(row, {ExtractionOutcome.NORMALIZED:"normalized", ExtractionOutcome.RECOVERED:"recovered", ExtractionOutcome.UNPARSED:"unparsed", ExtractionOutcome.SOURCE_UNSUPPORTED:"unsupported"}[item.outcome]) + 1)
        effective = counts[ExtractionOutcome.NORMALIZED] + counts[ExtractionOutcome.RECOVERED]
        self.extraction_coverage = ExtractionCoverageReport(source_vendor=vendor, source_version=version, semantic_total=semantic_total, normalized=counts[ExtractionOutcome.NORMALIZED], recovered=counts[ExtractionOutcome.RECOVERED], unparsed=counts[ExtractionOutcome.UNPARSED], unsupported=counts[ExtractionOutcome.SOURCE_UNSUPPORTED], ignored_non_semantic=ignored, coverage_percent=round(effective / semantic_total * 100, 2) if semantic_total else None, category_breakdown=categories, warnings=[x.message for x in self.warnings if x.severity != Severity.ERROR], blocking_issues=[x.message for x in self.warnings if x.severity == Severity.ERROR], items=items)
        return self