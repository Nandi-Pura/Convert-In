from typing import Any
from pydantic import BaseModel, Field

from .firewall import ConfigDomain, ExtractionCoverageReport, ParseIssue, Provenance, UnparsedConstruct


class RouterEntity(BaseModel):
    id: str = ""
    name: str = ""
    provenance: Provenance | None = None
    vendor_extensions: dict[str, Any] = Field(default_factory=dict)


class RouterInterface(RouterEntity):
    name: str
    addresses: list[str] = Field(default_factory=list)
    description: str | None = None
    enabled: bool = True
    vrf: str | None = None


class RouterVRF(RouterEntity):
    name: str
    route_distinguisher: str | None = None


class RouterStaticRoute(RouterEntity):
    destination: str
    next_hop: str
    vrf: str | None = None
    interface: str | None = None
    distance: int | None = None


class PrefixListEntry(BaseModel):
    id: str
    name: str
    sequence: int
    prefix: str
    action: str = "permit"
    ge: int | None = None
    le: int | None = None
    provenance: Provenance | None = None


class PrefixList(RouterEntity):
    name: str
    entries: list[PrefixListEntry] = Field(default_factory=list)


class RoutePolicyTerm(BaseModel):
    id: str
    name: str
    prefix_lists: list[str] = Field(default_factory=list)
    action: str
    sequence: int = 10
    match_statements: list[str] = Field(default_factory=list)
    set_statements: list[str] = Field(default_factory=list)
    provenance: Provenance | None = None


class RoutePolicy(RouterEntity):
    name: str
    terms: list[RoutePolicyTerm] = Field(default_factory=list)


class OSPFArea(BaseModel):
    area_id: str
    interfaces: list[str] = Field(default_factory=list)
    networks: list[str] = Field(default_factory=list)


class OSPFProcess(RouterEntity):
    process_id: str
    vrf: str | None = None
    areas: list[OSPFArea] = Field(default_factory=list)
    router_id: str | None = None


class BGPNeighbor(RouterEntity):
    address: str
    remote_as: int | None = None
    peer_group: str | None = None
    route_policy_in: str | None = None
    route_policy_out: str | None = None
    description: str | None = None
    update_source: str | None = None


class BGPNetwork(BaseModel):
    prefix: str
    route_policy: str | None = None


class BGPProcess(RouterEntity):
    local_as: int
    vrf: str | None = None
    neighbors: list[BGPNeighbor] = Field(default_factory=list)
    networks: list[BGPNetwork] = Field(default_factory=list)
    router_id: str | None = None


class RouterConfig(BaseModel):
    domain: ConfigDomain = ConfigDomain.ROUTER
    hostname: str | None = None
    interfaces: list[RouterInterface] = Field(default_factory=list)
    vrfs: list[RouterVRF] = Field(default_factory=list)
    static_routes: list[RouterStaticRoute] = Field(default_factory=list)
    prefix_lists: list[PrefixList] = Field(default_factory=list)
    route_policies: list[RoutePolicy] = Field(default_factory=list)
    ospf_processes: list[OSPFProcess] = Field(default_factory=list)
    bgp_processes: list[BGPProcess] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    warnings: list[ParseIssue] = Field(default_factory=list)
    unparsed_constructs: list[UnparsedConstruct] = Field(default_factory=list)
    extraction_coverage: ExtractionCoverageReport | None = None


class VLAN(BaseModel):
    id: str = ""
    vlan_id: int
    name: str | None = None
    provenance: Provenance | None = None
    vendor_extensions: dict[str, Any] = Field(default_factory=dict)


class VLANMembership(BaseModel):
    vlan_id: int
    tagged: bool = False


class SwitchPort(BaseModel):
    id: str = ""
    name: str
    mode: str | None = None
    access_vlan: int | None = None
    native_vlan: int | None = None
    allowed_vlans: list[int] = Field(default_factory=list)
    description: str | None = None
    enabled: bool = True
    lag: str | None = None
    provenance: Provenance | None = None
    vendor_extensions: dict[str, Any] = Field(default_factory=dict)


class LAG(BaseModel):
    id: str = ""
    name: str
    members: list[str] = Field(default_factory=list)
    lacp: bool = False
    lacp_mode: str | None = None
    mode: str | None = None
    native_vlan: int | None = None
    allowed_vlans: list[int] = Field(default_factory=list)
    description: str | None = None
    enabled: bool = True
    provenance: Provenance | None = None
    vendor_extensions: dict[str, Any] = Field(default_factory=dict)


class SVI(BaseModel):
    id: str = ""
    name: str
    vlan_id: int
    addresses: list[str] = Field(default_factory=list)
    description: str | None = None
    enabled: bool = True
    provenance: Provenance | None = None
    vendor_extensions: dict[str, Any] = Field(default_factory=dict)


class STPConfig(BaseModel):
    mode: str | None = None
    priority: int | None = None


class SwitchACLReference(BaseModel):
    port: str
    acl: str
    direction: str


class SwitchConfig(BaseModel):
    domain: ConfigDomain = ConfigDomain.SWITCH
    vlans: list[VLAN] = Field(default_factory=list)
    ports: list[SwitchPort] = Field(default_factory=list)
    lags: list[LAG] = Field(default_factory=list)
    svis: list[SVI] = Field(default_factory=list)
    stp: STPConfig | None = None
    acl_references: list[SwitchACLReference] = Field(default_factory=list)
    vendor_extensions: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)
    warnings: list[ParseIssue] = Field(default_factory=list)
    unparsed_constructs: list[UnparsedConstruct] = Field(default_factory=list)
    extraction_coverage: ExtractionCoverageReport | None = None