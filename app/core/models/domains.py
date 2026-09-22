from pydantic import BaseModel, Field

from .firewall import ConfigDomain


class RouterInterface(BaseModel):
    name: str
    addresses: list[str] = Field(default_factory=list)
    description: str | None = None
    enabled: bool = True
    vrf: str | None = None


class RouterVRF(BaseModel):
    name: str
    route_distinguisher: str | None = None


class RouterStaticRoute(BaseModel):
    destination: str
    next_hop: str
    vrf: str | None = None
    interface: str | None = None


class PrefixListEntry(BaseModel):
    sequence: int
    prefix: str
    action: str = "permit"


class PrefixList(BaseModel):
    name: str
    entries: list[PrefixListEntry] = Field(default_factory=list)


class RoutePolicyTerm(BaseModel):
    name: str
    prefix_lists: list[str] = Field(default_factory=list)
    action: str


class RoutePolicy(BaseModel):
    name: str
    terms: list[RoutePolicyTerm] = Field(default_factory=list)


class OSPFArea(BaseModel):
    area_id: str
    interfaces: list[str] = Field(default_factory=list)


class OSPFProcess(BaseModel):
    process_id: str
    vrf: str | None = None
    areas: list[OSPFArea] = Field(default_factory=list)


class BGPNeighbor(BaseModel):
    address: str
    remote_as: int | None = None
    peer_group: str | None = None
    route_policy_in: str | None = None
    route_policy_out: str | None = None


class BGPNetwork(BaseModel):
    prefix: str
    route_policy: str | None = None


class BGPProcess(BaseModel):
    local_as: int
    vrf: str | None = None
    neighbors: list[BGPNeighbor] = Field(default_factory=list)
    networks: list[BGPNetwork] = Field(default_factory=list)


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


class VLAN(BaseModel):
    vlan_id: int
    name: str | None = None


class VLANMembership(BaseModel):
    vlan_id: int
    tagged: bool = False


class SwitchPort(BaseModel):
    name: str
    mode: str | None = None
    native_vlan: int | None = None
    allowed_vlans: list[int] = Field(default_factory=list)
    description: str | None = None
    enabled: bool = True
    lag: str | None = None


class LAG(BaseModel):
    name: str
    members: list[str] = Field(default_factory=list)
    lacp: bool = False


class SVI(BaseModel):
    name: str
    vlan_id: int
    addresses: list[str] = Field(default_factory=list)


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