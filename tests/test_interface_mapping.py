from app.core.hardware import PortMappingStatus
from app.core.migration.interface_mapping import (
    apply_interface_mappings,
    required_source_interfaces,
    validate_interface_mappings,
)
from app.core.migration import MigrationMappings, MigrationPlanner, build_plan_artifact
from app.core.migration.models import InterfaceMapping
from app.core.models import FirewallConfig, Interface, NatRule, SecurityRule, StaticRoute, Vendor, Zone
from app.core.renderers import PaloAltoRenderer
from app.core.semantic_diff import build_semantic_diff
from app.core.versions.models import VersionContext


def config():
    return FirewallConfig(
        metadata={"source_vendor": Vendor.PALO_ALTO},
        interfaces=[
            Interface(id="interface:ethernet1/2", name="ethernet1/2", ipv4=["10.0.0.1/24"], description="inside", virtual_router="default"),
            Interface(id="interface:ethernet1/2.100", name="ethernet1/2.100", type="subinterface", parent="ethernet1/2", vlan=100, ipv4=["10.0.100.1/24"], virtual_router="default"),
            Interface(id="interface:ethernet1/3", name="ethernet1/3"),
        ],
        zones=[Zone(id="zone:trust", name="trust", interfaces=["ethernet1/2", "ethernet1/2.100"])],
        static_routes=[StaticRoute(id="route:default:r1", name="r1", destination="0.0.0.0/0", next_hop="10.0.0.254", interface="ethernet1/2", virtual_router="default")],
        security_policies=[SecurityRule(id="security_policy:p1", name="p1", position=1, ingress_interfaces=["ethernet1/2"], egress_interfaces=["ethernet1/2.100"], action="allow")],
        nat_policies=[NatRule(id="nat_policy:n1", name="n1", type="interface_address_pat", ingress_interface="ethernet1/2", egress_interface="ethernet1/2.100", translation_target="ethernet1/2", position=1)],
    )


def confirmed(source="ethernet1/2", target="ethernet1/6"):
    return InterfaceMapping(
        source_hardware_id="paloalto-pa5220", source_interface=source,
        target_hardware_id="paloalto-pa5410", target_interface=target,
        confirmed=True, confirmed_by_user=True,
    )


def test_required_interfaces_include_only_semantically_used_physical_ports():
    assert required_source_interfaces(config()) == ["ethernet1/2"]


def test_manual_mapping_validation_requires_confirmation_and_rejects_unknown_or_duplicate_targets():
    cfg = config()
    missing = validate_interface_mappings(cfg, "paloalto-pa5220", "paloalto-pa5410", [])
    assert not missing.valid_for_conversion
    assert missing.summary.required == 1 and missing.summary.unmapped == 1

    unconfirmed = confirmed().model_copy(update={"confirmed_by_user": False})
    result = validate_interface_mappings(cfg, "paloalto-pa5220", "paloalto-pa5410", [unconfirmed])
    assert not result.valid_for_conversion
    assert result.mappings[0].status == PortMappingStatus.UNMAPPED

    unknown = confirmed(target="ethernet1/99")
    result = validate_interface_mappings(cfg, "paloalto-pa5220", "paloalto-pa5410", [unknown])
    assert result.mappings[0].status == PortMappingStatus.INCOMPATIBLE
    assert not result.valid_for_conversion

    cfg.interfaces[2].ipv4 = ["10.3.0.1/24"]
    duplicate = validate_interface_mappings(cfg, "paloalto-pa5220", "paloalto-pa5410", [confirmed(), confirmed("ethernet1/3", "ethernet1/6")])
    assert not duplicate.valid_for_conversion
    assert duplicate.summary.incompatible == 2
    assert any("duplicate" in reason.lower() for reason in duplicate.blocking_reasons)


def test_identity_mapping_is_exact_only_after_explicit_confirmation():
    result = validate_interface_mappings(config(), "paloalto-pa5220", "paloalto-pa5410", [confirmed(target="ethernet1/2")])
    assert result.valid_for_conversion
    assert result.mappings[0].status == PortMappingStatus.EXACT


def test_structural_remap_keeps_source_and_updates_every_supported_dependency():
    source = config()
    source.interfaces[0].description = "Uplink previously on ethernet1/2"
    validation = validate_interface_mappings(source, "paloalto-pa5220", "paloalto-pa5410", [confirmed()])
    assert validation.valid_for_conversion
    target = apply_interface_mappings(source, validation)

    assert source.interfaces[0].name == "ethernet1/2"
    assert [item.name for item in target.interfaces[:2]] == ["ethernet1/6", "ethernet1/6.100"]
    assert target.interfaces[0].id == "interface:ethernet1/2"
    assert target.interfaces[0].description == "Uplink previously on ethernet1/2"
    assert target.interfaces[1].parent == "ethernet1/6" and target.interfaces[1].vlan == 100
    assert target.zones[0].interfaces == ["ethernet1/6", "ethernet1/6.100"]
    assert target.static_routes[0].interface == "ethernet1/6"
    assert target.static_routes[0].virtual_router == "default"
    assert target.security_policies[0].ingress_interfaces == ["ethernet1/6"]
    assert target.security_policies[0].egress_interfaces == ["ethernet1/6.100"]
    assert target.nat_policies[0].ingress_interface == "ethernet1/6"
    assert target.nat_policies[0].egress_interface == "ethernet1/6.100"
    assert target.nat_policies[0].translation_target == "ethernet1/6"


def test_breakout_and_stale_hardware_mappings_do_not_pass():
    breakout = validate_interface_mappings(config(), "paloalto-pa5220", "paloalto-pa5410", [confirmed(target="ethernet1/25")])
    assert not breakout.valid_for_conversion
    assert breakout.mappings[0].status == PortMappingStatus.UNVERIFIED

    stale = confirmed().model_copy(update={"target_hardware_id": "paloalto-pa5420"})
    result = validate_interface_mappings(config(), "paloalto-pa5220", "paloalto-pa5410", [stale])
    assert not result.valid_for_conversion
    assert result.mappings[0].status == PortMappingStatus.UNVERIFIED

def panos_11_1():
    return VersionContext(vendor=Vendor.PALO_ALTO, os_name="PAN-OS", selected_version="11.1", selected_family="11.1")


def hardware_mappings(items):
    return MigrationMappings(
        source_hardware_id="paloalto-pa5220",
        target_hardware_id="paloalto-pa5410",
        interfaces=items,
    )


def test_planner_uses_remapped_target_semantics_and_preserves_source_semantics():
    source = config()
    source.interfaces[0].configured_speed = "1G"
    plan = MigrationPlanner().plan(source, hardware_mappings([confirmed()]), panos_11_1(), panos_11_1())

    assert not plan.blocked
    assert plan.interface_mapping and plan.interface_mapping.valid_for_conversion
    physical = next(item for item in plan.compatibility if item.entity_id == "interface:ethernet1/2")
    child = next(item for item in plan.compatibility if item.entity_id == "interface:ethernet1/2.100")
    route = next(item for item in plan.compatibility if item.entity_id == "route:default:r1")
    assert physical.source_semantic["name"] == "ethernet1/2"
    assert physical.target_semantic["name"] == "ethernet1/6"
    assert child.source_semantic["parent"] == "ethernet1/2"
    assert child.target_semantic["name"] == "ethernet1/6.100"
    assert route.source_semantic["interface"] == "ethernet1/2"
    assert route.target_semantic["interface"] == "ethernet1/6"

    lines, report = PaloAltoRenderer().render(plan)
    semantic_lines = [line for line in lines if "description" not in line and "comment" not in line]
    assert any("network interface ethernet ethernet1/6 layer3" in line for line in lines)
    assert "set network interface ethernet ethernet1/6 link-speed 1000" in lines
    assert any("ethernet1/6.100" in line for line in lines)
    assert any("static-route r1 interface ethernet1/6" in line for line in lines)
    assert all("ethernet1/2" not in line for line in semantic_lines)
    assert report.interface_mapping and report.interface_mapping.valid_for_conversion

    context = {"domain": "FIREWALL", "vendor": "paloalto", "platform": "PAN_OS", "exact_version": "11.1"}
    diff = build_semantic_diff(
        source,
        plan.compatibility,
        context,
        context,
        mappings=plan.mappings.model_dump(mode="json"),
    )
    identities = {item.source_identity: item.target_identity for item in diff.entities}
    assert identities["ethernet1/2"] == "ethernet1/6"
    assert identities["ethernet1/2.100"] == "ethernet1/6.100"
    artifact = build_plan_artifact(plan, source)
    assert artifact.interface_mapping and artifact.interface_mapping.mappings[0].target_interface == "ethernet1/6"
    assert {"PA-5220-DATAPLANE-PORTS", "PA-5410-DATAPLANE-PORTS"} <= set(artifact.documentation_refs)


def test_planner_blocks_candidate_generation_until_required_mapping_is_confirmed():
    plan = MigrationPlanner().plan(config(), hardware_mappings([]), panos_11_1(), panos_11_1())
    assert plan.interface_mapping and not plan.interface_mapping.valid_for_conversion
    assert plan.interface_mapping.summary.unmapped == 1
    assert plan.blocked
    assert not plan.generate

def test_explicit_normalized_speed_is_required_on_the_target():
    cfg = config()
    cfg.interfaces[0].configured_speed = "1G"
    compatible = validate_interface_mappings(cfg, "paloalto-pa5220", "paloalto-pa5410", [confirmed()])
    assert compatible.valid_for_conversion
    assert any("1G" in reason for reason in compatible.mappings[0].compatibility_reasons)

    cfg.interfaces[0].vendor_extensions["unverified_link_speed"] = "unexpected"
    unverified = validate_interface_mappings(cfg, "paloalto-pa5220", "paloalto-pa5410", [confirmed()])
    assert not unverified.valid_for_conversion
    assert unverified.mappings[0].status == PortMappingStatus.UNVERIFIED

def test_subinterface_target_identity_collision_blocks_mapping():
    cfg = config()
    cfg.interfaces.append(Interface(
        id="interface:ethernet1/2.200",
        name="ethernet1/2.200",
        type="subinterface",
        parent="ethernet1/2",
        vlan=100,
    ))

    result = validate_interface_mappings(cfg, "paloalto-pa5220", "paloalto-pa5410", [confirmed()])

    assert not result.valid_for_conversion
    assert result.mappings[0].status == PortMappingStatus.INCOMPATIBLE
    assert "collision" in " ".join(result.mappings[0].compatibility_reasons).lower()

def test_missing_explicit_subinterface_vlan_blocks_mapping_before_remap():
    cfg = config()
    cfg.interfaces[1].vlan = None
    result = validate_interface_mappings(cfg, "paloalto-pa5220", "paloalto-pa5410", [confirmed()])
    assert not result.valid_for_conversion
    assert result.mappings[0].status == PortMappingStatus.INCOMPATIBLE
    assert "explicit vlan" in " ".join(result.mappings[0].compatibility_reasons).lower()
    assert result.mappings[0].source_evidence_refs
    assert result.mappings[0].target_evidence_refs