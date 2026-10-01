from collections import Counter

from app.core.hardware import (
    candidate_target_ports,
    PortMappingStatus,
    PortSpeed,
    SourceInterfaceContext,
    evaluate_port_compatibility,
    port_capability,
)
from app.core.models import FirewallConfig

from .models import InterfaceMapping, InterfaceMappingSummary, InterfaceMappingValidation


def _physical_name(config: FirewallConfig, interface_name: str) -> str | None:
    by_name = {interface.name: interface for interface in config.interfaces}
    interface = by_name.get(interface_name)
    if interface is None:
        return None
    if interface.type == "subinterface" or interface.parent:
        return interface.parent
    return interface.name


def required_source_interfaces(config: FirewallConfig) -> list[str]:
    required: set[str] = set()

    def add(interface_name: str | None) -> None:
        if interface_name:
            physical = _physical_name(config, interface_name)
            if physical:
                required.add(physical)

    for interface in config.interfaces:
        if interface.type == "subinterface" or interface.parent:
            add(interface.parent)
        elif interface.ipv4 or interface.ipv6 or interface.zone or interface.virtual_router:
            add(interface.name)
    for zone in config.zones:
        for interface_name in zone.interfaces:
            add(interface_name)
    for route in config.static_routes:
        add(route.interface)
    for rule in config.security_policies:
        for interface_name in (*rule.ingress_interfaces, *rule.egress_interfaces):
            add(interface_name)
    for rule in config.nat_policies:
        add(rule.ingress_interface)
        add(rule.egress_interface)
        add(rule.translation_target)

    return [
        interface.name
        for interface in config.interfaces
        if interface.name in required and interface.type != "subinterface" and not interface.parent
    ]


def _source_context(config: FirewallConfig, source_interface: str) -> SourceInterfaceContext:
    interface = next(item for item in config.interfaces if item.name == source_interface)
    children = [item for item in config.interfaces if item.parent == source_interface]
    configured_speed = None
    if interface.configured_speed:
        try:
            configured_speed = PortSpeed(interface.configured_speed)
        except ValueError:
            configured_speed = None
    return SourceInterfaceContext(
        configured_speed=configured_speed,
        requires_layer3=True,
        requires_subinterface=bool(children),
    )


def validate_interface_mappings(
    config: FirewallConfig,
    source_hardware_id: str,
    target_hardware_id: str,
    mappings: list[InterfaceMapping],
) -> InterfaceMappingValidation:
    required = required_source_interfaces(config)
    by_source = {mapping.source_interface: mapping for mapping in mappings}
    interface_ids = {interface.name: interface.id for interface in config.interfaces}
    evaluated: list[InterfaceMapping] = []

    for source_interface in required:
        supplied = by_source.get(source_interface)
        mapping = supplied.model_copy(deep=True) if supplied else InterfaceMapping(source_interface=source_interface)
        mapping.source_entity_id = interface_ids.get(source_interface)
        mapping.source_hardware_id = mapping.source_hardware_id or source_hardware_id
        mapping.target_hardware_id = mapping.target_hardware_id or target_hardware_id

        if not mapping.target_interface or not mapping.confirmed_by_user:
            mapping.status = PortMappingStatus.UNMAPPED
            mapping.compatibility_reasons = ["A target dataplane port must be selected and explicitly confirmed."]
            evaluated.append(mapping)
            continue
        if mapping.source_hardware_id != source_hardware_id or mapping.target_hardware_id != target_hardware_id:
            mapping.status = PortMappingStatus.UNVERIFIED
            mapping.compatibility_reasons = ["The saved mapping belongs to a different source or target hardware context."]
            evaluated.append(mapping)
            continue

        source_interface_model = next(item for item in config.interfaces if item.name == source_interface)
        source = port_capability(source_hardware_id, source_interface)
        target = port_capability(target_hardware_id, mapping.target_interface)
        mapping.source_evidence_refs = list(source.evidence_refs) if source else []
        mapping.target_evidence_refs = list(target.evidence_refs) if target else []
        missing_vlan = [item.name for item in config.interfaces if item.parent == source_interface and item.vlan is None]
        if missing_vlan:
            mapping.status = PortMappingStatus.INCOMPATIBLE
            mapping.compatibility_reasons = [f"Explicit VLAN tag is required for subinterface {name}." for name in missing_vlan]
            evaluated.append(mapping)
            continue
        if source_interface_model.vendor_extensions.get("unverified_link_speed"):
            mapping.status = PortMappingStatus.UNVERIFIED
            mapping.compatibility_reasons = ["Configured source link speed is not a verified normalized PAN-OS value."]
            evaluated.append(mapping)
            continue
        compatibility = evaluate_port_compatibility(source, target, _source_context(config, source_interface))
        mapping.status = compatibility.status
        mapping.compatibility_reasons = list(compatibility.reasons)
        if compatibility.status == PortMappingStatus.COMPATIBLE and source_interface == mapping.target_interface:
            mapping.status = PortMappingStatus.EXACT
        evaluated.append(mapping)

    compatible_physical = {
        mapping.source_interface: mapping.target_interface
        for mapping in evaluated
        if mapping.target_interface and mapping.status in {PortMappingStatus.EXACT, PortMappingStatus.COMPATIBLE}
    }
    predicted: dict[str, list[str]] = {}
    for interface in config.interfaces:
        owner = interface.parent if interface.type == "subinterface" or interface.parent else interface.name
        if interface.parent in compatible_physical and interface.vlan is not None:
            target_name = f"{compatible_physical[interface.parent]}.{interface.vlan}"
        else:
            target_name = compatible_physical.get(interface.name, interface.name)
        predicted.setdefault(target_name, []).append(owner)
    collisions = {
        target_name: set(owners)
        for target_name, owners in predicted.items()
        if len(owners) > 1
    }
    for mapping in evaluated:
        collision_names = [name for name, owners in collisions.items() if mapping.source_interface in owners]
        if collision_names:
            mapping.status = PortMappingStatus.INCOMPATIBLE
            mapping.compatibility_reasons.insert(
                0,
                f"Target interface identity collision: {', '.join(sorted(collision_names))}.",
            )
    target_counts = Counter(
        mapping.target_interface
        for mapping in evaluated
        if mapping.target_interface and mapping.confirmed_by_user
    )
    duplicate_targets = {target for target, count in target_counts.items() if count > 1}
    for mapping in evaluated:
        if mapping.target_interface in duplicate_targets:
            mapping.status = PortMappingStatus.INCOMPATIBLE
            mapping.compatibility_reasons.insert(0, f"Target interface {mapping.target_interface} has a duplicate assignment.")

    counts = Counter(mapping.status for mapping in evaluated)
    summary = InterfaceMappingSummary(
        required=len(required),
        mapped=sum(counts[status] for status in (PortMappingStatus.EXACT, PortMappingStatus.COMPATIBLE)),
        exact=counts[PortMappingStatus.EXACT],
        compatible=counts[PortMappingStatus.COMPATIBLE],
        unmapped=counts[PortMappingStatus.UNMAPPED],
        incompatible=counts[PortMappingStatus.INCOMPATIBLE],
        unverified=counts[PortMappingStatus.UNVERIFIED],
    )
    blocking_reasons = [
        reason
        for mapping in evaluated
        if mapping.status not in {PortMappingStatus.EXACT, PortMappingStatus.COMPATIBLE}
        for reason in mapping.compatibility_reasons
    ]
    evidence_refs = list(dict.fromkeys(
        reference
        for mapping in evaluated
        for reference in (*mapping.source_evidence_refs, *mapping.target_evidence_refs)
    ))
    return InterfaceMappingValidation(
        source_hardware_id=source_hardware_id,
        target_hardware_id=target_hardware_id,
        mappings=evaluated,
        summary=summary,
        valid_for_conversion=not blocking_reasons,
        blocking_reasons=list(dict.fromkeys(blocking_reasons)),
        evidence_refs=evidence_refs,
    )


def apply_interface_mappings(config: FirewallConfig, validation: InterfaceMappingValidation) -> FirewallConfig:
    if not validation.valid_for_conversion:
        raise ValueError("Interface mappings must be valid before structural remapping")
    target = config.model_copy(deep=True)
    physical = {
        mapping.source_interface: mapping.target_interface
        for mapping in validation.mappings
        if mapping.target_interface and mapping.status in {PortMappingStatus.EXACT, PortMappingStatus.COMPATIBLE}
    }
    names = dict(physical)
    for interface in target.interfaces:
        if interface.parent in physical:
            if interface.vlan is None:
                raise ValueError(f"Subinterface {interface.name} requires an explicit VLAN tag")
            remapped_parent = physical[interface.parent]
            names[interface.name] = f"{remapped_parent}.{interface.vlan}"

    for interface in target.interfaces:
        original_name = interface.name
        interface.name = names.get(original_name, original_name)
        if interface.parent:
            interface.parent = physical.get(interface.parent, interface.parent)
    for zone in target.zones:
        zone.interfaces = [names.get(name, name) for name in zone.interfaces]
    for route in target.static_routes:
        if route.interface:
            route.interface = names.get(route.interface, route.interface)
    for rule in target.security_policies:
        rule.ingress_interfaces = [names.get(name, name) for name in rule.ingress_interfaces]
        rule.egress_interfaces = [names.get(name, name) for name in rule.egress_interfaces]
    for rule in target.nat_policies:
        if rule.ingress_interface:
            rule.ingress_interface = names.get(rule.ingress_interface, rule.ingress_interface)
        if rule.egress_interface:
            rule.egress_interface = names.get(rule.egress_interface, rule.egress_interface)
        if rule.translation_target:
            rule.translation_target = names.get(rule.translation_target, rule.translation_target)
    return target

def _capability_payload(capability):
    if capability is None:
        return None
    return {
        "hardware_id": capability.hardware_id,
        "interface_name": capability.interface_name,
        "physical_port_number": capability.physical_port_number,
        "interface_family": capability.interface_family,
        "connector": capability.connector.value,
        "media_capability": capability.media_capability.value,
        "supported_speeds": [speed.value for speed in capability.supported_speeds],
        "supports_layer3": capability.supports_layer3,
        "supports_subinterface": capability.supports_subinterface,
        "supports_aggregate_membership": capability.supports_aggregate_membership,
        "breakout_capable": capability.breakout_capable,
        "breakout_parent": capability.breakout_parent,
        "evidence_refs": list(capability.evidence_refs),
        "constraints": list(capability.constraints),
    }


def interface_mapping_contract(
    config: FirewallConfig,
    source_hardware_id: str,
    target_hardware_id: str,
    mappings: list[InterfaceMapping],
) -> dict:
    validation = validate_interface_mappings(
        config,
        source_hardware_id,
        target_hardware_id,
        mappings,
    )
    by_source = {mapping.source_interface: mapping for mapping in validation.mappings}
    assigned = {
        mapping.target_interface
        for mapping in validation.mappings
        if mapping.confirmed_by_user and mapping.target_interface
    }
    interfaces = []
    for source_interface in required_source_interfaces(config):
        source_model = next(item for item in config.interfaces if item.name == source_interface)
        candidates = candidate_target_ports(
            source_hardware_id,
            source_interface,
            target_hardware_id,
            _source_context(config, source_interface),
            assigned,
        )
        if source_model.vendor_extensions.get("unverified_link_speed"):
            candidates = tuple(TargetPortCandidate(
                target_interface=candidate.target_interface,
                status=PortMappingStatus.UNVERIFIED,
                reasons=("Configured source link speed is not a verified normalized PAN-OS value.",),
                already_assigned=candidate.already_assigned,
                evidence_refs=candidate.evidence_refs,
            ) for candidate in candidates)
        interfaces.append({
            "source_interface": source_interface,
            "required": True,
            "source_capability": _capability_payload(port_capability(source_hardware_id, source_interface)),
            "mapping": by_source[source_interface].model_dump(mode="json"),
            "target_candidates": [{
                "target_interface": candidate.target_interface,
                "status": candidate.status.value,
                "reasons": list(candidate.reasons),
                "already_assigned": candidate.already_assigned,
                "evidence_refs": list(candidate.evidence_refs),
            } for candidate in candidates],
        })
    return {
        "source_hardware_id": source_hardware_id,
        "target_hardware_id": target_hardware_id,
        "interfaces": interfaces,
        "summary": validation.summary.model_dump(mode="json"),
        "valid_for_conversion": validation.valid_for_conversion,
        "blocking_reasons": validation.blocking_reasons,
        "evidence_refs": validation.evidence_refs,
    }
