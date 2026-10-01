from app.core.documentation import documentation_reference

from .models import (
    MediaCapability,
    PortCapability,
    PortCompatibility,
    PortConnector,
    PortMappingStatus,
    PortSpeed,
    SourceInterfaceContext,
    TargetPortCandidate,
)

_PA5220 = "paloalto-pa5220"
_PA5410 = "paloalto-pa5410"
_PA5220_REF = "PA-5220-DATAPLANE-PORTS"
_PA5410_REF = "PA-5410-DATAPLANE-PORTS"


def _ports(hardware_id, numbers, connector, speeds, evidence, *, breakout_capable=False, breakout_parents=None):
    breakout_parents = breakout_parents or {}
    return tuple(
        PortCapability(
            hardware_id=hardware_id,
            interface_name=f"ethernet1/{number}",
            physical_port_number=number,
            interface_family="ethernet",
            connector=connector,
            media_capability=MediaCapability.COPPER if connector == PortConnector.RJ45 else MediaCapability.TRANSCEIVER,
            supported_speeds=speeds,
            supports_layer3=True,
            supports_subinterface=True,
            supports_aggregate_membership=False,
            breakout_capable=breakout_capable,
            breakout_parent=breakout_parents.get(number),
            evidence_refs=(evidence,),
            constraints=("Breakout configuration is required and is not automated by ConfigMorph.",) if number in breakout_parents else (),
        )
        for number in numbers
    )


_PA5410_BREAKOUT = {
    number: f"ethernet1/{41 + (number - 25) // 4}"
    for number in range(25, 41)
}

PORT_CAPABILITIES = (
    *_ports(_PA5220, range(1, 5), PortConnector.RJ45, (PortSpeed.M100, PortSpeed.G1, PortSpeed.G10), _PA5220_REF),
    *_ports(_PA5220, range(5, 21), PortConnector.SFP_PLUS, (PortSpeed.G1, PortSpeed.G10), _PA5220_REF),
    *_ports(_PA5220, range(21, 25), PortConnector.QSFP_PLUS, (PortSpeed.G40,), _PA5220_REF),
    *_ports(_PA5410, range(1, 9), PortConnector.RJ45, (PortSpeed.M10, PortSpeed.M100, PortSpeed.G1, PortSpeed.G2_5, PortSpeed.G5, PortSpeed.G10), _PA5410_REF),
    *_ports(_PA5410, range(9, 21), PortConnector.SFP_PLUS, (PortSpeed.G1, PortSpeed.G10), _PA5410_REF),
    *_ports(_PA5410, range(21, 25), PortConnector.SFP28, (PortSpeed.G1, PortSpeed.G10, PortSpeed.G25), _PA5410_REF),
    *_ports(_PA5410, range(25, 41), PortConnector.QSFP28, (PortSpeed.G10, PortSpeed.G25), _PA5410_REF, breakout_parents=_PA5410_BREAKOUT),
    *_ports(_PA5410, range(41, 45), PortConnector.QSFP28, (PortSpeed.G40, PortSpeed.G100), _PA5410_REF, breakout_capable=True),
)


def _validate_registry(ports):
    keys = set()
    physical = set()
    for port in ports:
        key = (port.hardware_id, port.interface_name)
        physical_key = (port.hardware_id, port.physical_port_number)
        if key in keys or physical_key in physical:
            raise ValueError("Duplicate hardware port identity")
        if not port.evidence_refs:
            raise ValueError("Port capability evidence required")
        for reference in port.evidence_refs:
            documentation_reference(reference)
        keys.add(key)
        physical.add(physical_key)
    return tuple(sorted(ports, key=lambda item: (item.hardware_id, int(item.physical_port_number))))


PORT_CAPABILITIES = _validate_registry(PORT_CAPABILITIES)
_PORT_INDEX = {(port.hardware_id, port.interface_name): port for port in PORT_CAPABILITIES}
_PORTS_BY_HARDWARE = {
    hardware_id: tuple(port for port in PORT_CAPABILITIES if port.hardware_id == hardware_id)
    for hardware_id in (_PA5220, _PA5410)
}


def ports_for_hardware(hardware_id: str) -> tuple[PortCapability, ...]:
    return _PORTS_BY_HARDWARE.get(hardware_id, ())


def port_capability(hardware_id: str, interface_name: str) -> PortCapability | None:
    return _PORT_INDEX.get((hardware_id, interface_name))


def _connector_compatible(source: PortConnector, target: PortConnector) -> bool:
    if source == PortConnector.RJ45 or target == PortConnector.RJ45:
        return source == target
    compatible = {
        PortConnector.SFP: {PortConnector.SFP, PortConnector.SFP_PLUS, PortConnector.SFP28},
        PortConnector.SFP_PLUS: {PortConnector.SFP_PLUS, PortConnector.SFP28},
        PortConnector.SFP28: {PortConnector.SFP28},
        PortConnector.QSFP: {PortConnector.QSFP, PortConnector.QSFP_PLUS, PortConnector.QSFP28},
        PortConnector.QSFP_PLUS: {PortConnector.QSFP_PLUS, PortConnector.QSFP28},
        PortConnector.QSFP28: {PortConnector.QSFP28},
    }
    return target in compatible.get(source, set())


def evaluate_port_compatibility(
    source: PortCapability | None,
    target: PortCapability | None,
    context: SourceInterfaceContext,
) -> PortCompatibility:
    evidence = tuple(dict.fromkeys((source.evidence_refs if source else ()) + (target.evidence_refs if target else ())))
    if source is None:
        return PortCompatibility(PortMappingStatus.UNVERIFIED, ("Source port capability is not in the curated registry.",), evidence)
    if target is None:
        return PortCompatibility(PortMappingStatus.INCOMPATIBLE, ("Target interface is not a curated dataplane port.",), evidence)
    if not source.evidence_refs or not target.evidence_refs:
        return PortCompatibility(PortMappingStatus.UNVERIFIED, ("Complete source and target port evidence is required.",), evidence)
    reasons = []
    failures = []
    if target.breakout_parent:
        return PortCompatibility(
            PortMappingStatus.UNVERIFIED,
            (f"{target.interface_name} requires breakout configuration on {target.breakout_parent}; breakout is not automated.",),
            evidence,
        )
    if not _connector_compatible(source.connector, target.connector):
        failures.append(f"Connector capability mismatch: {source.connector.value} to {target.connector.value}.")
    else:
        reasons.append(f"Connector capability {source.connector.value} to {target.connector.value} is compatible.")
    if context.configured_speed:
        if context.configured_speed not in source.supported_speeds:
            failures.append(f"Configured speed {context.configured_speed.value} is not documented for the source port.")
        elif context.configured_speed not in target.supported_speeds:
            failures.append(f"Target port does not support configured speed {context.configured_speed.value}.")
        else:
            reasons.append(f"Configured speed {context.configured_speed.value} is supported by both ports.")
    else:
        overlap = tuple(speed for speed in source.supported_speeds if speed in target.supported_speeds)
        if not overlap:
            failures.append("Source and target ports have no documented supported-speed overlap.")
        else:
            reasons.append("Documented speed capabilities overlap; runtime speed is unspecified and was not guessed.")
    if context.requires_layer3 and not target.supports_layer3:
        failures.append("Target port does not support required Layer3 semantics.")
    if context.requires_subinterface and not target.supports_subinterface:
        failures.append("Target port does not support required subinterfaces.")
    reasons.append("PORT_CAPABILITY_COMPATIBLE only; physical cabling and installed transceiver are not confirmed.")
    return PortCompatibility(PortMappingStatus.INCOMPATIBLE if failures else PortMappingStatus.COMPATIBLE, tuple(failures + reasons), evidence)


def candidate_target_ports(
    source_hardware_id: str,
    source_interface: str,
    target_hardware_id: str,
    context: SourceInterfaceContext,
    assigned_targets: set[str] | frozenset[str] = frozenset(),
) -> tuple[TargetPortCandidate, ...]:
    source = port_capability(source_hardware_id, source_interface)
    return tuple(
        TargetPortCandidate(
            target_interface=target.interface_name,
            status=result.status,
            reasons=result.reasons,
            already_assigned=target.interface_name in assigned_targets,
            evidence_refs=result.evidence_refs,
        )
        for target in ports_for_hardware(target_hardware_id)
        for result in (evaluate_port_compatibility(source, target, context),)
    )
