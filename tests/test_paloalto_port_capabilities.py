from app.core.hardware import (
    PortConnector,
    PortMappingStatus,
    PortSpeed,
    SourceInterfaceContext,
    candidate_target_ports,
    evaluate_port_compatibility,
    port_capability,
    ports_for_hardware,
)


def test_curated_pa5220_port_registry_is_exact_and_evidenced():
    ports = ports_for_hardware("paloalto-pa5220")
    assert [port.interface_name for port in ports] == [f"ethernet1/{number}" for number in range(1, 25)]
    assert len({port.physical_port_number for port in ports}) == 24
    assert all(port.evidence_refs == ("PA-5220-DATAPLANE-PORTS",) for port in ports)
    assert {port.connector for port in ports[:4]} == {PortConnector.RJ45}
    assert ports[0].supported_speeds == (PortSpeed.M100, PortSpeed.G1, PortSpeed.G10)
    assert {port.connector for port in ports[4:20]} == {PortConnector.SFP_PLUS}
    assert ports[4].supported_speeds == (PortSpeed.G1, PortSpeed.G10)
    assert {port.connector for port in ports[20:]} == {PortConnector.QSFP_PLUS}
    assert ports[20].supported_speeds == (PortSpeed.G40,)


def test_curated_pa5410_registry_includes_breakout_identities_but_no_special_ports():
    ports = ports_for_hardware("paloalto-pa5410")
    assert [port.interface_name for port in ports] == [f"ethernet1/{number}" for number in range(1, 45)]
    assert len({port.physical_port_number for port in ports}) == 44
    assert all(port.evidence_refs == ("PA-5410-DATAPLANE-PORTS",) for port in ports)
    assert ports[0].connector == PortConnector.RJ45
    assert ports[0].supported_speeds == (PortSpeed.M10, PortSpeed.M100, PortSpeed.G1, PortSpeed.G2_5, PortSpeed.G5, PortSpeed.G10)
    assert ports[8].connector == PortConnector.SFP_PLUS
    assert ports[20].connector == PortConnector.SFP28
    assert ports[20].supported_speeds == (PortSpeed.G1, PortSpeed.G10, PortSpeed.G25)
    assert ports[24].breakout_parent == "ethernet1/41"
    assert ports[40].breakout_capable and ports[40].supported_speeds == (PortSpeed.G40, PortSpeed.G100)
    assert not any(token in port.interface_name.lower() for port in ports for token in ("mgt", "ha", "hsci", "console"))


def test_port_compatibility_is_deterministic_and_never_confirms_cabling():
    source = port_capability("paloalto-pa5220", "ethernet1/2")
    target = port_capability("paloalto-pa5410", "ethernet1/6")
    result = evaluate_port_compatibility(source, target, SourceInterfaceContext(requires_layer3=True))
    assert result.status == PortMappingStatus.COMPATIBLE
    assert result.evidence_refs == ("PA-5220-DATAPLANE-PORTS", "PA-5410-DATAPLANE-PORTS")
    assert any("runtime speed" in reason.lower() for reason in result.reasons)
    assert any("cabling" in reason.lower() for reason in result.reasons)

    incompatible = evaluate_port_compatibility(
        port_capability("paloalto-pa5220", "ethernet1/21"),
        target,
        SourceInterfaceContext(configured_speed=PortSpeed.G40, requires_layer3=True),
    )
    assert incompatible.status == PortMappingStatus.INCOMPATIBLE
    assert any("connector" in reason.lower() or "40G" in reason for reason in incompatible.reasons)


def test_candidates_include_incompatible_and_assigned_ports_without_selecting_one():
    candidates = candidate_target_ports(
        "paloalto-pa5220", "ethernet1/2", "paloalto-pa5410",
        SourceInterfaceContext(requires_layer3=True), assigned_targets={"ethernet1/6"},
    )
    assert len(candidates) == 44
    assert next(item for item in candidates if item.target_interface == "ethernet1/6").already_assigned
    breakout = next(item for item in candidates if item.target_interface == "ethernet1/25")
    assert breakout.status == PortMappingStatus.UNVERIFIED
    assert not any(getattr(item, "selected", False) for item in candidates)
