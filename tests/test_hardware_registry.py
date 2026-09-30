from app.core.hardware import (
    HardwareSelectionStatus,
    SupportStatus,
    detect_hardware,
    hardware_registry_payload,
    resolve_hardware_software_support,
)


def test_registry_filters_vendors_families_hardware_and_exact_versions():
    payload = hardware_registry_payload()
    domains = {item["domain"] for item in payload["hardware_profiles"]}
    assert domains == {"FIREWALL", "SWITCH"}
    assert {item["vendor"] for item in payload["hardware_profiles"] if item["domain"] == "FIREWALL"} == {"PALO_ALTO"}
    catalyst = next(item for item in payload["hardware_profiles"] if item["model"] == "C9300-48P")
    assert catalyst["product_family"] == "Catalyst 9300 Series"
    support = [item for item in payload["hardware_software_support"] if item["hardware_id"] == catalyst["id"]]
    assert [(item["exact_version"], item["status"]) for item in support] == [("17.12.1", "SUPPORTED")]


def test_unknown_source_hardware_is_not_guessed_from_fortigate_header():
    detected = detect_hardware("#config-version=FG39E8-7.0.13-FW-build0000-000000:opmode=0:vdom=0")
    assert detected.status == HardwareSelectionStatus.UNKNOWN
    assert detected.hardware_id is None


def test_unverified_hardware_software_pair_never_inherits_adjacent_patch():
    exact = resolve_hardware_software_support("cisco-c9300-48p", "IOS-XE", "17.12.1")
    assert exact.status == SupportStatus.SUPPORTED
    assert exact.evidence_refs == ("CISCO-CATALYST-9300-DATASHEET", "IOSXE-17.12.1-C9300-RELEASE")
    assert resolve_hardware_software_support("cisco-c9300-48p", "IOS-XE", "17.12.2").status == SupportStatus.UNKNOWN_SOFTWARE
    assert resolve_hardware_software_support("missing-model", "IOS-XE", "17.12.1").status == SupportStatus.UNKNOWN_HARDWARE


def test_registry_exposes_structured_authoritative_support_evidence():
    payload = hardware_registry_payload()
    support = next(item for item in payload["hardware_software_support"] if item["hardware_id"] == "cisco-c9300-48p")
    evidence = payload["evidence"]["IOSXE-17.12.1-C9300-RELEASE"]
    assert support["exact_version"] == "17.12.1"
    assert support["status"] == "SUPPORTED"
    assert evidence["source"] == "Cisco"
    assert evidence["title"] == "Release Notes for Cisco Catalyst 9300 Series Switches, Cisco IOS XE Dublin 17.12.x"
    assert evidence["reference"].startswith("https://www.cisco.com/")
    assert evidence["section"] == "Supported Hardware and Cisco IOS XE Dublin 17.12.1"
