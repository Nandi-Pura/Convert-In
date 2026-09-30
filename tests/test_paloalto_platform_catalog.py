import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from app.core.documentation import DOCUMENTATION_REFERENCES
from app.core.hardware import (
    HARDWARE_PROFILES,
    HardwareSelectionStatus,
    SupportScope,
    SupportStatus,
    detect_hardware,
    hardware_registry_payload,
    resolve_hardware_software_support,
)
from app.main import app
from app.web import api


EXPECTED_FAMILIES = {
    "PA-400 Series": {"PA-410", "PA-415", "PA-415-5G", "PA-440", "PA-445", "PA-450", "PA-455", "PA-455-5G", "PA-460"},
    "PA-800 Series": {"PA-820", "PA-850"},
    "PA-1400 Series": {"PA-1410", "PA-1420"},
    "PA-3200 Series": {"PA-3220", "PA-3250", "PA-3260"},
    "PA-3400 Series": {"PA-3410", "PA-3420", "PA-3430", "PA-3440"},
    "PA-5200 Series": {"PA-5220", "PA-5250", "PA-5260", "PA-5280"},
    "PA-5400 Series": {"PA-5410", "PA-5420", "PA-5430", "PA-5440", "PA-5445", "PA-5450"},
}


def _status(hardware_id: str, version: str):
    return resolve_hardware_software_support(hardware_id, "PAN-OS", version)


def _pan_selection(version: str = "11.1", hardware_id: str = "paloalto-pa3410"):
    endpoint = {
        "vendor": "PALO_ALTO",
        "hardware_id": hardware_id,
        "profile_id": "firewall-paloalto-panos",
        "os_version": version,
    }
    return api.WorkbenchSource(
        source_text="<config/>",
        source_vendor="paloalto",
        source_profile="firewall-paloalto-panos",
        source_version=version,
        target_profile="firewall-paloalto-panos",
        target_version=version,
        migration_context={"domain": "FIREWALL", "source": endpoint, "target": endpoint},
    )


def test_palo_alto_catalog_has_exact_models_evidence_and_deterministic_order():
    profiles = [profile for profile in HARDWARE_PROFILES if profile.vendor.value == "PALO_ALTO"]
    assert len(profiles) == 30
    assert [profile.id for profile in profiles] == sorted(profile.id for profile in profiles)
    assert len({profile.id for profile in profiles}) == len(profiles)
    assert len({(profile.vendor, profile.product_family, profile.model) for profile in profiles}) == len(profiles)
    assert {profile.product_family for profile in profiles} == set(EXPECTED_FAMILIES)
    for family, models in EXPECTED_FAMILIES.items():
        assert {profile.model for profile in profiles if profile.product_family == family} == models
    for profile in profiles:
        assert profile.evidence_refs
        assert all(reference in DOCUMENTATION_REFERENCES for reference in profile.evidence_refs)


def test_hardware_selection_remains_manual():
    detected = detect_hardware("model PA-3410\nsw-version 11.1.6")
    assert detected.status == HardwareSelectionStatus.UNKNOWN
    assert detected.hardware_id is None


@pytest.mark.parametrize(("hardware_id", "floor", "before"), [
    ("paloalto-pa440", "10.1.0", None),
    ("paloalto-pa410", "10.1.2", "10.1.1"),
    ("paloalto-pa415", "11.0", "10.2"),
    ("paloalto-pa445", "11.0", "10.2"),
    ("paloalto-pa415-5g", "11.1", "11.0"),
    ("paloalto-pa455", "11.1", "11.0"),
    ("paloalto-pa455-5g", "11.2.3", "11.2.2"),
])
def test_pa400_first_supported_boundaries(hardware_id, floor, before):
    supported = _status(hardware_id, floor)
    assert supported.status == SupportStatus.SUPPORTED
    assert supported.evidence_refs
    if before:
        assert _status(hardware_id, before).status == SupportStatus.UNSUPPORTED


@pytest.mark.parametrize("model", ("3410", "3420", "3430", "3440"))
def test_pa3400_models_begin_at_documented_10_2(model):
    assert _status(f"paloalto-pa{model}", "10.2").status == SupportStatus.SUPPORTED
    assert _status(f"paloalto-pa{model}", "10.1").status == SupportStatus.UNSUPPORTED


@pytest.mark.parametrize("model", ("5220", "5250", "5260"))
def test_pa5200_early_models_begin_at_8_0(model):
    assert _status(f"paloalto-pa{model}", "8.0").status == SupportStatus.SUPPORTED


def test_pa5280_first_release_exception_is_not_inherited():
    assert _status("paloalto-pa5280", "8.1").status == SupportStatus.SUPPORTED
    assert _status("paloalto-pa5280", "8.0").status == SupportStatus.VERSION_NOT_VERIFIED


def test_pa5400_model_rows_remain_distinct():
    assert _status("paloalto-pa5410", "10.2").status == SupportStatus.SUPPORTED
    assert _status("paloalto-pa5440", "10.2").status == SupportStatus.UNSUPPORTED
    assert _status("paloalto-pa5445", "11.0").status == SupportStatus.UNSUPPORTED
    assert _status("paloalto-pa5450", "10.1").status == SupportStatus.SUPPORTED


def test_release_train_matching_preserves_minimum_patch_and_scope():
    supported = _status("paloalto-pa455-5g", "11.2.9")
    assert supported.status == SupportStatus.SUPPORTED
    assert supported.support_scope == SupportScope.RELEASE_TRAIN
    assert supported.minimum_version == "11.2.3"
    assert _status("paloalto-pa455-5g", "11.2.2").status == SupportStatus.UNSUPPORTED
    assert _status("paloalto-pa455-5g", "11.1").status == SupportStatus.UNSUPPORTED
    assert _status("paloalto-pa455-5g", "12.1.1").status == SupportStatus.UNSUPPORTED
    assert _status("paloalto-pa455-5g", "12.1.2").status == SupportStatus.SUPPORTED


def test_known_unverified_and_unknown_states_are_not_promoted():
    assert _status("paloalto-pa3410", "8.0").status == SupportStatus.VERSION_NOT_VERIFIED
    assert _status("missing-model", "11.1").status == SupportStatus.UNKNOWN_HARDWARE
    assert _status("paloalto-pa3410", "99.9").status == SupportStatus.UNKNOWN_SOFTWARE
    assert _status("paloalto-pa3410", "11.2.999").status == SupportStatus.UNKNOWN_SOFTWARE


def test_group_support_does_not_leak_to_adjacent_models():
    assert _status("paloalto-pa440", "10.1.0").status == SupportStatus.SUPPORTED
    assert _status("paloalto-pa410", "10.1.0").status == SupportStatus.UNSUPPORTED
    assert _status("paloalto-pa5280", "8.0").status != SupportStatus.SUPPORTED


def test_registry_payload_expands_group_rules_to_exact_selectable_models():
    payload = hardware_registry_payload()
    pa3410 = [row for row in payload["hardware_software_support"] if row["hardware_id"] == "paloalto-pa3410"]
    assert {row["exact_version"] for row in pa3410} >= {"10.2", "11.1", "12.2"}
    assert all(row["support_scope"] in {"RELEASE_TRAIN", "EXACT_VERSION"} for row in pa3410)
    evidence_ids = set(payload["evidence"])
    assert all(
        set(row["evidence_refs"]) <= evidence_ids
        for row in payload["hardware_software_support"]
    )


def test_api_exposes_catalog_platform_and_conversion_states_separately():
    client = TestClient(app)
    response = client.post("/api/platform-compatibility", json={
        "domain": "FIREWALL",
        "vendor": "PALO_ALTO",
        "hardware_id": "paloalto-pa3410",
        "profile_id": "firewall-paloalto-panos",
        "os_version": "12.2.3",
    })
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "SUPPORTED"
    assert body["cataloged"] is True
    assert body["platform_verified"] is True
    assert body["conversion_supported"] is False
    assert body["convert_allowed"] is False
    assert body["evidence_refs"] == ["PANOS-HARDWARE-COMPATIBILITY-MATRIX"]


def test_existing_verified_conversion_version_can_pass_operation_gate(monkeypatch):
    created = []
    monkeypatch.setattr(api.operations, "create", lambda *args, **kwargs: created.append(args) or "operation-id")
    monkeypatch.setattr(api.executor, "submit", lambda *args, **kwargs: None)
    assert api.start_workbench_operation(_pan_selection())["operation_id"] == "operation-id"
    assert created


@pytest.mark.parametrize(("version", "hardware_id", "expected"), [
    ("10.1", "paloalto-pa3410", "UNSUPPORTED"),
    ("8.0", "paloalto-pa3410", "VERSION_NOT_VERIFIED"),
])
def test_operation_gate_rejects_unverified_or_unsupported_pairs(version, hardware_id, expected):
    with pytest.raises(HTTPException, match=expected):
        api.validate_platform_context(_pan_selection(version, hardware_id))


def test_platform_verified_but_unimplemented_version_is_not_conversion_supported():
    with pytest.raises(HTTPException, match="CONVERSION_NOT_SUPPORTED"):
        api.validate_platform_context(_pan_selection("12.2.3", "paloalto-pa3410"))
