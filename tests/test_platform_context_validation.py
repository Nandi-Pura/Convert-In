import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from pathlib import Path

from app.web import api
from app.main import app
from app.core.project_state import load_manifest


def selection(**updates):
    source = {"vendor": "CISCO", "hardware_id": "cisco-c9300-48p", "profile_id": "switch-cisco-iosxe", "os_version": "17.12.1"}
    target = dict(source)
    context = {"domain": "SWITCH", "source": source, "target": target}
    for key, value in updates.items():
        if key.startswith("source_"):
            source[key.removeprefix("source_")] = value
        elif key.startswith("target_"):
            target[key.removeprefix("target_")] = value
        else:
            context[key] = value
    return api.WorkbenchSource(
        source_text="Cisco IOS XE Software, Version 17.12.1\nvlan 10\n name USERS",
        source_vendor="cisco_iosxe",
        source_profile="switch-cisco-iosxe",
        source_version=source["os_version"],
        target_profile="switch-cisco-iosxe",
        target_version="17.12.1",
        migration_context=context,
    )


def test_supported_pair_is_accepted_before_operation_creation(monkeypatch):
    created = []
    monkeypatch.setattr(api.operations, "create", lambda *args, **kwargs: created.append((args, kwargs)) or "operation-id")
    monkeypatch.setattr(api.executor, "submit", lambda *args, **kwargs: None)
    response = api.start_workbench_operation(selection())
    assert response["operation_id"] == "operation-id"
    assert created[0][0][1] == "CONVERT"


def test_unknown_software_rejected_before_operation_creation(monkeypatch):
    def unexpected(*args, **kwargs):
        pytest.fail("Unverified platform must not create an operation")

    monkeypatch.setattr(api.operations, "create", unexpected)
    with pytest.raises(HTTPException, match="UNKNOWN_SOFTWARE") as error:
        api.start_workbench_operation(selection(source_os_version="17.12.2"))
    assert error.value.status_code == 422


@pytest.mark.parametrize("updates", [
    {"domain": "FIREWALL"},
    {"source_vendor": "PALO_ALTO"},
    {"source_hardware_id": "C9300"},
    {"source_hardware_id": "FG39E8"},
    {"source_hardware_id": ""},
])
def test_inconsistent_or_unknown_identity_rejected(updates):
    with pytest.raises(HTTPException, match="Invalid source platform selection"):
        api.validate_platform_context(selection(**updates))


def test_legacy_request_remains_compatible():
    api.validate_platform_context(api.WorkbenchSource(source_text=""))


def test_new_operation_endpoint_requires_explicit_migration_context(monkeypatch):
    monkeypatch.setattr(api.operations, "create", lambda *args, **kwargs: pytest.fail("Context-free request must not create an operation"))
    with pytest.raises(HTTPException, match="migration_context is required") as error:
        api.start_workbench_operation(api.WorkbenchSource(source_text="vlan 10"))
    assert error.value.status_code == 422


def test_explicit_source_parser_vendor_must_match_context(monkeypatch):
    request = selection()
    request.source_vendor = "fortigate"
    monkeypatch.setattr(api.operations, "create", lambda *args, **kwargs: pytest.fail("Inconsistent source routing must not create an operation"))
    with pytest.raises(HTTPException, match="Invalid source platform selection") as error:
        api.start_workbench_operation(request)
    assert error.value.status_code == 422


def test_source_limit_is_enforced_before_operation_creation(monkeypatch):
    monkeypatch.setattr(api.settings, "max_input_bytes", 8)
    monkeypatch.setattr(api.operations, "create", lambda *args, **kwargs: pytest.fail("Oversize source must not create an operation"))
    with pytest.raises(HTTPException, match="100 MiB limit") as error:
        api.start_workbench_operation(selection())
    assert error.value.status_code == 413


def test_real_operation_result_and_manifest_keep_exact_platform_context(tmp_path, monkeypatch):
    monkeypatch.setattr(api.settings, "workspace_dir", tmp_path)
    request = selection()
    request.source_text = Path("tests/fixtures/iosxe/basic-switch.cfg").read_text(encoding="utf-8")
    result = api.run_workbench_instrumented(request, lambda *args: None)

    assert result["candidate"] and "vlan 10" in result["candidate"]
    assert result["conversion_summary"]["added"] is None
    assert result["conversion_summary"]["needs_review"] == 0
    assert result["migration_plan"]["summary"]["total_entities"] == len(result["entities"])
    assert result["migration_plan"]["entities"]
    assert result["platform_context"]["source"]["hardware_id"] == "cisco-c9300-48p"
    assert result["platform_context"]["source"]["compatibility_status"] == "SUPPORTED"
    assert result["platform_context"]["source"]["evidence_refs"] == ["CISCO-CATALYST-9300-DATASHEET", "IOSXE-17.12.1-C9300-RELEASE"]
    assert result["conversion_evidence"]

    manifest = load_manifest(tmp_path, result["project_id"])
    assert manifest["source"]["hardware_id"] == "cisco-c9300-48p"
    assert manifest["target"]["hardware_id"] == "cisco-c9300-48p"


def test_platform_registry_and_compatibility_api_expose_conservative_states():
    client = TestClient(app)
    registry = client.get("/api/platform-registry")
    assert registry.status_code == 200
    assert [domain["id"] for domain in registry.json()["domains"]] == ["FIREWALL", "SWITCH", "ROUTER"]

    def status(domain, vendor, hardware_id, profile_id, os_version):
        response = client.post("/api/platform-compatibility", json={"domain": domain, "vendor": vendor, "hardware_id": hardware_id, "profile_id": profile_id, "os_version": os_version})
        assert response.status_code == 200
        return response.json()["status"]

    assert status("SWITCH", "CISCO", "cisco-c9300-48p", "switch-cisco-iosxe", "17.12.1") == "SUPPORTED"
    assert status("FIREWALL", "PALO_ALTO", "paloalto-pa5220", "firewall-paloalto-panos", "12.1.6") == "UNSUPPORTED"
    assert status("FIREWALL", "PALO_ALTO", "paloalto-pa5410", "firewall-paloalto-panos", "12.1.6") == "VERSION_NOT_VERIFIED"
    assert status("SWITCH", "CISCO", "missing-model", "switch-cisco-iosxe", "17.12.1") == "UNKNOWN_HARDWARE"
    assert status("SWITCH", "CISCO", "cisco-c9300-48p", "switch-cisco-iosxe", "17.12.99") == "UNKNOWN_SOFTWARE"
