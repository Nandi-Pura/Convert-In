from fastapi.testclient import TestClient

from app.config import settings
from app.main import app


PANOS = """<config version="11.1.0"><devices><entry name="localhost.localdomain">
<network><interface><ethernet><entry name="ethernet1/2"><layer3>
<ip><entry name="10.0.0.1/24"/></ip>
</layer3></entry></ethernet></interface></network>
<vsys><entry name="vsys1"><zone><entry name="trust"><network><layer3>
<member>ethernet1/2</member>
</layer3></network></entry></zone></entry></vsys>
</entry></devices></config>"""


def endpoint(hardware_id: str) -> dict[str, str]:
    return {
        "vendor": "PALO_ALTO",
        "hardware_id": hardware_id,
        "profile_id": "firewall-paloalto-panos",
        "os_version": "11.1",
    }


def payload(source_text: str = PANOS) -> dict:
    return {
        "source_text": source_text,
        "source_vendor": "paloalto",
        "source_version": "11.1",
        "target_vendor": "paloalto",
        "target_version": "11.1",
        "source_profile": "firewall-paloalto-panos",
        "target_profile": "firewall-paloalto-panos",
        "migration_context": {
            "domain": "FIREWALL",
            "source": endpoint("paloalto-pa5220"),
            "target": endpoint("paloalto-pa5410"),
        },
    }


def test_preflight_requires_valid_context_and_preserves_source_limit(monkeypatch):
    client = TestClient(app)
    missing = payload()
    missing.pop("migration_context")
    response = client.post("/api/workbench/preflight", json=missing)
    assert response.status_code == 422
    assert response.json()["detail"] == "migration_context is required for interface mapping preflight."

    invalid = payload()
    invalid["migration_context"]["source"]["hardware_id"] = "paloalto-unknown"
    response = client.post("/api/workbench/preflight", json=invalid)
    assert response.status_code == 422

    monkeypatch.setattr(settings, "max_input_bytes", 8)
    response = client.post("/api/workbench/preflight", json=payload())
    assert response.status_code == 413


def test_preflight_creates_reusable_mapping_project_without_conversion_output():
    client = TestClient(app)
    response = client.post("/api/workbench/preflight", json=payload())
    assert response.status_code == 200, response.text
    body = response.json()
    project_id = body["project_id"]
    contract = body["interface_mapping"]

    assert body["interface_mapping_required"] is True
    assert contract["source_hardware_id"] == "paloalto-pa5220"
    assert contract["target_hardware_id"] == "paloalto-pa5410"
    assert contract["summary"]["required"] == 1
    assert contract["interfaces"][0]["source_interface"] == "ethernet1/2"
    assert contract["valid_for_conversion"] is False

    root = settings.workspace_dir / project_id
    assert (root / "source.cfg").is_file()
    assert (root / "normalized.json").is_file()
    assert (root / "project.json").is_file()
    assert not (root / "workbench-result.json").exists()
    assert not (root / "migration" / "candidate-pan-os.set").exists()

    base = f"/api/projects/{project_id}/migration/interface-mappings"
    assert client.get(base).status_code == 200
    saved = client.put(base, json={"mappings": [{
        "source_interface": "ethernet1/2",
        "target_interface": "ethernet1/6",
        "confirmed_by_user": True,
    }]})
    assert saved.status_code == 200, saved.text
    assert saved.json()["valid_for_conversion"] is True

    repeated = client.post("/api/workbench/preflight", json=payload())
    assert repeated.status_code == 200, repeated.text
    assert repeated.json()["project_id"] == project_id
    mapping = repeated.json()["interface_mapping"]["interfaces"][0]["mapping"]
    assert mapping["target_interface"] == "ethernet1/6"
    assert mapping["confirmed_by_user"] is True

    conversion = payload()
    conversion["mappings"] = {
        "source_hardware_id": "paloalto-pa5220",
        "target_hardware_id": "paloalto-pa5410",
        "interfaces": [mapping],
    }
    converted = client.post("/api/workbench/run", json=conversion)
    assert converted.status_code == 200, converted.text
    assert converted.json()["project_id"] == project_id
    assert "network interface ethernet ethernet1/6 layer3" in converted.json()["candidate"]
    assert "network interface ethernet ethernet1/2 layer3" not in converted.json()["candidate"]

    changed = client.post("/api/workbench/preflight", json=payload(PANOS.replace("10.0.0.1/24", "10.0.1.1/24")))
    assert changed.status_code == 200, changed.text
    assert changed.json()["project_id"] != project_id
    assert changed.json()["interface_mapping"]["valid_for_conversion"] is False
