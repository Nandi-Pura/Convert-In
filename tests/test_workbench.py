from pathlib import Path

from fastapi.testclient import TestClient

from app.main import app

client=TestClient(app)


def run(path,vendor,version):
    return client.post("/api/workbench/run",data={"config":Path(path).read_text(),"source_vendor":vendor,"source_version":version,"target_version":"11.1"})


def test_firewall_workbench_uses_emission_gates_and_entity_commands():
    response=run("examples/fortigate/basic.conf","fortigate","7.4"); assert response.status_code==200
    body=response.json(); assert body["mode"]=="CONVERT" and body["target_profile"]["version"]=="11.1"
    ready=[x for x in body["entities"] if x["copyable"]]
    assert ready and all(x["user_status"]=="READY" and x["commands"] for x in ready)
    assert all(not x["commands"] and not x["copyable"] for x in body["entities"] if x["entity_type"]=="NAT Rule")
    assert not any(line.startswith("set rulebase nat") for line in body["candidate"].splitlines())


def test_router_workbench_is_analysis_only_and_exposes_cp1():
    response=run("tests/fixtures/iosxe/policy-router.cfg","cisco_iosxe","17.12.1"); assert response.status_code==200
    body=response.json(); assert body["mode"]=="ANALYZE" and body["target_profile"] is None and body["candidate"] is None
    assert body["cp1_summary"]["blocking_findings"]==1
    blocked=[x for x in body["entities"] if x["user_status"]=="BLOCKED"]
    assert blocked and all(not x["copyable"] and x["detailed_status"]=="CP1: BLOCKED" for x in blocked)


def test_workbench_requires_verified_source_version():
    response=client.post("/api/workbench/run",data={"config":"router ospf 1","source_vendor":"cisco_iosxe"})
    assert response.status_code==422 and "verified" in response.json()["detail"]