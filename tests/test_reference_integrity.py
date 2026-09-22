from app.core.models import Address, FirewallConfig, Interface, SecurityRule, Service, StaticRoute, Vendor, Zone
from app.core.reference_integrity import ReferenceFindingType as F, ReferenceIntegrityStatus, ReferenceIntegrityValidator


def config():
    return FirewallConfig(metadata={"source_vendor": Vendor.FORTIGATE}, interfaces=[Interface(id="port1", name="port1")],
        zones=[Zone(id="outside", name="outside", interfaces=["port1"])], addresses=[Address(id="web", name="web", type="host", value="192.0.2.2")],
        services=[Service(id="https", name="https", protocol="tcp", destination_ports=["443"])],
        security_policies=[SecurityRule(id="allow-web", name="allow-web", position=1, source_zones=["outside"], destination_zones=["outside"], sources=["any"], destinations=["web"], services=["https"], action="allow")],
        static_routes=[StaticRoute(id="default", name="default", destination="0.0.0.0/0", next_hop="192.0.2.1", interface="port1")])


def test_valid_typed_resolution_and_determinism():
    first=ReferenceIntegrityValidator().validate(config()); second=ReferenceIntegrityValidator().validate(config())
    assert first.blocking_findings==0 and first.resolved_references==6
    assert [x.finding_id for x in first.findings]==[x.finding_id for x in second.findings]
    assert first.entity_statuses["allow-web"]==ReferenceIntegrityStatus.PASS


def test_unresolved_type_mismatch_duplicate_orphan_and_dependency_blocking():
    cfg=config(); cfg.addresses += [Address(id="dup1",name="duplicate",type="host",value="1.1.1.1"),Address(id="dup2",name="duplicate",type="host",value="2.2.2.2")]
    cfg.address_groups=[Address(id="inner",name="inner",type="group",members=["missing"]),Address(id="outer",name="outer",type="group",members=["inner"])]
    cfg.security_policies[0].destinations=["outer"]; cfg.security_policies[0].services=["web"]
    report=ReferenceIntegrityValidator().validate(cfg); kinds={x.finding_type for x in report.findings}
    assert {F.MISSING_GROUP_MEMBER,F.TYPE_MISMATCH,F.DUPLICATE_NAME,F.ORPHANED_OBJECT} <= kinds
    assert {"inner","outer","allow-web"} <= report.blocked_entity_ids
    policy=next(x for x in report.findings if x.source_entity_id=="allow-web" and x.finding_type==F.MISSING_GROUP_MEMBER)
    assert policy.dependency_path==["security_policy:allow-web","address_group:outer","address_group:inner","address/address_group:missing"]


def test_self_reference_and_stable_nested_cycle_path():
    cfg=config(); cfg.address_groups=[Address(id="a",name="A",type="group",members=["B"]),Address(id="b",name="B",type="group",members=["C"]),Address(id="c",name="C",type="group",members=["A"]),Address(id="self",name="SELF",type="group",members=["SELF"])]
    report=ReferenceIntegrityValidator().validate(cfg)
    cycle=next(x for x in report.findings if x.finding_type==F.REFERENCE_CYCLE)
    assert cycle.dependency_path==["address_group:A","address_group:B","address_group:C","address_group:A"]
    assert any(x.finding_type==F.SELF_REFERENCE for x in report.findings)


def test_disabled_policy_and_any_are_validated():
    cfg=config(); cfg.security_policies[0].enabled=False; cfg.security_policies[0].sources=["any"]; cfg.security_policies[0].destinations=["missing"]
    report=ReferenceIntegrityValidator().validate(cfg)
    assert any(x.source_entity_id=="allow-web" and x.finding_type==F.MISSING_ADDRESS for x in report.findings)
    assert not any(x.referenced_entity_name=="any" for x in report.findings)