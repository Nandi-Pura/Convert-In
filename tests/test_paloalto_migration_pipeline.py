from app.core.migration import MigrationMappings, MigrationPlanner
from app.core.migration.models import NatRulePlacement, SecurityRulePlacement
from app.core.migration.registry import migration_pair
from app.core.models import Vendor
from app.core.parsing import parse_config
from app.core.reference_integrity import ReferenceIntegrityValidator
from app.core.renderers import PaloAltoRenderer
from app.core.versions.models import VersionContext


PANOS = """<config version="11.1.0"><devices><entry name="localhost.localdomain">
<network><interface><ethernet>
  <entry name="ethernet1/1"><comment>Outside link</comment><layer3><ip><entry name="192.0.2.2/24"/><entry name="192.0.2.3/24"/></ip>
    <units><entry name="ethernet1/1.100"><tag>100</tag><comment>Tenant VLAN</comment><ip><entry name="10.0.100.1/24"/></ip></entry></units>
  </layer3></entry>
</ethernet></interface><virtual-router><entry name="default"><interface><member>ethernet1/1</member><member>ethernet1/1.100</member></interface><routing-table><ip><static-route>
  <entry name="default-route"><destination>0.0.0.0/0</destination><nexthop><ip-address>192.0.2.1</ip-address></nexthop><interface>ethernet1/1</interface><metric>10</metric><admin-dist>15</admin-dist></entry>
</static-route></ip></routing-table></entry></virtual-router></network>
<vsys><entry name="vsys1">
<zone><entry name="outside"><network><layer3><member>ethernet1/1</member></layer3></network></entry><entry name="tenant"><network><layer3><member>ethernet1/1.100</member></layer3></network></entry></zone>
<address><entry name="WEB"><ip-netmask>10.0.100.10/32</ip-netmask><description>Web host</description><tag><member>production</member></tag></entry><entry name="PUBLIC"><ip-range>203.0.113.10-203.0.113.20</ip-range></entry><entry name="FQDN"><fqdn>app.example.com</fqdn></entry></address>
<address-group><entry name="SERVERS"><static><member>WEB</member></static></entry></address-group>
<service><entry name="HTTPS"><protocol><tcp><port>443,8443-8444</port></tcp></protocol><description>HTTPS ports</description></entry></service>
<service-group><entry name="WEB-SERVICES"><members><member>HTTPS</member></members></entry></service-group>
<rulebase><security><rules><entry name="Allow-Web"><from><member>outside</member></from><to><member>tenant</member></to><source><member>any</member></source><destination><member>SERVERS</member></destination><application><member>ssl</member><member>web-browsing</member></application><service><member>WEB-SERVICES</member></service><action>allow</action><log-start>yes</log-start><log-end>yes</log-end><description>Allow reviewed web traffic</description></entry></rules></security>
<nat><rules>
 <entry name="Interface-DIPP"><from><member>tenant</member></from><to><member>outside</member></to><source><member>WEB</member></source><destination><member>any</member></destination><service>any</service><source-translation><dynamic-ip-and-port><interface-address><interface>ethernet1/1</interface><ip>192.0.2.2/24</ip></interface-address></dynamic-ip-and-port></source-translation></entry>
 <entry name="Pool-DIPP"><from><member>tenant</member></from><to><member>outside</member></to><source><member>WEB</member></source><destination><member>any</member></destination><service>any</service><source-translation><dynamic-ip-and-port><translated-address><member>PUBLIC</member></translated-address></dynamic-ip-and-port></source-translation></entry>
 <entry name="DNAT"><from><member>outside</member></from><to><member>outside</member></to><source><member>any</member></source><destination><member>PUBLIC</member></destination><service>HTTPS</service><destination-translation><translated-address>WEB</translated-address></destination-translation></entry>
 <entry name="Combined"><from><member>outside</member></from><to><member>outside</member></to><source><member>any</member></source><destination><member>PUBLIC</member></destination><service>HTTPS</service><source-translation><dynamic-ip-and-port><translated-address><member>PUBLIC</member></translated-address></dynamic-ip-and-port></source-translation><destination-translation><translated-address>WEB</translated-address></destination-translation></entry>
</rules></nat></rulebase>
</entry></vsys></entry></devices></config>"""


def version():
    return VersionContext(vendor=Vendor.PALO_ALTO, os_name="PAN-OS", selected_version="11.1", selected_family="11.1")


def test_parser_preserves_p0_semantics_and_scope():
    cfg = parse_config(PANOS, Vendor.PALO_ALTO)
    assert cfg.metadata["vsys"] == "vsys1"
    assert cfg.interfaces[0].description == "Outside link"
    assert cfg.interfaces[1].parent == "ethernet1/1" and cfg.interfaces[1].vlan == 100
    assert {item.virtual_router for item in cfg.interfaces} == {"default"}
    assert cfg.addresses[0].tags == ["production"]
    assert cfg.security_policies[0].applications == ["ssl", "web-browsing"]
    assert cfg.security_policies[0].log_start and cfg.security_policies[0].log_end
    assert cfg.static_routes[0].virtual_router == "default" and cfg.static_routes[0].distance == 15
    assert [rule.position for rule in cfg.nat_policies] == [1, 2, 3, 4]
    assert cfg.nat_policies[0].translation_target == "ethernet1/1"
    assert cfg.extraction_coverage and cfg.extraction_coverage.semantic_total == 16


def test_multiple_vsys_is_blocked_without_cross_scope_merge():
    xml = PANOS.replace('</entry></vsys>', '</entry><entry name="vsys2"><address><entry name="WEB"><ip-netmask>10.9.9.9</ip-netmask></entry></address></entry></vsys>')
    cfg = parse_config(xml, Vendor.PALO_ALTO)
    assert not cfg.addresses and not cfg.security_policies
    assert any("Multiple VSYS" in item.reason for item in cfg.unparsed_constructs)
    assert any(issue.severity == "ERROR" for issue in cfg.warnings)


def test_dynamic_group_profile_and_bad_route_are_never_silent():
    xml = PANOS.replace('<static><member>WEB</member></static>', '<dynamic><filter>production</filter></dynamic>', 1)
    xml = xml.replace('<description>Allow reviewed web traffic</description>', '<profile-setting><group><member>strict</member></group></profile-setting>')
    xml = xml.replace('<nexthop><ip-address>192.0.2.1</ip-address></nexthop>', '<nexthop><next-vr>other</next-vr></nexthop>')
    cfg = parse_config(xml, Vendor.PALO_ALTO)
    assert not cfg.address_groups and not cfg.static_routes
    assert cfg.security_policies[0].vendor_extensions["security_profiles"]
    reasons = " ".join(x.reason for x in cfg.unparsed_constructs)
    assert "Dynamic address group" in reasons and "next-hop" in reasons


def test_reference_integrity_and_bounded_plan_render_are_deterministic():
    cfg = parse_config(PANOS.replace('<tag><member>production</member></tag>',''), Vendor.PALO_ALTO)
    integrity = ReferenceIntegrityValidator().validate(cfg)
    assert not integrity.blocked_entity_ids
    mappings = MigrationMappings(security_rule_placement=SecurityRulePlacement(mode="BOTTOM"), nat_rule_placement=NatRulePlacement(mode="BOTTOM"))
    plan = MigrationPlanner().plan(cfg, mappings, version(), version(), integrity)
    statuses = {(item.entity_type, item.entity_id): item.status for item in plan.compatibility}
    assert all(statuses[(kind, name)] in {"EXACT", "SUPPORTED"} for kind, name in (
        ("interface", "interface:ethernet1/1"), ("interface", "interface:ethernet1/1.100"), ("zone", "zone:outside"),
        ("security_policy", "security_policy:Allow-Web"), ("route", "route:default:default-route"),
        ("nat_policy", "nat_policy:Interface-DIPP"), ("nat_policy", "nat_policy:Pool-DIPP"),
        ("nat_policy", "nat_policy:DNAT"), ("nat_policy", "nat_policy:Combined")))
    renderer = PaloAltoRenderer()
    first, report = renderer.render(plan)
    second, _ = PaloAltoRenderer().render(plan)
    assert first == second and not report.errors
    assert report.nat_rule_ordering.source_order == ["Interface-DIPP", "Pool-DIPP", "DNAT", "Combined"]
    assert any(" application ssl" in line for line in first)
    assert any("network interface ethernet ethernet1/1 layer3" in line for line in first)
    assert any("network virtual-router default interface ethernet1/1" in line for line in first)
    assert any("service-group WEB-SERVICES members HTTPS" in line for line in first)
    assert any("rulebase nat rules Interface-DIPP source-translation dynamic-ip-and-port interface-address interface ethernet1/1" in line for line in first)
    assert any("rulebase nat rules Interface-DIPP source-translation dynamic-ip-and-port interface-address ip 192.0.2.2/24" in line for line in first)
    assert report.total_entities == report.generated_entities + report.skipped_entities


def test_root_shared_scope_is_preserved_for_review():
    xml = PANOS.replace("<devices>", "<shared><address><entry name=\"GLOBAL\"><ip-netmask>10.9.9.9</ip-netmask></entry></address></shared><devices>", 1)
    cfg = parse_config(xml, Vendor.PALO_ALTO)
    assert any(item.section == "shared" for item in cfg.unparsed_constructs)
    assert all(item.name != "GLOBAL" for item in cfg.addresses)


def test_invalid_interface_blocks_dependent_zone_and_nat_generation():
    xml = PANOS.replace('name="192.0.2.2/24"', 'name="not-an-address"', 1).replace('<tag><member>production</member></tag>', '')
    cfg = parse_config(xml, Vendor.PALO_ALTO)
    integrity = ReferenceIntegrityValidator().validate(cfg)
    mappings = MigrationMappings(security_rule_placement=SecurityRulePlacement(mode="BOTTOM"), nat_rule_placement=NatRulePlacement(mode="BOTTOM"))
    plan = MigrationPlanner().plan(cfg, mappings, version(), version(), integrity)
    outcomes = {item.entity_id: item.status for item in plan.compatibility}
    assert outcomes["interface:ethernet1/1"] == "MANUAL_REVIEW"
    assert outcomes["zone:outside"] == "MANUAL_REVIEW"
    assert outcomes["nat_policy:Interface-DIPP"] == "MANUAL_REVIEW"

def test_unsupported_nat_option_and_security_profile_stay_manual_review():
    xml = PANOS.replace('</dynamic-ip-and-port>', '<fallback><translated-address><member>PUBLIC</member></translated-address></fallback></dynamic-ip-and-port>', 1)
    xml = xml.replace('<description>Allow reviewed web traffic</description>', '<profile-setting><group><member>strict</member></group></profile-setting>')
    cfg = parse_config(xml, Vendor.PALO_ALTO)
    integrity = ReferenceIntegrityValidator().validate(cfg)
    plan = MigrationPlanner().plan(cfg, MigrationMappings(security_rule_placement=SecurityRulePlacement(mode="BOTTOM"), nat_rule_placement=NatRulePlacement(mode="BOTTOM")), version(), version(), integrity)
    nat = next(x for x in plan.compatibility if x.entity_id == "nat_policy:Interface-DIPP")
    policy = next(x for x in plan.compatibility if x.entity_id == "security_policy:Allow-Web")
    assert nat.status == policy.status == "MANUAL_REVIEW"
    assert "fallback" in " ".join(nat.reasons).lower()


def test_incomplete_nat_translation_stays_manual_review():
    xml = PANOS.replace('<translated-address><member>PUBLIC</member></translated-address>', '', 1).replace('<tag><member>production</member></tag>', '')
    cfg = parse_config(xml, Vendor.PALO_ALTO)
    integrity = ReferenceIntegrityValidator().validate(cfg)
    mappings = MigrationMappings(security_rule_placement=SecurityRulePlacement(mode="BOTTOM"), nat_rule_placement=NatRulePlacement(mode="BOTTOM"))
    plan = MigrationPlanner().plan(cfg, mappings, version(), version(), integrity)
    outcome = next(item for item in plan.compatibility if item.entity_id == "nat_policy:Pool-DIPP")
    assert outcome.status == "MANUAL_REVIEW"
    assert "missing-translated-address" in cfg.nat_policies[1].vendor_extensions["manual_review"]

def test_pair_is_bounded_to_panos_11_1():
    pair = migration_pair(Vendor.PALO_ALTO, Vendor.PALO_ALTO)
    assert pair.supported_source_profiles == pair.supported_target_profiles == frozenset({"panos-11.1"})
    assert "security_policy" in pair.features and "nat:interface_address_pat" in pair.features
def test_address_and_service_namespaces_do_not_collide():
    xml = PANOS.replace('name="WEB"', 'name="HTTPS"', 1).replace('<member>WEB</member>', '<member>HTTPS</member>').replace('<tag><member>production</member></tag>', '')
    cfg = parse_config(xml, Vendor.PALO_ALTO)
    assert next(item for item in cfg.addresses if item.name == "HTTPS").id == "address:HTTPS"
    assert next(item for item in cfg.services if item.name == "HTTPS").id == "service:HTTPS"
    entities = cfg.addresses + cfg.address_groups + cfg.services + cfg.service_groups + cfg.security_policies + cfg.nat_policies + cfg.interfaces + cfg.zones + cfg.static_routes
    assert len({item.id for item in entities}) == len(entities)
    integrity = ReferenceIntegrityValidator().validate(cfg)
    mappings = MigrationMappings(security_rule_placement=SecurityRulePlacement(mode="BOTTOM"), nat_rule_placement=NatRulePlacement(mode="BOTTOM"))
    plan = MigrationPlanner().plan(cfg, mappings, version(), version(), integrity)
    outcomes = {item.entity_id: item.status for item in plan.compatibility}
    assert outcomes["address:HTTPS"] in {"EXACT", "SUPPORTED"}
    assert outcomes["service:HTTPS"] in {"EXACT", "SUPPORTED"}
    candidate, report = PaloAltoRenderer().render(plan)
    assert not report.errors
    assert any("address HTTPS ip-netmask" in line for line in candidate)
    assert any("service HTTPS protocol tcp" in line for line in candidate)

def test_paloalto_api_pipeline_returns_candidate_plan_diff_and_evidence():
    from fastapi.testclient import TestClient
    from app.main import app

    client=TestClient(app)
    source=PANOS.replace('<tag><member>production</member></tag>','')
    analyzed=client.post("/api/analyze",data={"source":source,"source_vendor":"paloalto","source_version":"11.1","target_vendor":"paloalto","target_version":"11.1"})
    assert analyzed.status_code==200
    project=analyzed.text.split("Project: <code>")[1].split("<")[0]
    base=f"/api/projects/{project}/migration"
    mappings=client.get(base+"/mappings").json()
    mappings["security_rule_placement"]={"mode":"BOTTOM"}
    mappings["nat_rule_placement"]={"mode":"BOTTOM"}
    assert client.put(base+"/mappings",json=mappings).status_code==200
    compatibility=client.get(base+"/compatibility").json()
    assert compatibility["source_vendor"]==compatibility["target_vendor"]=="paloalto"
    assert all(item["documentation_refs"] for item in compatibility["items"] if item["status"] in {"EXACT","SUPPORTED"})
    plan=client.post(base+"/plan")
    semantic=client.post(base+"/semantic-diff")
    rendered=client.post(base+"/render")
    assert plan.status_code==semantic.status_code==rendered.status_code==200
    payload=rendered.json()
    assert payload["status"]=="CANDIDATE"
    assert payload["report"]["nat_rule_ordering"]["source_order"] == ["Interface-DIPP", "Pool-DIPP", "DNAT", "Combined"]
    assert "set rulebase security rules Allow-Web application ssl" in payload["candidate"]
    assert semantic.json()["entities"]
    extraction=client.get(f"/api/projects/{project}/extraction").json()
    assert extraction["semantic_total"]==extraction["normalized"]+extraction["recovered"]+extraction["unparsed"]+extraction["unsupported"]

def test_parser_normalizes_explicit_link_speed_without_guessing_auto_or_unknown_values():
    explicit = parse_config(PANOS.replace('<entry name="ethernet1/1">', '<entry name="ethernet1/1"><link-speed>1000</link-speed>', 1), Vendor.PALO_ALTO)
    assert explicit.interfaces[0].configured_speed == "1G"

    automatic = parse_config(PANOS.replace('<entry name="ethernet1/1">', '<entry name="ethernet1/1"><link-speed>auto</link-speed>', 1), Vendor.PALO_ALTO)
    assert automatic.interfaces[0].configured_speed is None

    unknown = parse_config(PANOS.replace('<entry name="ethernet1/1">', '<entry name="ethernet1/1"><link-speed>unexpected</link-speed>', 1), Vendor.PALO_ALTO)
    assert unknown.interfaces[0].vendor_extensions["unverified_link_speed"] == "unexpected"
    assert any("link speed" in item.reason.lower() for item in unknown.unparsed_constructs)

def test_hardware_mapping_api_persists_manual_pa5220_to_pa5410_decision_and_gates_rendering():
    from fastapi.testclient import TestClient
    from app.main import app

    client = TestClient(app)
    source = PANOS.replace("ethernet1/1", "ethernet1/2").replace('<tag><member>production</member></tag>', '')
    endpoint = lambda hardware_id: {
        "vendor": "PALO_ALTO",
        "hardware_id": hardware_id,
        "profile_id": "firewall-paloalto-panos",
        "os_version": "11.1",
    }
    response = client.post("/api/workbench/run", json={
        "source_text": source,
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
    })
    assert response.status_code == 200, response.text
    initial = response.json()
    assert initial["candidate"] is None
    assert not initial["interface_mapping"]["valid_for_conversion"]
    project = initial["project_id"]
    base = f"/api/projects/{project}/migration"

    contract = client.get(base + "/interface-mappings")
    assert contract.status_code == 200
    body = contract.json()
    assert body["summary"] == {
        "required": 1, "mapped": 0, "exact": 0, "compatible": 0,
        "unmapped": 1, "incompatible": 0, "unverified": 0,
    }
    assert len(body["interfaces"][0]["target_candidates"]) == 44
    assert all(not item.get("selected", False) for item in body["interfaces"][0]["target_candidates"])
    unknown = client.put(base + "/interface-mappings", json={"mappings": [{
        "source_interface": "ethernet1/2", "target_interface": "ethernet1/999", "confirmed_by_user": True,
    }]})
    assert unknown.status_code == 422

    saved = client.put(base + "/interface-mappings", json={"mappings": [{
        "source_hardware_id": "paloalto-pa5220",
        "source_interface": "ethernet1/2",
        "target_hardware_id": "paloalto-pa5410",
        "target_interface": "ethernet1/6",
        "confirmed_by_user": True,
    }]})
    assert saved.status_code == 200
    assert saved.json()["valid_for_conversion"]
    validated = client.post(base + "/interface-mappings/validate")
    assert validated.status_code == 200 and validated.json()["valid_for_conversion"]
    reloaded = client.get(base + "/interface-mappings").json()
    assert reloaded["interfaces"][0]["mapping"]["target_interface"] == "ethernet1/6"
    assert reloaded["interfaces"][0]["mapping"]["status"] == "COMPATIBLE"


    mappings = client.get(base + "/mappings").json()
    mappings["security_rule_placement"] = {"mode": "BOTTOM"}
    mappings["nat_rule_placement"] = {"mode": "BOTTOM"}
    assert client.put(base + "/mappings", json=mappings).status_code == 200

    plan = client.post(base + "/plan")
    rendered = client.post(base + "/render")
    semantic = client.post(base + "/semantic-diff")
    assert plan.status_code == rendered.status_code == semantic.status_code == 200
    assert plan.json()["interface_mapping"]["valid_for_conversion"]
    candidate = rendered.json()["candidate"]
    assert "network interface ethernet ethernet1/6 layer3" in candidate
    assert "ethernet1/6.100" in candidate
    assert "static-route default-route interface ethernet1/6" in candidate
    evidence = client.post(base + "/evidence-pack")
    assert evidence.status_code == 200, evidence.text
    assert next(item for item in evidence.json()["artifacts"] if item["name"] == "mappings")["status"] == "PRESENT"
    exported = client.get(f"/api/projects/{project}/export")
    assert exported.status_code == 200
    imported = client.post(
        "/api/projects/import",
        files={"project": ("mapping.configmorph.zip", exported.content, "application/zip")},
    )
    assert imported.status_code == 200, imported.text
    imported_project = imported.json()["project_id"]
    imported_mapping = client.get(f"/api/projects/{imported_project}/migration/interface-mappings")
    assert imported_mapping.status_code == 200, imported_mapping.text
    assert imported_mapping.json()["interfaces"][0]["mapping"]["target_interface"] == "ethernet1/6"
    assert imported_mapping.json()["interfaces"][0]["mapping"]["confirmed_by_user"] is True
    identities = {item["source_identity"]: item["target_identity"] for item in semantic.json()["entities"]}
    assert identities["ethernet1/2"] == "ethernet1/6"
    assert identities["ethernet1/2.100"] == "ethernet1/6.100"

    reset = client.delete(base + "/interface-mappings")
    assert reset.status_code == 200
    assert not reset.json()["valid_for_conversion"]
    blocked = client.post(base + "/render")
    assert blocked.status_code == 200
    assert blocked.json()["status"] == "BLOCKED"
    assert blocked.json()["candidate"] == ""
