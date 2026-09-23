import itertools

from app.core.models import Vendor
from app.core.migration.compatibility import finalize,result
from app.core.migration.models import CompatibilityStatus
from app.core.models import Address
from app.core.platforms import PLATFORM_PROFILES,profiles_payload
from app.core.renderers.registry import lookup_renderer
from app.core.versions import PROFILES,exact_profile,release_profiles
from app.core.versions.models import VersionStatus


def test_primary_release_lines_and_order():
    expected={Vendor.ASA:["9.24","9.23","9.22"],Vendor.FORTIGATE:["7.6","7.4","7.2"],Vendor.PALO_ALTO:["12.2","12.1","11.2"],Vendor.JUNIPER_SRX:["25.4","25.2","24.4"]}
    for vendor,lines in expected.items():
        assert [p.release_line for p in release_profiles(vendor)[:3]]==lines


def test_release_registry_invariants_and_fortios_exact_versions():
    profiles=release_profiles(); keys=[]; latest=set()
    for profile in profiles:
        assert profile.release_line and profile.exact_version and profile.release_evidence_ids and profile.audited_at
        key=(profile.domain,profile.vendor,profile.platform,profile.exact_version); assert key not in keys; keys.append(key)
        if profile.version_status==VersionStatus.LATEST_VERIFIED:
            latest_key=(profile.vendor,profile.platform,profile.release_line); assert latest_key not in latest; latest.add(latest_key)
    assert [p.exact_version for p in release_profiles(Vendor.FORTIGATE)[:3]]==["7.6.7","7.4.12","7.2.13"]


def test_unknown_patch_never_resolves_and_unverified_never_renders():
    assert exact_profile(Vendor.FORTIGATE,"7.4.99") is None
    assert exact_profile(Vendor.FORTIGATE,"7.4.12").version_status==VersionStatus.LATEST_VERIFIED
    assert lookup_renderer("FIREWALL","PALO_ALTO","PAN_OS","12.2.3") is None
    assert lookup_renderer("FIREWALL","FORTINET","FORTIGATE","7.6.7") is None


def test_profiles_api_payload_is_exact_and_registry_driven():
    forti=next(p for p in profiles_payload() if p["id"]=="firewall-fortinet-fortigate")
    assert forti["version_profiles"][0]["release_line"]=="7.6"
    assert forti["version_profiles"][0]["exact_version"]=="7.6.7"
    assert forti["version_profiles"][-1]["exact_version"]=="7.6.4"


def test_all_sixteen_firewall_directions_share_ir_and_exact_target_registry():
    vendors=(Vendor.ASA,Vendor.FORTIGATE,Vendor.PALO_ALTO,Vendor.JUNIPER_SRX)
    targets={Vendor.ASA:("CISCO","ASA","9.24"),Vendor.FORTIGATE:("FORTINET","FORTIGATE","7.6.4"),Vendor.PALO_ALTO:("PALO_ALTO","PAN_OS","11.1"),Vendor.JUNIPER_SRX:("JUNIPER","SRX","23.4R2")}
    profiles={p.source_vendor:p for p in PLATFORM_PROFILES if p.domain=="FIREWALL"}
    directions=set()
    for source,target in itertools.product(vendors,repeat=2):
        assert profiles[source].source_parser
        vendor,platform,version=targets[target]
        assert lookup_renderer("FIREWALL",vendor,platform,version)
        directions.add((source,target))
    assert len(directions)==16


def test_exact_versions_scope_metadata_and_cp2_decision_identity():
    source=PROFILES["fortios-7.4"]; target=PROFILES["panos-11.1"]
    entity=Address(id="a1",name="HOST",type="host",value="192.0.2.1")
    first=result(entity,"address",CompatibilityStatus.EXACT); first.target_version="11.1"
    second=result(entity,"address",CompatibilityStatus.EXACT); second.target_version="12.1.6"
    finalize(first,entity,source,target,"address","LOCAL")
    finalize(second,entity,source,target,"address","LOCAL")
    assert first.decision_id!=second.decision_id
    asa=next(p for p in profiles_payload() if p["id"]=="firewall-cisco-asa")
    legacy=next(p for p in asa["version_profiles"] if p["exact_version"]=="9.24")
    assert legacy["target_renderer_available"] and legacy["version_status"]=="LEGACY_VERIFIED"