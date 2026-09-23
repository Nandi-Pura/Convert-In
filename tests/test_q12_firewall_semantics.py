from pathlib import Path

from app.core.models import Vendor
from app.core.renderers.registry import lookup_renderer
from app.core.versions import exact_profile
from app.core.versions.models import CapabilityStatus


CAPABILITIES=("interface_zone_context","disabled_rules","icmp","source_ports","multiple_service_ranges","nested_groups","fqdn_objects","ipv6_objects","logging","schedules","static_route_options")
TARGETS=((Vendor.ASA,"9.24"),(Vendor.FORTIGATE,"7.6.4"),(Vendor.PALO_ALTO,"11.1"),(Vendor.JUNIPER_SRX,"23.4R2"))


def test_q12_audit_is_complete_and_non_emitting():
    for vendor,version in TARGETS:
        profile=exact_profile(vendor,version)
        assert profile is not None
        for name in CAPABILITIES:
            capability=profile.capabilities[f"q12.{name}"]
            assert capability.status==CapabilityStatus.VERSION_NOT_VERIFIED
            assert not capability.renderer_support
            assert not capability.documentation_refs


def test_q12_version_boundaries_do_not_register_adjacent_renderers():
    assert lookup_renderer("FIREWALL","CISCO","ASA","9.24")
    assert lookup_renderer("FIREWALL","FORTINET","FORTIGATE","7.6.4")
    assert lookup_renderer("FIREWALL","PALO_ALTO","PAN_OS","11.1")
    assert lookup_renderer("FIREWALL","JUNIPER","SRX","23.4R2")
    assert lookup_renderer("FIREWALL","CISCO","ASA","9.24(10)") is None
    assert lookup_renderer("FIREWALL","FORTINET","FORTIGATE","7.6.7") is None
    assert lookup_renderer("FIREWALL","PALO_ALTO","PAN_OS","11.2.9") is None
    assert lookup_renderer("FIREWALL","JUNIPER","SRX","24.4R2") is None


def test_q12_unverified_state_is_visible_in_documentation():
    text=Path("docs/firewall-semantic-coverage.md").read_text(encoding="utf-8")
    assert text.count("| VERSION_NOT_VERIFIED |")==44
    assert text.count("| REVIEW |")==44