from app.core.models import ExtractionOutcome, Vendor
from app.core.parsing import parse_config


def test_asa_construct_accounting_and_deterministic_ids():
    text="""! comment
ASA Version 9.20
object network WEB
 host 192.0.2.10
access-list OUT extended permit tcp any object WEB eq 443
access-group OUT in interface outside
route outside 0.0.0.0 0.0.0.0 192.0.2.1
unknown semantic command
"""
    first=parse_config(text,Vendor.ASA).extraction_coverage
    second=parse_config(text,Vendor.ASA).extraction_coverage
    assert first.semantic_total==first.normalized+first.recovered+first.unparsed+first.unsupported
    assert first.ignored_non_semantic==1 and first.unparsed==1
    assert [x.id for x in first.items]==[x.id for x in second.items]
    assert any(len(x.normalized_entity_ids)==2 for x in first.items)  # ACL and inline service share one source construct.


def test_fortigate_blocks_fields_recovery_and_unsupported():
    text='''# comment
config firewall address
 edit "WEB"
  set subnet 192.0.2.10 255.255.255.255
  set fabric-object enable
 next
end
config firewall central-snat-map
 edit 1
  set srcaddr "all"
 next
end
config router static
 edit 1
  set dst 0.0.0.0 0.0.0.0
  set gateway 192.0.2.1
end
'''
    report=parse_config(text,Vendor.FORTIGATE).extraction_coverage
    assert report.semantic_total==3
    assert (report.normalized,report.recovered,report.unparsed,report.unsupported)==(0,2,0,1)
    assert report.coverage_percent==66.67 and report.ignored_non_semantic==1
    assert any(x.outcome==ExtractionOutcome.SOURCE_UNSUPPORTED for x in report.items)


def test_no_semantic_constructs_has_unavailable_coverage():
    report=parse_config("! comment\n\n",Vendor.ASA).extraction_coverage
    assert report.semantic_total==0 and report.coverage_percent is None