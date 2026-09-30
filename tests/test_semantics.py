from app.core.models import Vendor
from app.core.parsing import parse_config

def test_equivalent_allow_rule_concepts():
    asa=parse_config("access-list x extended permit tcp object A object B eq 443",Vendor.ASA).security_policies[0]
    forti=parse_config('config firewall policy\n edit 1\n set srcaddr "A"\n set dstaddr "B"\n set service "HTTPS"\n set action accept\n next\nend',Vendor.FORTIGATE).security_policies[0]
    pan=parse_config('<config><devices><entry><vsys><entry name="vsys1"><rulebase><security><rules><entry name="x"><source><member>A</member></source><destination><member>B</member></destination><service><member>service-https</member></service><action>allow</action></entry></rules></security></rulebase></entry></vsys></entry></devices></config>',Vendor.PALO_ALTO).security_policies[0]
    assert {asa.action,forti.action,pan.action} == {"allow"}
    assert [asa.sources,forti.sources,pan.sources] == [["A"]]*3
    assert [asa.destinations,forti.destinations,pan.destinations] == [["B"]]*3