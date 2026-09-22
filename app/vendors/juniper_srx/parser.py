import ipaddress
import shlex

from app.core.models import Address,FirewallConfig,Interface,NatRule,ParseIssue,Provenance,SecurityRule,Service,Severity,StaticRoute,UnparsedConstruct,Vendor,Zone
from app.core.parsing.base import DetectionResult


class JunosSrxParser:
    vendor=Vendor.JUNIPER_SRX

    def detect(self,text):
        hits=[x for x in ("set security zones","set security policies","set security address-book") if x in text.lower()]
        return DetectionResult(self.vendor,min(1,len(hits)/2),hits)

    def validate_input(self,text):
        return [] if text.strip() else [ParseIssue(severity=Severity.ERROR,vendor=self.vendor,message="Configuration is empty")]

    def parse(self,text):
        cfg=FirewallConfig(metadata={"source_vendor":self.vendor,"domain":"FIREWALL","syntax":"set"}); cfg.warnings.extend(self.validate_input(text)); policies={}; position=0
        for number,raw in enumerate(text.splitlines(),1):
            line=raw.strip(); inactive=False
            if not line or line.startswith("#"): continue
            if line.startswith("inactive: "): inactive=True; line=line[10:]
            if not line.startswith("set "):
                self._unknown(cfg,number,raw,"Hierarchical Junos syntax is recognized but not normalized in Q5.",unsupported="{" in line or "}" in line); continue
            try: p=shlex.split(line)
            except ValueError: self._unknown(cfg,number,raw,"Malformed quoting"); continue
            provenance=Provenance(source_vendor=self.vendor,source_line=number,source_section=" ".join(p[1:3]))
            try:
                if p[1:4]==["security","zones","security-zone"]:
                    zone=self._get(cfg.zones,p[4],Zone,provenance)
                    if len(p)>=7 and p[5]=="interfaces": zone.interfaces.append(p[6]); self._get(cfg.interfaces,p[6],Interface,provenance).zone=p[4]
                elif p[1:3]==["interfaces",p[2]] and "address" in p:
                    interface=".".join((p[2],p[p.index("unit")+1])) if "unit" in p else p[2]; obj=self._get(cfg.interfaces,interface,Interface,provenance); obj.ipv4.append(p[p.index("address")+1])
                elif p[1:4]==["security","address-book",p[3]] and len(p)>=7 and p[4]=="address":
                    scope=p[3]; name=p[5]; value=p[6]; kind="network" if "/" in value else "host"; ipaddress.ip_network(value,strict=False)
                    cfg.addresses.append(Address(id=f"{scope}:{name}",name=name,type=kind,value=value,provenance=provenance,vendor_extensions={"address_book":scope}))
                elif p[1:4]==["security","address-book",p[3]] and len(p)>=8 and p[4]=="address-set" and p[6]=="address":
                    group=self._get(cfg.address_groups,p[5],Address,provenance,type="group",vendor_extensions={"address_book":p[3]}); group.members.append(p[7])
                elif p[1:3]==["applications","application"]:
                    app=self._get(cfg.services,p[3],Service,provenance,protocol="ip")
                    if p[4]=="protocol": app.protocol=p[5]
                    elif p[4]=="destination-port": app.destination_ports.append(p[5].replace("to","-"))
                    else: self._unknown(cfg,number,raw,"Unsupported application field preserved",True)
                elif p[1:3]==["applications","application-set"] and p[4]=="application":
                    self._get(cfg.service_groups,p[3],Service,provenance,protocol="group").members.append(p[5])
                elif p[1:3]==["security","policies"] and p[3]=="from-zone" and p[5]=="to-zone" and p[7]=="policy":
                    key=(p[4],p[6],p[8]); rule=policies.get(key)
                    if rule is None: position+=1; rule=policies.setdefault(key,SecurityRule(id=f"{p[4]}:{p[6]}:{p[8]}",name=p[8],position=position,source_zones=[p[4]],destination_zones=[p[6]],sources=[],destinations=[],services=[],provenance=provenance))
                    rule.enabled &= not inactive; field=p[9:]
                    if field[:2]==["match","source-address"]: rule.sources.append(field[2])
                    elif field[:2]==["match","destination-address"]: rule.destinations.append(field[2])
                    elif field[:2]==["match","application"]: rule.services.append(field[2])
                    elif field[:1]==["then"] and field[1] in {"permit","deny","reject"}: rule.action=field[1]
                    elif field[:2]==["then","log"]: rule.log_start|=field[2]=="session-init"; rule.log_end|=field[2]=="session-close"
                    else: rule.vendor_extensions["manual_review"]="Unsupported policy field preserved."; self._unknown(cfg,number,raw,"Unsupported policy field preserved",True)
                elif p[1:4]==["routing-options","static","route"] and p[5]=="next-hop":
                    cfg.static_routes.append(StaticRoute(id=f"route:{p[4]}",name=p[4],destination=p[4],next_hop=p[6],provenance=provenance))
                elif p[1:3]==["security","nat"]:
                    kind=p[3] if p[3] in {"source","destination","static"} else "unknown"; name=p[p.index("rule")+1] if "rule" in p else f"nat-{number}"
                    if not any(x.name==name for x in cfg.nat_policies): cfg.nat_policies.append(NatRule(id=f"nat:{kind}:{name}",name=name,type=f"{kind}_nat",provenance=provenance,vendor_extensions={"manual_review":"SRX NAT is recognized; PAN NAT generation remains disabled."}))
                else: self._unknown(cfg,number,raw,"Unrecognized Junos set statement")
            except (IndexError,ValueError) as exc: self._unknown(cfg,number,raw,f"Invalid Junos statement: {exc}")
        cfg.security_policies=list(policies.values())
        return cfg

    @staticmethod
    def _get(items,name,kind,provenance,**values):
        found=next((x for x in items if x.name==name),None)
        if found:return found
        found=kind(id=name,name=name,provenance=provenance,**values); items.append(found); return found

    def _unknown(self,cfg,line,raw,reason,unsupported=False):
        cfg.unparsed_constructs.append(UnparsedConstruct(vendor=self.vendor,line_number=line,raw_text=raw,reason=reason,unsupported=unsupported)); cfg.warnings.append(ParseIssue(severity=Severity.WARNING,vendor=self.vendor,line=line,message=reason))