import hashlib
import ipaddress
from defusedxml import ElementTree as ET
from defusedxml.common import DefusedXmlException
from app.core.models import (Address,FirewallConfig,Interface,NatRule,ParseIssue,Provenance,
    SecurityRule,Service,Severity,StaticRoute,UnparsedConstruct,Vendor,Zone)
from app.core.parsing.base import DetectionResult
from app.core.versions import detect_version

class PaloAltoParser:
    vendor=Vendor.PALO_ALTO
    def detect(self,text):
        hits=[x for x in ("<config","<devices","<vsys") if x in text.lower()]
        return DetectionResult(self.vendor,len(hits)/3,hits)
    def validate_input(self,text):
        return [] if text.strip() else [ParseIssue(severity=Severity.ERROR,vendor=self.vendor,message="Configuration is empty")]
    def parse(self,text):
        version=detect_version(text,self.vendor)
        cfg=FirewallConfig(metadata={"source_vendor":self.vendor,"version_detection":version.model_dump(mode="json")})
        cfg.warnings.extend(self.validate_input(text))
        if not text.strip(): return cfg.finalize_metrics(0).finalize_extraction(self.vendor,version.detected_family)
        try: root=ET.fromstring(text)
        except (ET.ParseError,DefusedXmlException,ValueError) as exc:
            self._add(cfg,None,"xml",text[:1000],f"Unsafe or invalid XML: {exc}",Severity.ERROR)
            return cfg.finalize_metrics(0).finalize_extraction(self.vendor,version.detected_family)
        device=root.find("./devices/entry"); vsyses=root.findall("./devices/entry/vsys/entry")
        if device is None or len(vsyses)!=1:
            reason="Multiple VSYS contexts require explicit selection; no VSYS was merged" if len(vsyses)>1 else "A local firewall device and exactly one VSYS are required"
            self._xml(cfg,device if device is not None else root,"scope",reason,Severity.ERROR)
            return self._finish(cfg,root,version.detected_family)
        vsys=vsyses[0]; cfg.metadata["vsys"]=vsys.attrib.get("name","")
        p=Provenance(source_vendor=self.vendor,source_version=version.detected_family,source_section=f"vsys:{cfg.metadata['vsys']}")
        shared=root.find("./shared"); shared=shared if shared is not None else device.find("shared")
        if shared is not None:self._xml(cfg,shared,"shared","Shared object inheritance is outside the supported local-VSYS scope")
        for location in ("pre-rulebase","post-rulebase"):
            for node in root.findall(f".//{location}"):self._xml(cfg,node,location,"Panorama rulebase context is not merged into the local firewall rulebase")
        self._addresses(vsys,cfg,p);self._groups(vsys,cfg,p);self._services(vsys,cfg,p)
        self._interfaces(device,cfg,p);self._zones(vsys,cfg,p);self._policies(vsys,cfg,p)
        self._nat(vsys,cfg,p);self._routes(device,cfg,p)
        return self._finish(cfg,root,version.detected_family)
    def _finish(self,cfg,root,version):
        for attr in ("interfaces","zones","addresses","address_groups","services","service_groups","security_policies","nat_policies","static_routes"):
            for entity in getattr(cfg,attr):
                if entity.provenance: entity.provenance=entity.provenance.model_copy(update={"source_section":f"{attr}:{entity.id}"})
        return cfg.finalize_metrics(sum(1 for _ in root.iter())).finalize_extraction(self.vendor,version)
    def _addresses(self,vsys,cfg,p):
        for e in vsys.findall("./address/entry"):
            values=[(tag,e.find(tag)) for tag in ("ip-netmask","ip-range","fqdn") if e.find(tag) is not None]
            if len(values)!=1:self._xml(cfg,e,"address","Address must contain exactly one supported value");continue
            tag,child=values[0];value=(child.text or "").strip()
            try:
                if tag=="ip-netmask":
                    parsed=ipaddress.ip_network(value,strict=False) if "/" in value else ipaddress.ip_address(value)
                    if parsed.version!=4:raise ValueError("IPv6 is outside the P0 slice")
                    value=str(parsed)
                elif tag=="ip-range":
                    start,end=(ipaddress.ip_address(x.strip()) for x in value.split("-",1))
                    if start.version!=4 or end.version!=4 or int(start)>int(end):raise ValueError("invalid IPv4 range")
                    value=f"{start}-{end}"
                elif not value or any(c.isspace() for c in value):raise ValueError("invalid FQDN")
            except (ValueError,TypeError) as exc:self._xml(cfg,e,"address",f"Invalid address value: {exc}",Severity.ERROR);continue
            name=e.attrib.get("name","")
            try:cfg.addresses.append(Address(id=f"address:{name}",name=name,type={"ip-netmask":"network" if "/" in value else "host","ip-range":"range","fqdn":"fqdn"}[tag],value=value,description=e.findtext("description"),tags=self._members(e,"./tag/member"),provenance=p,vendor_extensions=self._ext(e,{tag,"description","tag"})))
            except ValueError as exc:self._xml(cfg,e,"address",str(exc),Severity.ERROR)
    def _groups(self,vsys,cfg,p):
        for e in vsys.findall("./address-group/entry"):
            if e.find("dynamic") is not None:self._xml(cfg,e,"address_group","Dynamic address group requires manual review");continue
            n=e.attrib.get("name","");cfg.address_groups.append(Address(id=f"address_group:{n}",name=n,type="group",members=self._members(e,"./static/member"),description=e.findtext("description"),tags=self._members(e,"./tag/member"),provenance=p,vendor_extensions=self._ext(e,{"static","description","tag"})))
        for e in vsys.findall("./service-group/entry"):
            n=e.attrib.get("name","");cfg.service_groups.append(Service(id=f"service_group:{n}",name=n,protocol="group",members=self._members(e,"./members/member"),description=e.findtext("description"),tags=self._members(e,"./tag/member"),provenance=p,vendor_extensions=self._ext(e,{"members","description","tag"})))
    def _services(self,vsys,cfg,p):
        for e in vsys.findall("./service/entry"):
            protocols=[x for x in ("tcp","udp") if e.find(f"./protocol/{x}") is not None]
            if len(protocols)!=1:self._xml(cfg,e,"service","Exactly one TCP or UDP protocol is required");continue
            proto=protocols[0];dst=(e.findtext(f"./protocol/{proto}/port") or "").split(",");src=(e.findtext(f"./protocol/{proto}/source-port") or "").split(",");n=e.attrib.get("name","")
            try:cfg.services.append(Service(id=f"service:{n}",name=n,protocol=proto,source_ports=[x.strip() for x in src if x.strip()],destination_ports=[x.strip() for x in dst if x.strip()],description=e.findtext("description"),tags=self._members(e,"./tag/member"),provenance=p,vendor_extensions=self._ext(e,{"protocol","description","tag"})))
            except ValueError as exc:self._xml(cfg,e,"service",str(exc),Severity.ERROR)
    def _interfaces(self,device,cfg,p):
        for e in device.findall("./network/interface/ethernet/entry"):
            l3=e.find("layer3")
            if l3 is None:self._xml(cfg,e,"interface","Only Ethernet Layer3 interfaces are supported");continue
            n=e.attrib.get("name","");ext=self._ext(l3,{"ip","units"});ips,invalid=self._ips(l3,cfg,e)
            if ext or invalid:ext["manual_review"]="Unsupported or invalid Layer3 interface settings are preserved"
            cfg.interfaces.append(Interface(id=f"interface:{n}",name=n,ipv4=ips,description=e.findtext("comment"),enabled=e.findtext("disabled","no")!="yes",provenance=p,vendor_extensions=ext))
            for u in l3.findall("./units/entry"):
                un=u.attrib.get("name","");tag=u.findtext("tag")
                if not tag or not tag.isdigit():self._xml(cfg,u,"interface","Layer3 subinterface requires an explicit VLAN tag");continue
                uext=self._ext(u,{"tag","ip","comment"});ips,invalid=self._ips(u,cfg,u)
                if uext or invalid:uext["manual_review"]="Unsupported or invalid Layer3 subinterface settings are preserved"
                cfg.interfaces.append(Interface(id=f"interface:{un}",name=un,type="subinterface",parent=n,vlan=int(tag),ipv4=ips,description=u.findtext("comment"),enabled=u.findtext("disabled","no")!="yes",provenance=p,vendor_extensions=uext))
    def _ips(self,node,cfg,owner):
        out=[];invalid=False
        for item in node.findall("./ip/entry"):
            value=item.attrib.get("name","")
            try:
                parsed=ipaddress.ip_interface(value)
                if parsed.version!=4:raise ValueError
                out.append(str(parsed))
            except ValueError:invalid=True;self._xml(cfg,owner,"interface",f"Invalid or unsupported IPv4 interface address: {value}")
        return out,invalid
    def _zones(self,vsys,cfg,p):
        for e in vsys.findall("./zone/entry"):
            if e.find("./network/layer3") is None:self._xml(cfg,e,"zone","Only Layer3 zones are supported");continue
            ext=self._ext(e,{"network"})
            if ext:ext["manual_review"]="Unsupported zone settings are preserved"
            n=e.attrib.get("name","");cfg.zones.append(Zone(id=f"zone:{n}",name=n,interfaces=self._members(e,"./network/layer3/member"),provenance=p,vendor_extensions=ext))
    def _policies(self,vsys,cfg,p):
        for pos,e in enumerate(vsys.findall("./rulebase/security/rules/entry"),1):
            ext=self._ext(e,{"from","to","source","destination","application","service","action","disabled","description","tag","log-start","log-end"})
            profile=e.find("profile-setting")
            if profile is not None:ext["security_profiles"]=[ET.tostring(profile,encoding="unicode")]
            n=e.attrib.get("name","");cfg.security_policies.append(SecurityRule(id=f"security_policy:{n}",name=n,position=pos,source_zones=self._members(e,"./from/member"),destination_zones=self._members(e,"./to/member"),sources=self._members(e,"./source/member") or ["any"],destinations=self._members(e,"./destination/member") or ["any"],applications=self._members(e,"./application/member") or ["any"],services=self._members(e,"./service/member") or ["any"],action=e.findtext("action","unknown"),enabled=e.findtext("disabled","no")!="yes",log_start=e.findtext("log-start","no")=="yes",log_end=e.findtext("log-end","no")=="yes",description=e.findtext("description"),tags=self._members(e,"./tag/member"),provenance=p,vendor_extensions=ext))
    def _nat(self,vsys,cfg,p):
        for pos,e in enumerate(vsys.findall("./rulebase/nat/rules/entry"),1):
            dyn=e.find("./source-translation/dynamic-ip-and-port");dnat=e.find("./destination-translation");ia=dyn.find("interface-address") if dyn is not None else None
            kind="source_destination_nat" if dyn is not None and dnat is not None else "interface_address_pat" if ia is not None else "dynamic_ip_and_port" if dyn is not None else "destination_static_nat" if dnat is not None else "none"
            ext=self._ext(e,{"from","to","source","destination","service","source-translation","destination-translation","disabled","description","tag"});bad=[]
            if dyn is not None:bad += [x.tag for x in dyn if x.tag not in {"translated-address","interface-address"}]
            if ia is not None:bad += [x.tag for x in ia if x.tag not in {"interface","ip"}]
            if dnat is not None:bad += [x.tag for x in dnat if x.tag not in {"translated-address","translated-port"}]
            if dyn is not None and ia is None and not self._members(dyn,"./translated-address/member"):bad.append("missing-translated-address")
            if dnat is not None and not dnat.findtext("translated-address"):bad.append("missing-destination-address")
            if kind=="none":bad.append("missing-translation")
            if bad:ext["manual_review"]=f"Unsupported NAT settings preserved: {', '.join(bad)}"
            service=self._members(e,"./service/member") or ([e.findtext("service")] if e.findtext("service") else ["any"]);n=e.attrib.get("name","")
            cfg.nat_policies.append(NatRule(id=f"nat_policy:{n}",name=n,type=kind,position=pos,source_zones=self._members(e,"./from/member"),destination_zones=self._members(e,"./to/member"),original_source=self._members(e,"./source/member") or ["any"],original_destination=self._members(e,"./destination/member") or ["any"],original_service=service,translated_source=self._members(dyn,"./translated-address/member") or ([ia.findtext("ip")] if ia is not None and ia.findtext("ip") else []),translated_destination=[dnat.findtext("translated-address")] if dnat is not None and dnat.findtext("translated-address") else [],translated_port=dnat.findtext("translated-port") if dnat is not None else None,translation_target=ia.findtext("interface") if ia is not None else None,enabled=e.findtext("disabled","no")!="yes",description=e.findtext("description"),tags=self._members(e,"./tag/member"),status="PARTIAL",provenance=p,vendor_extensions=ext))
    def _routes(self,device,cfg,p):
        for vr in device.findall("./network/virtual-router/entry"):
            vrn=vr.attrib.get("name","")
            for member in self._members(vr,"./interface/member"):
                interface=next((x for x in cfg.interfaces if x.name==member),None)
                if interface: interface.virtual_router=vrn
                else: self._xml(cfg,vr,"virtual_router",f"Virtual router references missing interface: {member}")
            for e in vr.findall("./routing-table/ip/static-route/entry"):
                dst=e.findtext("destination");nh=e.findtext("./nexthop/ip-address")
                try:
                    if not dst or not nh:raise ValueError("IPv4 destination and IP next-hop are required")
                    if ipaddress.ip_network(dst,strict=False).version!=4 or ipaddress.ip_address(nh).version!=4:raise ValueError("Only IPv4 routes are supported")
                except ValueError as exc:self._xml(cfg,e,"route",f"Unsupported or invalid route next-hop: {exc}");continue
                n=e.attrib.get("name","")
                ext=self._ext(e,{"destination","nexthop","interface","metric","admin-dist","disabled"})
                if ext: ext["manual_review"]="Unsupported static-route settings are preserved"
                try:cfg.static_routes.append(StaticRoute(id=f"route:{vrn}:{n}",name=n,virtual_router=vrn,destination=str(ipaddress.ip_network(dst,strict=False)),next_hop=str(ipaddress.ip_address(nh)),interface=e.findtext("interface"),metric=int(e.findtext("metric")) if e.findtext("metric") else None,distance=int(e.findtext("admin-dist")) if e.findtext("admin-dist") else None,enabled=e.findtext("disabled","no")!="yes",provenance=p,vendor_extensions=ext))
                except ValueError as exc:self._xml(cfg,e,"route",str(exc))
    @staticmethod
    def _members(e,path):
        return [] if e is None else [(x.text or "").strip() for x in e.findall(path) if (x.text or "").strip()]
    @staticmethod
    def _ext(e,known):return {x.tag:ET.tostring(x,encoding="unicode") for x in e if x.tag not in known}
    def _xml(self,cfg,e,section,reason,severity=Severity.WARNING):self._add(cfg,None,section,ET.tostring(e,encoding="unicode") if e is not None else "",reason,severity)
    def _add(self,cfg,line,section,raw,reason,severity=Severity.WARNING):
        identity="xml-"+hashlib.sha256(f"{section}|{reason}|{raw}".encode()).hexdigest()[:16]
        cfg.unparsed_constructs.append(UnparsedConstruct(vendor=self.vendor,section=section,line_number=line,raw_text=raw,reason=reason,severity=severity,source_extraction_id=identity))
        cfg.warnings.append(ParseIssue(severity=severity,vendor=self.vendor,section=section,line=line,message=reason,raw_text=raw))
