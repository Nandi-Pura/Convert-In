import ipaddress, re
from app.core.models import (Address, FirewallConfig, Interface, NatRule, ParseIssue, Provenance, SecurityRule, Service, Severity, StaticRoute, UnparsedConstruct, Vendor, Zone)
from app.core.parsing.base import DetectionResult
from .topology import AsaTopologyResolver
from app.core.versions import detect_version

PORTS={"www":"80","http":"80","https":"443","ssh":"22","domain":"53","smtp":"25"}; OPS={"eq","range","lt","gt","neq"}

class AsaParser:
    vendor=Vendor.ASA
    def detect(self,text):
        hits=[x for x in ("access-list","object network","object-group","nameif","security-level") if x in text.lower()]; return DetectionResult(self.vendor,min(1,len(hits)/3),hits)
    def validate_input(self,text):return [] if text.strip() else [ParseIssue(severity=Severity.ERROR,vendor=self.vendor,message="Configuration is empty")]
    def parse(self,text):
        lines=text.splitlines(); version=detect_version(text,self.vendor); cfg=FirewallConfig(metadata={"source_vendor":self.vendor,"version_detection":version.model_dump(mode="json")}); cfg.warnings.extend(self.validate_input(text)); current=None; section=None; remarks={}; attachments={}; positions={}; nat_position=0
        for number,raw in enumerate(lines,1):
            line=raw.strip()
            if not line or line.startswith("!"):current=None; section=None; continue
            m=re.fullmatch(r"interface (\S+)",line)
            if m:current=Interface(id=m[1],name=m[1],provenance=self._p(number,"interface")); cfg.interfaces.append(current); section="interface"; continue
            m=re.fullmatch(r"object network (\S+)",line)
            if m:current=Address(id=m[1],name=m[1],type="host",provenance=self._p(number,"object network")); cfg.addresses.append(current); section="object network"; continue
            m=re.fullmatch(r"object-group network (\S+)",line)
            if m:current=Address(id=m[1],name=m[1],type="group",provenance=self._p(number,"object-group network")); cfg.address_groups.append(current); section="object-group network"; continue
            m=re.fullmatch(r"object(?:-group)? service (\S+)(?: (tcp|udp|tcp-udp))?",line)
            if m:
                group=line.startswith("object-group"); current=Service(id=m[1],name=m[1],protocol=m[2] or ("group" if group else "ip"),provenance=self._p(number,"service")); (cfg.service_groups if group else cfg.services).append(current); section="service"; continue
            if section=="interface" and isinstance(current,Interface):
                if line.startswith("description "):current.description=line[12:]; continue
                if line.startswith("nameif "):current.zone=line[7:]; cfg.zones.append(Zone(id=line[7:],name=line[7:],interfaces=[current.name],provenance=self._p(number,section))); continue
                if line.startswith("security-level "):current.vendor_extensions["security_level"]=line.split()[1]; continue
                m=re.fullmatch(r"ip address (\S+) (\S+)",line)
                if m:
                    value=self._network(m[1],m[2],cfg,number,section,line)
                    if value:current.ipv4.append(value)
                    continue
                if line in {"shutdown","no shutdown"}:current.enabled=line=="no shutdown"; continue
            if isinstance(current,Address):
                m=re.fullmatch(r"host (\S+)",line)
                if m:
                    if self._ip(m[1],cfg,number,section,line):current.value=m[1]; current.type="host"
                    continue
                m=re.fullmatch(r"subnet (\S+) (\S+)",line)
                if m:
                    value=self._network(m[1],m[2],cfg,number,section,line)
                    if value:current.value=value; current.type="network"
                    continue
                m=re.fullmatch(r"range (\S+) (\S+)",line)
                if m:current.type="range"; current.value=f"{m[1]}-{m[2]}"; continue
                m=re.fullmatch(r"network-object (?:object|host) (\S+)",line)
                if m:current.members.append(m[1]); continue
                if raw[:1].isspace() and line.startswith("nat "):nat_position+=1; cfg.nat_policies.append(self._object_nat(current,line,number,nat_position)); continue
            if isinstance(current,Service) and self._service_line(current,line,cfg,number):continue
            m=re.fullmatch(r"route (\S+) (\S+) (\S+) (\S+)(?: (\d+))?",line)
            if m:
                destination=self._network(m[2],m[3],cfg,number,"route",line)
                if destination:cfg.static_routes.append(StaticRoute(id=f"route-{number}",name=f"route {destination}",destination=destination,next_hop=m[4],interface=m[1],distance=int(m[5] or 1),provenance=self._p(number,"route")))
                continue
            m=re.fullmatch(r"access-group (\S+) (in|out) interface (\S+)",line)
            if m:attachments[m[1]]={"direction":m[2],"interface":m[3],"line":number}; continue
            m=re.fullmatch(r"access-list (\S+)(?: line \d+)? remark (.+)",line)
            if m:remarks[m[1]]=m[2]; continue
            m=re.match(r"access-list (\S+)(?: line (\d+))? extended (permit|deny) (\S+) (.+)",line)
            if m:
                acl=m[1]; positions[acl]=positions.get(acl,0)+1; rule=self._acl(m,line,number,positions[acl],cfg); rule.description=remarks.pop(acl,None); cfg.security_policies.append(rule); current=None; section="access-list"; continue
            if line.startswith("nat ("):nat_position+=1; cfg.nat_policies.append(self._manual_nat(line,number,nat_position)); continue
            if line.startswith("hostname ") or line.startswith("ASA Version "):continue
            self._unparsed(cfg,number,section,line,"Unsupported ASA syntax")
        for rule in cfg.security_policies:
            attachment=attachments.get(rule.vendor_extensions["acl"]); rule.vendor_extensions["attachment"]=attachment or {"attached":False}; rule.vendor_extensions["attached"]=bool(attachment)
        self._references(cfg); AsaTopologyResolver(cfg).apply(); return cfg.finalize_metrics(len(lines))

    def _p(self,line,section):return Provenance(source_vendor=self.vendor,source_line=line,source_section=section)
    def _unparsed(self,cfg,line,section,raw,reason,severity=Severity.WARNING):cfg.unparsed_constructs.append(UnparsedConstruct(vendor=self.vendor,section=section,line_number=line,raw_text=raw,reason=reason,severity=severity)); cfg.warnings.append(ParseIssue(severity=severity,vendor=self.vendor,section=section,line=line,message=reason,raw_text=raw))
    def _ip(self,value,cfg,line,section,raw):
        try:ipaddress.ip_address(value); return True
        except ValueError:self._unparsed(cfg,line,section,raw,"Invalid IP address",Severity.ERROR); return False
    def _network(self,address,mask,cfg,line,section,raw):
        try:return str(ipaddress.ip_network(f"{address}/{mask}",strict=False))
        except ValueError:self._unparsed(cfg,line,section,raw,"Invalid network or mask",Severity.ERROR); return None
    def _port(self,value,cfg,line):
        if value.isdigit() and 0<=int(value)<=65535:return value
        if value.lower() in PORTS:return PORTS[value.lower()]
        cfg.warnings.append(ParseIssue(severity=Severity.WARNING,vendor=self.vendor,section="service",line=line,message=f"Unknown named service port: {value}")); return None
    def _ports(self,tokens,cfg,line):
        tokens=list(tokens)
        if not tokens or tokens[0] not in OPS:return [],tokens,None
        op=tokens.pop(0); count=2 if op=="range" else 1
        if len(tokens)<count:return [],tokens,op
        values=[self._port(tokens.pop(0),cfg,line) for _ in range(count)]
        if any(x is None for x in values):return [],tokens,op
        if op=="eq":return [values[0]],tokens,None
        if op=="range":return [f"{values[0]}-{values[1]}"],tokens,None
        return [],tokens,op
    def _service_line(self,current,line,cfg,number):
        tokens=line.split()
        if tokens[:2]==["service-object","object"]:current.members.append(tokens[2]); return True
        if tokens and tokens[0] in {"service","service-object"}:
            protocol=tokens[1]; current.protocol=protocol if current.protocol=="ip" else current.protocol
            if current.protocol=="group" and protocol in {"tcp","udp","icmp","ip"}:
                name=f"{current.name}__{len(cfg.services)+1}"; member=Service(id=name,name=name,protocol=protocol,provenance=self._p(number,"service-object")); cfg.services.append(member); current.members.append(name); current=member
            tokens=tokens[2:]
            if "source" in tokens:
                i=tokens.index("source"); part=tokens[i+1:tokens.index("destination") if "destination" in tokens else len(tokens)]; current.source_ports,_,op=self._ports(part,cfg,number); current.vendor_extensions["source_operator"]=op
            if "destination" in tokens:
                current.destination_ports,_,op=self._ports(tokens[tokens.index("destination")+1:],cfg,number); current.vendor_extensions["destination_operator"]=op
            return True
        if tokens and tokens[0]=="port-object":current.destination_ports,_,op=self._ports(tokens[1:],cfg,number); current.vendor_extensions["destination_operator"]=op; return True
        if tokens and tokens[0]=="protocol-object":current.vendor_extensions.setdefault("protocols",[]).append(tokens[1]); return True
        return False
    def _address(self,tokens,i,cfg,number,label):
        if i>=len(tokens):return "any",i
        token=tokens[i]
        if token in {"any","any4","any6"}:return token,i+1
        if token in {"object","object-group"} and i+1<len(tokens):return tokens[i+1],i+2
        if token=="host" and i+1<len(tokens):
            value=tokens[i+1]; name=f"__acl_{number}_{label}"; cfg.addresses.append(Address(id=name,name=name,type="host",value=value,provenance=self._p(number,"access-list inline"))); return name,i+2
        if i+1<len(tokens):
            try:value=str(ipaddress.ip_network(f"{token}/{tokens[i+1]}",strict=False)); name=f"__acl_{number}_{label}"; cfg.addresses.append(Address(id=name,name=name,type="network",value=value,provenance=self._p(number,"access-list inline"))); return name,i+2
            except ValueError:pass
        return token,i+1
    def _acl(self,m,line,number,position,cfg):
        acl,sequence,action,protocol,rest=m.groups(); tokens=rest.split(); source,i=self._address(tokens,0,cfg,number,"src"); source_ports,remainder,source_op=self._ports(tokens[i:],cfg,number); i+=len(tokens[i:])-len(remainder); destination,i=self._address(tokens,i,cfg,number,"dst"); destination_ports,remainder,destination_op=self._ports(tokens[i:],cfg,number)
        if remainder[:1] in (["object"],["object-group"]) and len(remainder)>1:services=[remainder[1]]
        elif protocol in {"tcp","udp"} and destination_ports:
            service=f"__acl_{number}_service"; cfg.services.append(Service(id=service,name=service,protocol=protocol,source_ports=source_ports,destination_ports=destination_ports,provenance=self._p(number,"access-list inline"),vendor_extensions={"source_operator":source_op,"destination_operator":destination_op})); services=[service]
        else:services=[protocol]
        return SecurityRule(id=f"{acl}-{sequence or number}",name=f"{acl} line {sequence or number}",position=int(sequence) if sequence else position,sources=[source],destinations=[destination],services=services,action=action,provenance=self._p(number,"access-list"),vendor_extensions={"acl":acl,"protocol":protocol,"sequence":int(sequence) if sequence else None,"raw_acl":line,"source_ports":source_ports,"source_operator":source_op,"destination_operator":destination_op})
    def _object_nat(self,obj,line,number,position):
        m=re.fullmatch(r"nat \(([^,]+),([^\)]+)\) (static|dynamic) (\S+)(.*)",line); ext={"raw":line,"section":2,"section_name":"auto","sequence":position}
        if not m:return NatRule(id=f"nat-{number}",name=f"NAT-{position:03}",type="unknown",position=position,provenance=self._p(number,"object NAT"),vendor_extensions=ext)
        src,dst,mode,target,_=m.groups(); identity=target==obj.name; kind="identity_nat" if identity else "dynamic_pat" if mode=="dynamic" and target=="interface" else "static_source_nat" if mode=="static" else "dynamic_source_nat"
        return NatRule(id=f"nat-{number}",name=f"NAT-{position:03}",type=kind,position=position,ingress_interface=src,egress_interface=dst,source_zones=[src],destination_zones=[dst],original_source=[obj.name],translated_source=[target],translation_target="INTERFACE_ADDRESS" if target=="interface" else None,identity=identity,status="MANUAL_REVIEW" if identity else "SUPPORTED",provenance=self._p(number,"object NAT"),vendor_extensions=ext)
    def _manual_nat(self,line,number,position):
        tokens=line.split(); pair=tokens[1][1:-1].split(","); section=3 if "after-auto" in tokens else 1; ext={"raw":line,"section":section,"section_name":"after-auto" if section==3 else "before-auto","sequence":position}
        def after(keyword):
            try:
                i=tokens.index(keyword); values=tokens[i+1:i+4]
                return values[1:3] if values and values[0] in {"static","dynamic"} else values[:2]
            except ValueError:return []
        source=after("source"); destination=after("destination"); service=after("service"); identity=len(source)==2 and source[0]==source[1]
        return NatRule(id=f"nat-{number}",name=f"NAT-{position:03}",type="identity_nat" if identity else "twice_nat",position=position,ingress_interface=pair[0] if pair else None,egress_interface=pair[1] if len(pair)>1 else None,source_zones=pair[:1],destination_zones=pair[1:2],original_source=source[:1],translated_source=source[1:2],original_destination=destination[:1],translated_destination=destination[1:2],original_service=service[:1],translated_service=service[1:2],identity=identity,provenance=self._p(number,"manual NAT"),vendor_extensions=ext)
    def _references(self,cfg):
        known={"any","any4","any6","ip","icmp","tcp","udp"}|{x.name for x in cfg.addresses+cfg.address_groups+cfg.services+cfg.service_groups}
        for rule in cfg.security_policies:
            for ref in rule.sources+rule.destinations+rule.services:
                if ref not in known:cfg.warnings.append(ParseIssue(severity=Severity.WARNING,vendor=self.vendor,section="access-list",object=rule.name,message=f"Unresolved reference: {ref}"))