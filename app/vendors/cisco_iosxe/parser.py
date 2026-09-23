import ipaddress
import re

from app.core.models import (BGPNeighbor,BGPNetwork,BGPProcess,OSPFProcess,OSPFArea,ParseIssue,PrefixList,PrefixListEntry,
    Provenance,RoutePolicy,RoutePolicyTerm,RouterConfig,RouterInterface,RouterStaticRoute,RouterVRF,Severity,UnparsedConstruct,Vendor)
from app.core.parsing.base import DetectionResult
from app.core.router_assurance import finalize_router_extraction


class IosXeRouterParser:
    vendor=Vendor.CISCO_IOSXE
    def detect(self,text):
        lower=text.lower(); evidence=[x for x in ("cisco ios xe software, version","router bgp ","router ospf ","vrf definition ","ip route ") if x in lower]
        if "asa version" in lower:return DetectionResult(self.vendor,0,[])
        return DetectionResult(self.vendor,min(1,len(evidence)/2),evidence)

    def parse(self,text):
        version="17.12.1" if re.search(r"^Cisco IOS XE Software, Version 17\.12\.1\b",text,re.M|re.I) else None
        cfg=RouterConfig(metadata={"source_vendor":self.vendor,"platform":"IOS_XE","domain":"ROUTER","version_status":"EXACT" if version else "VERSION_NOT_VERIFIED"}); context=("GLOBAL",None); ignored=0
        prefix_lists={}; policies={}; bgp=None
        lines=text.splitlines()
        for number,raw in enumerate(lines,1):
            line=raw.strip()
            if not line or line.startswith("!") or line.startswith("#") or line in {"exit","end"}: ignored+=1; context=("GLOBAL",None) if line=="end" else context; continue
            if not raw[:1].isspace(): context=("GLOBAL",None)
            p=Provenance(source_vendor=self.vendor,source_version=version,source_line=number,source_section=context[0])
            try:
                if re.match(r"Cisco IOS XE Software, Version 17\.12\.1\b",line,re.I): cfg.metadata["version_detection"]={"detected_version":"17.12.1","detected_family":"17.12.1"}; ignored+=1
                elif line.startswith("hostname "): cfg.hostname=line.split(None,1)[1]
                elif line.startswith("interface "):
                    name=line.split(None,1)[1]; obj=RouterInterface(id=f"interface:{name}",name=name,provenance=p); cfg.interfaces.append(obj); context=("INTERFACE",obj)
                elif line.startswith("vrf definition "):
                    name=line.split(None,2)[2]; obj=RouterVRF(id=f"vrf:{name}",name=name,provenance=p); cfg.vrfs.append(obj); context=("VRF",obj)
                elif line.startswith("ip route "): self._route(cfg,line,number,p)
                elif line.startswith("ip prefix-list "): self._prefix(cfg,prefix_lists,line,p)
                elif line.startswith("route-map "):
                    _,name,action,seq=line.split(); policy=policies.setdefault(name,RoutePolicy(id=f"route_policy:{name}",name=name,provenance=p)); term=RoutePolicyTerm(id=f"route_policy:{name}:{seq}",name=seq,sequence=int(seq),action=action,provenance=p); policy.terms.append(term); context=("ROUTE_MAP",term)
                elif line.startswith("router ospf "):
                    parts=line.split(); pid=parts[2]; vrf=parts[4] if len(parts)==5 and parts[3]=="vrf" else None; obj=OSPFProcess(id=f"ospf:{vrf or 'global'}:{pid}",name=pid,process_id=pid,vrf=vrf,provenance=p); cfg.ospf_processes.append(obj); context=("OSPF",obj)
                elif line.startswith("router bgp "):
                    asn=int(line.split()[2]); bgp=BGPProcess(id=f"bgp:global:{asn}",name=str(asn),local_as=asn,provenance=p); cfg.bgp_processes.append(bgp); context=("BGP",bgp)
                elif line.startswith("router "): self._unknown(cfg,number,raw,"Routing protocol outside Q6 scope",True,"routing_protocol")
                elif context[0]=="INTERFACE": self._interface(cfg,context[1],line,number,raw)
                elif context[0]=="ROUTE_MAP": self._route_map(cfg,context[1],line,number,raw)
                elif context[0]=="OSPF": self._ospf(cfg,context[1],line,number,raw)
                elif context[0] in {"BGP","ADDRESS_FAMILY"}: context=self._bgp(cfg,bgp,context,line,number,raw)
                elif line.startswith(("mpls ","ip multicast","class-map ","policy-map ","track ","ip sla ")): self._unknown(cfg,number,raw,"Recognized IOS-XE feature outside Q6 scope",True,"unsupported_feature")
                else:self._unknown(cfg,number,raw,"Unrecognized IOS-XE statement",False,"other")
            except (ValueError,IndexError) as exc:self._unknown(cfg,number,raw,f"Malformed IOS-XE statement: {exc}",False,"malformed")
        cfg.prefix_lists=list(prefix_lists.values()); cfg.route_policies=list(policies.values())
        for interface in cfg.interfaces:
            if not interface.addresses: interface.vendor_extensions["recovered"]=True
        return finalize_router_extraction(cfg,ignored,version)

    def _interface(self,cfg,obj,line,number,raw):
        if line.startswith("description "):obj.description=line.split(None,1)[1]
        elif line=="shutdown":obj.enabled=False
        elif line=="no shutdown":obj.enabled=True
        elif line.startswith("vrf forwarding "):obj.vrf=line.split()[2]
        elif line.startswith("ip address "):
            parts=line.split(); network=ipaddress.ip_interface(f"{parts[2]}/{parts[3]}"); obj.addresses.append(str(network));
            if len(parts)>4 and parts[4]!="secondary":raise ValueError("unsupported ip address option")
        else:self._unknown(cfg,number,raw,"Unsupported interface field preserved",True,"interface_field")

    def _route(self,cfg,line,number,p):
        parts=line.split()[2:]; vrf=None
        if parts[0]=="vrf":vrf=parts[1];parts=parts[2:]
        destination=str(ipaddress.ip_network(f"{parts[0]}/{parts[1]}",strict=False)); rest=parts[2:]; interface=None
        if not self._is_ip(rest[0]):interface=rest.pop(0)
        next_hop=rest.pop(0); ipaddress.ip_address(next_hop); distance=int(rest.pop(0)) if rest and rest[0].isdigit() else None
        if rest:raise ValueError("unsupported route option")
        cfg.static_routes.append(RouterStaticRoute(id=f"route:{vrf or 'global'}:{destination}:{number}",name=destination,destination=destination,next_hop=next_hop,vrf=vrf,interface=interface,distance=distance,provenance=p))

    def _prefix(self,cfg,lists,line,p):
        parts=line.split(); name=parts[2]; i=3; seq=int(parts[i+1]) if parts[i]=="seq" else len(lists.get(name,PrefixList(id="x",name="x")).entries)*5+5; i+=2 if parts[i]=="seq" else 0
        action=parts[i]; prefix=str(ipaddress.ip_network(parts[i+1])); extras=parts[i+2:]; ge=le=None
        while extras:
            key,value=extras[:2]; extras=extras[2:]; ge=int(value) if key=="ge" else ge; le=int(value) if key=="le" else le
        plen=ipaddress.ip_network(prefix).prefixlen
        if ge is not None and (ge<=plen or ge>32):raise ValueError("invalid ge")
        if le is not None and (le<plen or le>32 or ge is not None and le<ge):raise ValueError("invalid le")
        obj=lists.setdefault(name,PrefixList(id=f"prefix_list:{name}",name=name,provenance=p)); obj.entries.append(PrefixListEntry(id=f"prefix_list:{name}:{seq}",name=str(seq),sequence=seq,prefix=prefix,action=action,ge=ge,le=le,provenance=p))

    def _route_map(self,cfg,term,line,number,raw):
        if line.startswith("match ip address prefix-list "):term.prefix_lists.extend(line.split()[4:]);term.match_statements.append(line)
        elif line.startswith("set "):term.set_statements.append(line)
        elif line.startswith("match "):self._unknown(cfg,number,raw,"Recognized route-map match type outside Q6 scope",True,"route_map_field")
        else:self._unknown(cfg,number,raw,"Unrecognized route-map field",False,"route_map_field")

    def _ospf(self,cfg,obj,line,number,raw):
        if line.startswith("router-id "):obj.router_id=line.split()[1];ipaddress.ip_address(obj.router_id)
        elif line.startswith("network "):
            _,address,wildcard,_,area=line.split(); ipaddress.ip_address(address);ipaddress.ip_address(wildcard); found=next((x for x in obj.areas if x.area_id==area),None)
            if not found:found=OSPFArea(area_id=area);obj.areas.append(found)
            found.networks.append(f"{address} {wildcard}")
        else:self._unknown(cfg,number,raw,"Recognized OSPF field outside Q6 scope",True,"ospf_field")

    def _bgp(self,cfg,obj,context,line,number,raw):
        if line=="address-family ipv4":return ("ADDRESS_FAMILY",obj)
        if line.startswith("address-family "):self._unknown(cfg,number,raw,"Advanced BGP address family outside Q6 scope",True,"bgp_address_family");return context
        if line=="exit-address-family":return ("BGP",obj)
        if line.startswith("bgp router-id "):obj.router_id=line.split()[2];return context
        if line.startswith("network "):
            parts=line.split(); prefix=parts[1]; policy=parts[3] if len(parts)==4 and parts[2]=="route-map" else None; obj.networks.append(BGPNetwork(prefix=str(ipaddress.ip_network(prefix)),route_policy=policy));return context
        if line.startswith("neighbor "):
            parts=line.split(); address=parts[1];ipaddress.ip_address(address); neighbor=next((x for x in obj.neighbors if x.address==address),None)
            if not neighbor:neighbor=BGPNeighbor(id=f"bgp_neighbor:{obj.local_as}:{address}",name=address,address=address,provenance=Provenance(source_vendor=self.vendor,source_version=obj.provenance.source_version,source_line=number));obj.neighbors.append(neighbor)
            command=parts[2]
            if command=="remote-as":neighbor.remote_as=int(parts[3])
            elif command=="description":neighbor.description=" ".join(parts[3:])
            elif command=="update-source":neighbor.update_source=parts[3]
            elif command=="route-map":setattr(neighbor,"route_policy_"+parts[4],parts[3])
            else:self._unknown(cfg,number,raw,"Recognized BGP neighbor field outside Q6 scope",True,"bgp_neighbor_field")
            return context
        self._unknown(cfg,number,raw,"Recognized BGP field outside Q6 scope",True,"bgp_field");return context

    def _unknown(self,cfg,line,raw,reason,unsupported,category):
        cfg.unparsed_constructs.append(UnparsedConstruct(vendor=self.vendor,line_number=line,raw_text=raw,reason=reason,unsupported=unsupported,category=category));cfg.warnings.append(ParseIssue(severity=Severity.WARNING,vendor=self.vendor,line=line,message=reason,raw_text=raw))
    @staticmethod
    def _is_ip(value):
        try:ipaddress.ip_address(value);return True
        except ValueError:return False