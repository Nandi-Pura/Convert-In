import ipaddress
import re

from app.core.models import LAG, ParseIssue, Provenance, Severity, SVI, SwitchConfig, SwitchPort, UnparsedConstruct, Vendor, VLAN
from app.core.parsing.base import DetectionResult
from app.core.switch_assurance import finalize_switch_extraction


class IosXeSwitchParser:
    vendor=Vendor.CISCO_IOSXE

    def detect(self,text):
        evidence=[x for x in ("switchport ","vlan ","channel-group ","interface vlan") if x in text.lower()]
        return DetectionResult(self.vendor,min(1,len(evidence)/2),evidence)

    def parse(self,text):
        version="17.12.1" if re.search(r"^Cisco IOS XE Software, Version 17\.12\.1\b",text,re.M|re.I) else None
        cfg=SwitchConfig(metadata={"source_vendor":self.vendor,"platform":"IOS_XE","domain":"SWITCH","version_status":"EXACT" if version else "VERSION_NOT_VERIFIED"})
        context=("GLOBAL",None); ignored=0
        for number,raw in enumerate(text.splitlines(),1):
            line=raw.strip()
            if not line or line.startswith(("!","#")) or line in {"exit","end"}:
                ignored+=1
                if line=="end":context=("GLOBAL",None)
                continue
            if not raw[:1].isspace():context=("GLOBAL",None)
            p=Provenance(source_vendor=self.vendor,source_version=version,source_line=number,source_section=context[0])
            try:
                if re.match(r"Cisco IOS XE Software, Version 17\.12\.1\b",line,re.I):
                    cfg.metadata["version_detection"]={"detected_version":version,"detected_family":version};ignored+=1
                elif re.fullmatch(r"vlan \d+",line):
                    vid=int(line.split()[1]); obj=VLAN(id=f"vlan:{vid}",vlan_id=vid,provenance=p);cfg.vlans.append(obj);context=("VLAN",obj)
                elif line.startswith("interface "):
                    name=line.split(None,1)[1]
                    if re.fullmatch(r"Vlan\d+",name,re.I):obj=SVI(id=f"svi:{name}",name=name,vlan_id=int(name[4:]),provenance=p);cfg.svis.append(obj);context=("SVI",obj)
                    elif re.fullmatch(r"Port-channel\d+",name,re.I):obj=LAG(id=f"lag:{name}",name=name,provenance=p);cfg.lags.append(obj);context=("LAG",obj)
                    else:obj=SwitchPort(id=f"interface:{name}",name=name,provenance=p);cfg.ports.append(obj);context=("PORT",obj)
                elif context[0]=="VLAN" and line.startswith("name "):context[1].name=line[5:]
                elif context[0] in {"PORT","LAG","SVI"}:self._interface(cfg,context,line,number,raw)
                elif line.startswith(("spanning-tree ","vtp ")):self._unknown(cfg,number,raw,"Switch feature outside Q16 scope",True,"switch_feature")
                else:self._unknown(cfg,number,raw,"Unrecognized switch construct",False,"other")
            except (ValueError,IndexError) as exc:self._unknown(cfg,number,raw,f"Malformed switch construct: {exc}",False,"malformed")
        by_name={x.name:x for x in cfg.lags}
        for port in cfg.ports:
            if port.lag and port.lag in by_name:by_name[port.lag].members.append(port.name)
        return finalize_switch_extraction(cfg,ignored,version)

    def _interface(self,cfg,context,line,number,raw):
        kind,obj=context
        if line.startswith("description "):obj.description=line[12:]
        elif line=="shutdown":obj.enabled=False
        elif line=="no shutdown":obj.enabled=True
        elif kind=="PORT" and line in {"switchport mode access","switchport mode trunk"}:obj.mode=line.rsplit(" ",1)[1]
        elif kind=="PORT" and line.startswith("switchport access vlan "):obj.access_vlan=int(line.split()[3])
        elif kind in {"PORT","LAG"} and line.startswith("switchport trunk native vlan "):obj.native_vlan=int(line.split()[4])
        elif kind in {"PORT","LAG"} and line.startswith("switchport trunk allowed vlan "):
            obj.allowed_vlans=self._vlans(line.split()[4])
        elif kind=="PORT" and line.startswith("channel-group "):
            match=re.fullmatch(r"channel-group (\d+) mode (active|passive|on)",line)
            if not match:raise ValueError("unsupported channel-group syntax")
            obj.lag=f"Port-channel{match.group(1)}";obj.vendor_extensions["lacp_mode"]=match.group(2)
        elif kind=="SVI" and line.startswith("ip address "):
            _,_,address,mask,*rest=line.split()
            if rest:raise ValueError("unsupported SVI address option")
            obj.addresses.append(str(ipaddress.ip_interface(f"{address}/{mask}")))
        elif line=="switchport":pass
        else:self._unknown(cfg,number,raw,"Interface feature outside Q16 scope",True,"interface_feature")

    @staticmethod
    def _vlans(value):
        result=[]
        for part in value.split(","):
            if "-" in part:
                first,last=map(int,part.split("-",1));result.extend(range(first,last+1))
            else:result.append(int(part))
        return result

    def _unknown(self,cfg,line,raw,reason,unsupported,category):
        cfg.unparsed_constructs.append(UnparsedConstruct(vendor=self.vendor,line_number=line,raw_text=raw,reason=reason,unsupported=unsupported,category=category))
        cfg.warnings.append(ParseIssue(severity=Severity.WARNING,vendor=self.vendor,line=line,message=reason,raw_text=raw))