import hashlib
from collections import Counter

from app.core.migration.models import CompatibilityResult, CompatibilityStatus
from app.core.models import ExtractionCategoryBreakdown, ExtractionCoverageReport, ExtractionOutcome, SourceExtractionItem, Vendor
from app.core.reference_integrity import ReferenceCategoryBreakdown, ReferenceFindingType, ReferenceIntegrityFinding, ReferenceIntegrityReport, ReferenceIntegrityStatus
from app.core.models import Severity


def finalize_switch_extraction(cfg,ignored,version):
    items=[]
    for kind,entities in (("vlan",cfg.vlans),("interface",cfg.ports),("lag",cfg.lags),("svi",cfg.svis)):
        for entity in entities:
            location=f"line {entity.provenance.source_line}" if entity.provenance else "unknown"
            raw=f"{kind}|{entity.id}|{location}"
            items.append(SourceExtractionItem(id=hashlib.sha256(raw.encode()).hexdigest()[:16],source_vendor=Vendor.CISCO_IOSXE,source_version=version,source_type=kind,source_name=entity.name or str(getattr(entity,"vlan_id","")),source_location=location,outcome=ExtractionOutcome.NORMALIZED,normalized_entity_ids=[entity.id]))
    for entry in cfg.unparsed_constructs:
        outcome=ExtractionOutcome.SOURCE_UNSUPPORTED if entry.unsupported else ExtractionOutcome.UNPARSED
        raw=f"{entry.category}|{entry.raw_text}|{entry.line_number}"
        items.append(SourceExtractionItem(id=hashlib.sha256(raw.encode()).hexdigest()[:16],source_vendor=Vendor.CISCO_IOSXE,source_version=version,source_type=entry.category or "other",source_name=entry.section or "construct",source_location=f"line {entry.line_number}",outcome=outcome,reason=entry.reason))
    counts=Counter(x.outcome for x in items); categories={}
    fields={ExtractionOutcome.NORMALIZED:"normalized",ExtractionOutcome.RECOVERED:"recovered",ExtractionOutcome.UNPARSED:"unparsed",ExtractionOutcome.SOURCE_UNSUPPORTED:"unsupported"}
    for item in items:
        row=categories.setdefault(item.source_type,ExtractionCategoryBreakdown());row.semantic_total+=1;setattr(row,fields[item.outcome],getattr(row,fields[item.outcome])+1)
    total=len(items);cfg.extraction_coverage=ExtractionCoverageReport(source_vendor=Vendor.CISCO_IOSXE,source_version=version,semantic_total=total,normalized=counts[ExtractionOutcome.NORMALIZED],recovered=counts[ExtractionOutcome.RECOVERED],unparsed=counts[ExtractionOutcome.UNPARSED],unsupported=counts[ExtractionOutcome.SOURCE_UNSUPPORTED],ignored_non_semantic=ignored,coverage_percent=round(counts[ExtractionOutcome.NORMALIZED]/total*100,2) if total else None,category_breakdown=categories,items=items,warnings=[x.message for x in cfg.warnings])
    return cfg


class SwitchReferenceIntegrityValidator:
    def validate(self,cfg):
        findings=[]; refs=[]; vlans={x.vlan_id for x in cfg.vlans}; ports={x.name for x in cfg.ports}; lags={x.name for x in cfg.lags}
        entities=[*cfg.vlans,*cfg.ports,*cfg.lags,*cfg.svis]
        def add(entity,kind,ref,reason):
            raw=f"{kind}|{entity.id}|{ref}"
            findings.append(ReferenceIntegrityFinding(finding_id=hashlib.sha256(raw.encode()).hexdigest()[:16],finding_type=ReferenceFindingType.INVALID_BINDING,severity=Severity.ERROR,source_entity_id=entity.id,source_entity_type=kind,source_entity_name=entity.name or str(getattr(entity,"vlan_id","")),referenced_entity_name=str(ref),reason=reason,blocking=True))
        seen={}
        for vlan in cfg.vlans:
            if not 1<=vlan.vlan_id<=4094:add(vlan,"vlan",vlan.vlan_id,"VLAN ID must be between 1 and 4094.")
            if vlan.vlan_id in seen:add(vlan,"vlan",vlan.vlan_id,"Conflicting VLAN identity or name." if seen[vlan.vlan_id].name!=vlan.name else "Duplicate VLAN ID.")
            seen[vlan.vlan_id]=vlan
        for interface in [*cfg.ports,*cfg.lags]:
            for vid in [getattr(interface,"access_vlan",None),interface.native_vlan,*interface.allowed_vlans]:
                if vid is None:continue
                refs.append(("interface→vlan",vid in vlans))
                if vid not in vlans:add(interface,"interface",vid,"Interface references an undefined VLAN.")
        members={}
        for port in cfg.ports:
            if port.lag:
                refs.append(("interface→lag",port.lag in lags))
                if port.lag not in lags:add(port,"interface",port.lag,"Interface references an undefined LAG.")
                if port.name in members and members[port.name]!=port.lag:add(port,"interface",port.lag,"Interface belongs to conflicting LAGs.")
                members[port.name]=port.lag
        for lag in cfg.lags:
            for member in lag.members:
                refs.append(("lag→interface",member in ports))
                if member not in ports:add(lag,"lag",member,"LAG references an undefined interface.")
        for svi in cfg.svis:
            refs.append(("svi→vlan",svi.vlan_id in vlans))
            if svi.vlan_id not in vlans:add(svi,"svi",svi.vlan_id,"SVI references an undefined VLAN.")
        counts=Counter(k for k,_ in refs);resolved=Counter(k for k,ok in refs if ok);blocked={x.source_entity_id for x in findings}
        return ReferenceIntegrityReport(status=ReferenceIntegrityStatus.BLOCKED if findings else ReferenceIntegrityStatus.PASS,total_entities=len(entities),total_references=len(refs),resolved_references=sum(resolved.values()),unresolved_references=len(refs)-sum(resolved.values()),warnings=0,blocking_findings=len(findings),findings=sorted(findings,key=lambda x:x.finding_id),category_breakdown={k:ReferenceCategoryBreakdown(total=v,resolved=resolved[k],unresolved=v-resolved[k]) for k,v in counts.items()},entity_statuses={x.id:ReferenceIntegrityStatus.BLOCKED if x.id in blocked else ReferenceIntegrityStatus.PASS for x in entities},duplicates=sum("Duplicate" in x.reason for x in findings))


class SwitchCompatibilityEvaluator:
    REF="IOSXE-17.12.1-C9300-COMMANDS"
    def evaluate(self,cfg,source,target,mappings,cp1):
        blocked={k for k,v in cp1.entity_statuses.items() if v==ReferenceIntegrityStatus.BLOCKED};results=[]
        maps={x.get("source_entity_id"):x for x in mappings.get("interfaces",[]) if x.get("confirmed") and x.get("source_profile")==source.id and x.get("source_version")=="17.12.1" and x.get("target_profile")==target.id and x.get("target_version")=="17.12.1"}
        def add(entity,kind,commands,reasons=()):
            status=CompatibilityStatus.MANUAL_REVIEW if entity.id in blocked or reasons else CompatibilityStatus.SUPPORTED
            if entity.id in blocked:reasons=("CP1 reference integrity is blocked.",)
            item=CompatibilityResult(entity_id=entity.id,entity_type=kind,source_name=entity.name or str(getattr(entity,"vlan_id","")),status=status,reasons=list(reasons),source_version="17.12.1",target_version="17.12.1",documentation_refs=[self.REF],version_status="VERIFIED",renderer_capability_id=kind,renderer_support=status==CompatibilityStatus.SUPPORTED,blocking=status!=CompatibilityStatus.SUPPORTED,target_semantic={"commands":commands if status==CompatibilityStatus.SUPPORTED else []})
            item.decision_id=hashlib.sha256(f"{entity.id}|{target.id}|{status}".encode()).hexdigest()[:16];results.append(item)
        for x in cfg.vlans:add(x,"vlan",[f"vlan {x.vlan_id}"]+([f" name {x.name}"] if x.name else []))
        for x in cfg.ports:
            mapping=maps.get(x.id);same=source.id==target.id
            identity=x.name if same else mapping.get("target_identity") if mapping else None
            if not identity:add(x,"interface",[],("Confirmed target interface mapping is required.",));continue
            commands=[f"interface {identity}"]+([f" description {x.description}"] if x.description else [])+([" switchport mode access",f" switchport access vlan {x.access_vlan}"] if x.mode=="access" and x.access_vlan else [])+([" switchport mode trunk"]+[f" switchport trunk allowed vlan {','.join(map(str,x.allowed_vlans))}"]*(bool(x.allowed_vlans))+[f" switchport trunk native vlan {x.native_vlan}"]*(x.native_vlan is not None) if x.mode=="trunk" else [])+([" shutdown"] if not x.enabled else [" no shutdown"])
            if x.lag:
                mode=x.vendor_extensions.get("lacp_mode");commands.append(f" channel-group {x.lag.removeprefix('Port-channel')} mode {mode}")
            add(x,"interface",commands)
        for x in cfg.lags:add(x,"lag",[f"interface {x.name}"]+([f" description {x.description}"] if x.description else [])+([" shutdown"] if not x.enabled else [" no shutdown"]))
        for x in cfg.svis:add(x,"svi",[f"interface Vlan{x.vlan_id}"]+([f" description {x.description}"] if x.description else [])+[f" ip address {a.ip} {a.netmask}" for a in map(__import__('ipaddress').ip_interface,x.addresses)]+([" shutdown"] if not x.enabled else [" no shutdown"]))
        return results