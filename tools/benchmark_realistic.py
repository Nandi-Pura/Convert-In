import json,time,tracemalloc
from app.core.analysis import AnalysisEngine
from app.core.migration import MigrationPlanner,default_mappings
from app.core.migration.models import SecurityRulePlacement
from app.core.models import Vendor
from app.core.parsing import parse_config
from app.core.renderers import PaloAltoRenderer
from app.core.versions import resolve_context
from app.testing.realistic_fixtures import TIERS,asa,fortigate,juniper_srx,iosxe_router
from app.core.router_assurance import RouterReferenceIntegrityValidator

def measure(vendor,builder,tier):
    text=builder(tier); tracemalloc.start(); total=time.perf_counter(); marks={}
    start=time.perf_counter(); cfg=parse_config(text,vendor); marks["parse"]=time.perf_counter()-start
    start=time.perf_counter(); normalized=cfg.model_dump_json(); marks["normalization"]=time.perf_counter()-start
    start=time.perf_counter(); AnalysisEngine().analyze(cfg); marks["analysis"]=time.perf_counter()-start
    mappings=default_mappings(cfg)
    for i,m in enumerate(mappings.interfaces): m.target_interface=f"ethernet1/{i+1}"; m.target_zone=m.source_nameif; m.confirmed=True
    mappings.security_rule_placement=SecurityRulePlacement(mode="BOTTOM"); version="9.20" if vendor is Vendor.ASA else "23.4R2" if vendor is Vendor.JUNIPER_SRX else "7.4"
    start=time.perf_counter(); plan=MigrationPlanner().plan(cfg,mappings,resolve_context(text,vendor,version),resolve_context("",Vendor.PALO_ALTO,"11.1")); marks["planning"]=time.perf_counter()-start
    start=time.perf_counter(); PaloAltoRenderer().render(plan); marks["render"]=time.perf_counter()-start
    marks["total"]=time.perf_counter()-total; marks["peak_mib"]=tracemalloc.get_traced_memory()[1]/1048576; tracemalloc.stop(); return {k:round(v,4) for k,v in marks.items()}

def measure_router(tier):
    text=iosxe_router(tier);tracemalloc.start();total=time.perf_counter();marks={};start=time.perf_counter();cfg=parse_config(text,Vendor.CISCO_IOSXE);marks["parse_cp0"]=time.perf_counter()-start
    start=time.perf_counter();RouterReferenceIntegrityValidator().validate(cfg);marks["cp1"]=time.perf_counter()-start;marks["total"]=time.perf_counter()-total;marks["peak_mib"]=tracemalloc.get_traced_memory()[1]/1048576;tracemalloc.stop();return {k:round(v,4) for k,v in marks.items()}

if __name__=="__main__":
    results={f"{v.value}/{tier}":measure(v,b,tier) for v,b in ((Vendor.ASA,asa),(Vendor.FORTIGATE,fortigate),(Vendor.JUNIPER_SRX,juniper_srx)) for tier in TIERS}
    results.update({f"{Vendor.CISCO_IOSXE.value}/{tier}":measure_router(tier) for tier in TIERS})
    print(json.dumps(results,indent=2)); assert all(x["total"]<30 for x in results.values()),"30 s loose regression ceiling exceeded"