from app.core.models import Vendor
from app.core.parsing.base import DetectionResult
from app.vendors.cisco_asa.parser import AsaParser
from app.vendors.fortigate.parser import FortiGateParser
from app.vendors.paloalto.parser import PaloAltoParser
from app.vendors.juniper_srx.parser import JunosSrxParser
from app.vendors.cisco_iosxe.parser import IosXeRouterParser

PARSERS = {p.vendor: p for p in (AsaParser(), FortiGateParser(), PaloAltoParser(), JunosSrxParser(), IosXeRouterParser())}

def detect_vendor(text: str) -> DetectionResult:
    result = max((p.detect(text) for p in PARSERS.values()), key=lambda x: x.confidence)
    return result if result.confidence >= .34 else DetectionResult(Vendor.UNKNOWN, result.confidence, result.evidence)

def parse_config(text: str, vendor: Vendor):
    if vendor not in PARSERS: raise ValueError("Select a source vendor")
    cfg=PARSERS[vendor].parse(text)
    if vendor in {Vendor.ASA, Vendor.FORTIGATE, Vendor.JUNIPER_SRX}:
        detected=cfg.metadata.get("version_detection",{}).get("detected_family")
        ignored=sum(not line.strip() or line.lstrip().startswith(("!","#")) for line in text.splitlines())
        cfg.finalize_extraction(vendor,detected,ignored)
    return cfg