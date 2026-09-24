from app.core.models import Vendor
from app.core.parsing.base import DetectionResult
from app.vendors.cisco_asa.parser import AsaParser
from app.vendors.fortigate.parser import FortiGateParser
from app.vendors.paloalto.parser import PaloAltoParser
from app.vendors.juniper_srx.parser import JunosSrxParser
from app.vendors.cisco_iosxe.parser import IosXeRouterParser
from app.vendors.cisco_iosxe.switch_parser import IosXeSwitchParser
from app.core.platforms import platform_profile

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

def lookup_parser(profile_id:str,version:str):
    profile=platform_profile(profile_id,version)
    if profile and profile.source_parser=="IosXeSwitchParser":return IosXeSwitchParser()
    return PARSERS.get(profile.source_vendor) if profile and profile.source_parser else None

def parse_profile(text:str,profile_id:str,version:str):
    profile=platform_profile(profile_id,version)
    if profile and profile.source_parser=="IosXeSwitchParser":return IosXeSwitchParser().parse(text)
    if not profile or not profile.source_parser:raise ValueError("Invalid source platform or version profile.")
    return parse_config(text,profile.source_vendor)