from .models import (
    HardwareProfile,
    HardwareSelection,
    HardwareSelectionStatus,
    HardwareSoftwareSupport,
    SupportScope,
    SupportStatus,
    MediaCapability, PortCapability, PortCompatibility, PortConnector, PortMappingStatus, PortSpeed,
    SourceInterfaceContext, TargetPortCandidate,
)
from .registry import HARDWARE_PROFILES, hardware_registry_payload, validate_registry
from .resolver import detect_hardware, resolve_hardware, resolve_hardware_software_support
from .ports import PORT_CAPABILITIES, candidate_target_ports, evaluate_port_compatibility, port_capability, ports_for_hardware

__all__ = [
    "HARDWARE_PROFILES", "HardwareProfile", "HardwareSelection",
    "HardwareSelectionStatus", "HardwareSoftwareSupport", "SupportScope", "SupportStatus",
    "detect_hardware", "hardware_registry_payload", "resolve_hardware",
    "resolve_hardware_software_support", "validate_registry",
    "MediaCapability", "PortCapability", "PortCompatibility", "PortConnector", "PortMappingStatus", "PortSpeed",
    "SourceInterfaceContext", "TargetPortCandidate", "PORT_CAPABILITIES", "candidate_target_ports",
    "evaluate_port_compatibility", "port_capability", "ports_for_hardware",
]
