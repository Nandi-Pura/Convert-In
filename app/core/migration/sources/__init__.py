from .base import MigrationSourceAdapter
from .cisco_asa import CiscoAsaSourceAdapter
from .fortigate import FortiGateSourceAdapter
from .juniper_srx import JuniperSrxSourceAdapter

class NormalizedSourceAdapter(MigrationSourceAdapter):
    def adapt(self,config): return config
