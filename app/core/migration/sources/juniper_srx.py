from app.core.models import Vendor
from .base import MigrationSourceAdapter


class JuniperSrxSourceAdapter(MigrationSourceAdapter):
    vendor=Vendor.JUNIPER_SRX
    def adapt(self,config): return config