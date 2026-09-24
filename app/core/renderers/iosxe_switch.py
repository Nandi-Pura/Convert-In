import re
from pydantic import BaseModel
from app.core.migration.models import CompatibilityStatus

class IosXeSwitchCommand(BaseModel):
    entity_id:str; text:str; capability_id:str; documentation_refs:list[str]

class IosXeSwitchRenderer:
    domain="SWITCH";vendor="CISCO";platform="IOS_XE";version="17.12.1"
    def render(self,compatibility):
        self.commands=[]
        for item in compatibility:
            if item.status not in {CompatibilityStatus.EXACT,CompatibilityStatus.SUPPORTED} or item.version_status!="VERIFIED" or not item.renderer_support:continue
            for text in item.target_semantic.get("commands",[]):
                if not re.fullmatch(r"[\x20-\x7e]+",text):raise ValueError("Unsafe IOS-XE command")
                self.commands.append(IosXeSwitchCommand(entity_id=item.entity_id,text=text,capability_id=item.renderer_capability_id,documentation_refs=item.documentation_refs))
        return [x.text for x in self.commands]