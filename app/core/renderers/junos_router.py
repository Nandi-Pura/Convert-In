import re
from pydantic import BaseModel

from app.core.migration.models import CompatibilityStatus


class JunosSetCommand(BaseModel):
    entity_id:str; text:str; target_profile:str="router-juniper-junos"; capability_id:str; documentation_refs:list[str]


class JunosRouterRenderer:
    domain="ROUTER"; vendor="JUNIPER"; platform="JUNOS"; version="23.4R2"

    def render(self,compatibility):
        commands=[]
        for item in compatibility:
            if item.status not in {CompatibilityStatus.EXACT,CompatibilityStatus.SUPPORTED} or item.version_status!="VERIFIED" or not item.renderer_support:continue
            for text in item.target_semantic.get("commands",[]):
                if not re.fullmatch(r"set [\x20-\x7e]+",text):raise ValueError("Unsafe Junos command")
                commands.append(JunosSetCommand(entity_id=item.entity_id,text=text,capability_id=item.renderer_capability_id,documentation_refs=item.documentation_refs))
        self.commands=commands
        return [x.text for x in commands]