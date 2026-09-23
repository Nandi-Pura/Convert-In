from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from app.core.migration.quick_convert import profiles
from app.core.platforms import profiles_payload
from app.config import MAX_CONFIG_BYTES

router = APIRouter(); templates = Jinja2Templates(directory="app/templates")
@router.get("/", response_class=HTMLResponse)
def home(request: Request): return templates.TemplateResponse(request, "index.html", {"quick_profiles":profiles(),"platform_profiles":profiles_payload(),"max_config_bytes":MAX_CONFIG_BYTES})
@router.get("/advanced", response_class=HTMLResponse)
def advanced(request: Request): return templates.TemplateResponse(request, "advanced.html", {"quick_profiles":profiles(),"max_config_bytes":MAX_CONFIG_BYTES})
