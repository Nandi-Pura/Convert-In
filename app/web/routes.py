from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from app.core.migration.quick_convert import profiles

router = APIRouter(); templates = Jinja2Templates(directory="app/templates")
@router.get("/", response_class=HTMLResponse)
def home(request: Request): return templates.TemplateResponse(request, "index.html", {"quick_profiles":profiles()})
