import time
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from app import __version__
from app.config import settings
from app.web import api, routes

settings.workspace_dir.mkdir(parents=True, exist_ok=True)
app = FastAPI(title="ConfigMorph", version=__version__, docs_url=None, redoc_url=None)
app.mount("/static", StaticFiles(directory="app/static"), name="static")
app.include_router(routes.router); app.include_router(api.router)

@app.middleware("http")
async def security_headers(request: Request, call_next):
    started = time.perf_counter(); response = await call_next(request)
    response.headers.update({"Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer", "X-Frame-Options": "DENY", "Server-Timing": f'app;dur={(time.perf_counter()-started)*1000:.1f}'})
    return response

@app.middleware("http")
async def input_size_limit(request: Request, call_next):
    length = request.headers.get("content-length")
    ceiling=settings.max_request_bytes
    if request.method in {"POST", "PUT", "PATCH"} and length and int(length) > ceiling:
        return JSONResponse({"detail": "Request exceeds input size limit"}, status_code=413)
    return await call_next(request)

@app.get("/health")
def health(): return {"status": "ok", "version": __version__}
