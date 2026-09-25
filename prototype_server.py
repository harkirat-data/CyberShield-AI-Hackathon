#!/usr/bin/env python3
"""
VALENS — Protected Asset Prototype Server
===========================================
Hosts the client application prototypes on Port 8090:
- Medicare.AI Healthcare Operations Portal (Default)
- Apex Global Treasury Financial Portal
- VALENS Prototype Showcase & Deception Grid Preview

Seamlessly linked to the VALENS Autonomous SOC Engine running on Port 8050.
"""

from pathlib import Path
import httpx
import uvicorn
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, FileResponse, RedirectResponse, Response

PROJECT_ROOT = Path(__file__).resolve().parent
DASHBOARD_ROOT = PROJECT_ROOT / "dashboard"
TEMPLATES_ROOT = PROJECT_ROOT / "honeypot" / "templates"
SOC_BACKEND_URL = "http://127.0.0.1:8050"

app = FastAPI(
    title="VALENS Protected Prototype Platform",
    description="Customer Asset Prototypes protected by VALENS Autonomous WAF & Deception Mesh",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

NO_CACHE_HEADERS = {
    "Cache-Control": "no-cache, no-store, must-revalidate",
    "Pragma": "no-cache",
    "Expires": "0",
}


@app.get("/", include_in_schema=False)
@app.get("/medicare", include_in_schema=False)
@app.get("/apps/medicare", include_in_schema=False)
def serve_medicare_prototype():
    """Serves the primary Medicare.AI Clinical Intelligence Portal prototype."""
    medicare_file = TEMPLATES_ROOT / "medicare_portal.html"
    if medicare_file.is_file():
        return HTMLResponse(content=medicare_file.read_text(encoding="utf-8"), status_code=200, headers=NO_CACHE_HEADERS)
    return HTMLResponse("<h1>Medicare.AI Clinical Operations Portal</h1>", status_code=200)


@app.get("/finance", include_in_schema=False)
@app.get("/finance-portal", include_in_schema=False)
def serve_finance_prototype():
    """Serves the Apex Global Treasury Financial Portal prototype."""
    finance_file = TEMPLATES_ROOT / "finance_portal.html"
    if finance_file.is_file():
        return HTMLResponse(content=finance_file.read_text(encoding="utf-8"), status_code=200, headers=NO_CACHE_HEADERS)
    return HTMLResponse("<h1>Apex Global Treasury Portal</h1>", status_code=200)


@app.get("/dashboard", include_in_schema=False)
@app.get("/showcase", include_in_schema=False)
def serve_dashboard_showcase():
    """Serves the VALENS Prototype Landing and Architecture Showcase."""
    index_file = DASHBOARD_ROOT / "index.html"
    if index_file.is_file():
        return FileResponse(index_file, media_type="text/html", headers=NO_CACHE_HEADERS)
    return HTMLResponse("<h1>VALENS Platform Showcase</h1>", status_code=200)


@app.get("/console", include_in_schema=False)
def redirect_to_soc_console():
    """Redirects to the live VALENS SOC Command Center Console on Port 8050."""
    return RedirectResponse(url="http://127.0.0.1:8050/console", status_code=302)


@app.get("/api/v1/sentinel/agent.js", include_in_schema=False)
def serve_sentinel_script():
    """Serves the Sentinel Agent extension script with port 8090 awareness."""
    script_file = DASHBOARD_ROOT / "sentinel_agent.js"
    if script_file.is_file():
        return FileResponse(script_file, media_type="application/javascript", headers=NO_CACHE_HEADERS)
    return Response(content="console.log('Sentinel agent ready');", media_type="application/javascript")


# Serve static assets from dashboard folder (styles.css, console.css, app.js, logo.svg, etc.)
@app.get("/dashboard/{file_path:path}", include_in_schema=False)
def serve_dashboard_static(file_path: str):
    target = DASHBOARD_ROOT / file_path
    if target.is_file():
        media_type = "text/css" if file_path.endswith(".css") else (
            "application/javascript" if file_path.endswith(".js") else (
                "image/svg+xml" if file_path.endswith(".svg") else (
                    "image/png" if file_path.endswith(".png") else "application/octet-stream"
                )
            )
        )
        return FileResponse(target, media_type=media_type, headers=NO_CACHE_HEADERS)
    return Response(status_code=404)


# Reverse proxy any API calls targeting /api/v1/... to the live SOC backend on Port 8050
@app.api_route("/api/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"], include_in_schema=False)
async def proxy_to_soc_backend(request: Request, path: str):
    target_url = f"{SOC_BACKEND_URL}/api/{path}"
    headers = dict(request.headers)
    headers.pop("host", None)
    body = await request.body()
    params = dict(request.query_params)

    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            resp = await client.request(
                method=request.method,
                url=target_url,
                headers=headers,
                params=params,
                content=body,
            )
            return Response(
                content=resp.content,
                status_code=resp.status_code,
                headers=dict(resp.headers),
            )
        except Exception as exc:
            return Response(
                content=f'{{"ok": false, "error": "SOC backend unreachable: {exc}"}}',
                status_code=502,
                media_type="application/json",
            )


if __name__ == "__main__":
    port = 8090
    print("=" * 60)
    print("VALENS — Protected Customer Prototype Server")
    print(f"[*] Serving Medicare.AI Prototype on: http://127.0.0.1:{port}/")
    print(f"[*] Serving Apex Finance Prototype on: http://127.0.0.1:{port}/finance")
    print(f"[*] Serving Platform Showcase on: http://127.0.0.1:{port}/dashboard")
    print(f"[*] Connected to VALENS SOC Backend at: {SOC_BACKEND_URL}")
    print("=" * 60)
    uvicorn.run("prototype_server:app", host="0.0.0.0", port=port, reload=True)
