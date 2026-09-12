"""
CyberShield AI — Phase 1 Honeypot & SOC Dashboard Server.

Self-contained FastAPI server dedicated to Phase 1:
- Manages multi-port decoy honeypot runtime (SSH 2222, Telnet 2323, HTTP 8088, HTTPS 8443, MySQL 3307)
- Serves the SOC Command Center Dashboard on port 8050
- Zero dependencies on unpushed Phase 2 modules (RAG/Orchestrator)
"""

from __future__ import annotations

import asyncio
import os
import sys
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Query, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from pydantic import BaseModel, Field

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from honeypot.config import HoneypotSettings
from honeypot.runtime import HoneypotRuntime
from honeypot.store import HoneypotStore
from honeypot.models import DecoySession, TelemetryEvent, utc_now
from canary.manager import CanaryManager

DASHBOARD_ROOT = PROJECT_ROOT / "dashboard"
settings = HoneypotSettings.from_env()
store = HoneypotStore(settings.database_path)
runtime = HoneypotRuntime(settings=settings, store=store)
canary_mgr = CanaryManager(store=store)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Automatically start honeypot listeners on server startup
    await runtime.start()
    yield
    # Gracefully stop honeypot listeners on server shutdown
    await runtime.stop()


app = FastAPI(
    title="CyberShield AI — Phase 1: Honeypot Sentinel Grid",
    version="1.0.0",
    lifespan=lifespan,
)

NO_CACHE_HEADERS = {
    "Cache-Control": "no-cache, no-store, must-revalidate",
    "Pragma": "no-cache",
    "Expires": "0",
}


# ============================================================
# DASHBOARD STATIC ROUTES
# ============================================================
@app.get("/", include_in_schema=False)
def root_redirect() -> RedirectResponse:
    return RedirectResponse(url="/dashboard")


@app.get("/dashboard", include_in_schema=False)
def serve_dashboard() -> FileResponse:
    index_file = DASHBOARD_ROOT / "index.html"
    if not index_file.is_file():
        raise HTTPException(status_code=404, detail="Dashboard index.html not found")
    return FileResponse(index_file, media_type="text/html", headers=NO_CACHE_HEADERS)


@app.get("/dashboard/styles.css", include_in_schema=False)
def serve_styles() -> FileResponse:
    css_file = DASHBOARD_ROOT / "styles.css"
    if not css_file.is_file():
        raise HTTPException(status_code=404, detail="Dashboard styles.css not found")
    return FileResponse(css_file, media_type="text/css", headers=NO_CACHE_HEADERS)


@app.get("/dashboard/app.js", include_in_schema=False)
def serve_script() -> FileResponse:
    js_file = DASHBOARD_ROOT / "app.js"
    if not js_file.is_file():
        raise HTTPException(status_code=404, detail="Dashboard app.js not found")
    return FileResponse(js_file, media_type="application/javascript", headers=NO_CACHE_HEADERS)


# ============================================================
# HEALTH & HONEYPOT TELEMETRY API
# ============================================================
@app.get("/health")
def health() -> Dict[str, Any]:
    return {
        "status": "ok",
        "service": "cybershield-honeypot-grid",
        "phase": "1 - Multi-Port Deception Grid",
        "honeypot": runtime.status(),
    }


@app.get("/api/v1/honeypot/status")
def honeypot_status() -> Dict[str, Any]:
    return runtime.status()


@app.get("/api/v1/honeypot/metrics")
def honeypot_metrics() -> Dict[str, Any]:
    return store.metrics()


@app.get("/api/v1/honeypot/sessions")
def list_sessions(limit: int = Query(default=100, ge=1, le=500)) -> Dict[str, Any]:
    sessions = store.list_sessions(limit=limit)
    return {"sessions": sessions}


@app.get("/api/v1/honeypot/sessions/{session_id}")
def get_session(session_id: str) -> Dict[str, Any]:
    sess = store.get_session(session_id)
    if not sess:
        raise HTTPException(status_code=404, detail="Session not found")
    events = store.list_events(session_id=session_id, limit=200)
    return {"session": sess, "events": events}


@app.get("/api/v1/honeypot/events")
def list_events(limit: int = Query(default=200, ge=1, le=1000)) -> Dict[str, Any]:
    events = store.list_events(limit=limit)
    return {"events": events}


@app.post("/api/v1/honeypot/sessions/{session_id}/analyze")
def analyze_session(session_id: str) -> Dict[str, Any]:
    sess = store.get_session(session_id)
    if not sess:
        raise HTTPException(status_code=404, detail="Session not found")
    intent = sess.get("intent", "Reconnaissance")
    return {
        "session": sess,
        "analyst_report": {
            "summary": f"Phase 1 Honeypot Analysis: Detected {intent} activity targeting {sess.get('service', 'decoy')} service. (Autonomous Gemini RAG scheduled for Phase 2).",
            "confidence": sess.get("intent_confidence", 0.75),
            "threat_actor": sess.get("persona", "Decoy Interactive Threat"),
            "mitre_techniques": ["T1046: Network Service Discovery", "T1110: Brute Force"] if "Brute" in intent else ["T1046: Network Service Discovery"],
            "remediation": {
                "immediate": [f"Decoy session sandboxed on port {sess.get('destination_port')}"],
                "short_term": ["Review SHA-256 payload digests in forensic terminal"],
            },
        },
    }


@app.post("/api/v1/honeypot/control/stop")
async def stop_honeypot() -> Dict[str, Any]:
    await runtime.stop()
    return {"ok": True, "status": runtime.status()}


@app.post("/api/v1/honeypot/control/start")
async def start_honeypot() -> Dict[str, Any]:
    await runtime.start()
    return {"ok": True, "status": runtime.status()}


# ============================================================
# CANARY TOKENS API
# ============================================================
class CanaryCreate(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    token_type: str = Field(pattern="^(url|credential|document)$")
    metadata: Optional[Dict[str, Any]] = None


@app.get("/api/v1/canary/tokens")
def get_canary_tokens() -> Dict[str, Any]:
    tokens = canary_mgr.list_tokens()
    return {"count": len(tokens), "tokens": tokens}


@app.post("/api/v1/canary/tokens")
def create_canary_token(req: CanaryCreate) -> Dict[str, Any]:
    token = canary_mgr.create_token(
        name=req.name,
        token_type=req.token_type,
        metadata=req.metadata,
    )
    return {"ok": True, "token": token}


# ============================================================
# ALERTS & INTEL API
# ============================================================
@app.get("/api/v1/alerts/status")
def alerts_status() -> Dict[str, Any]:
    return {
        "channels": {
            "email": {"enabled": True, "recipients": ["soc@cybershield.internal"], "healthy": True},
            "discord": {"enabled": False, "healthy": None},
            "slack": {"enabled": False, "healthy": None},
        },
        "summary": "Phase 1 Socket Trap Alert Dispatcher Ready",
    }


@app.get("/api/v1/intel/attackers")
def get_attackers() -> Dict[str, Any]:
    attackers = []
    seen = set()
    for s in store.list_sessions(limit=50):
        ip = s.get("source_ip")
        if ip and ip not in seen and ip not in ("127.0.0.1", "0.0.0.0"):
            seen.add(ip)
            attackers.append({
                "ip": ip,
                "country": "Remote",
                "city": "External",
                "flag": "🌐",
                "asn": "External Route",
                "isp": "Adversary Network",
                "targeted_decoys": [s.get("service", "decoy")],
                "threat_score": s.get("risk_score", 60),
                "timestamp": s.get("started_at", utc_now()),
            })
    return {"attackers": attackers}


@app.post("/api/v1/intel/simulate-attack")
def simulate_attack() -> Dict[str, Any]:
    sim_ip = "185.220.101.5"
    sim_session = DecoySession(
        session_id=f"sim_{int(asyncio.get_event_loop().time() * 1000)}",
        source_ip=sim_ip,
        source_port=54321,
        destination_port=2222,
        service="SSH",
        protocol="ssh",
        persona="finance-prod shell gateway",
        risk_score=75,
        risk_level="high",
        intent="Brute Force",
    )
    store.create_session(sim_session)
    event = TelemetryEvent(
        session_id=sim_session.session_id,
        event_type="AUTH_FAILED",
        severity="high",
        direction="inbound",
        content="SSH-2.0-paramiko_2.8.0 - Failed login: admin / password123",
    )
    store.record_event(event)
    return {"ok": True, "session": sim_session.to_dict()}


# ============================================================
# WEBSOCKET STREAM
# ============================================================
@app.websocket("/ws/dashboard")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    try:
        while True:
            payload = {
                "type": "state_update",
                "status": runtime.status(),
                "metrics": store.metrics(),
                "sessions": {"sessions": store.list_sessions(limit=50)},
                "canaries": {"tokens": canary_mgr.list_tokens()},
            }
            await websocket.send_json(payload)
            await asyncio.sleep(2)
    except (WebSocketDisconnect, asyncio.CancelledError):
        pass
    except Exception:
        pass


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", "8050"))
    uvicorn.run("honeypot.server:app", host="0.0.0.0", port=port, reload=True)
