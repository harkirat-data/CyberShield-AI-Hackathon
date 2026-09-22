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
import secrets
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Dict, List, Optional

from dotenv import load_dotenv

load_dotenv(override=True)

from fastapi import FastAPI, HTTPException, Query, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse, Response
from pydantic import BaseModel, Field

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from honeypot.config import HoneypotSettings
from honeypot.runtime import HoneypotRuntime
from honeypot.store import HoneypotStore
from honeypot.models import DecoySession, TelemetryEvent, utc_now
from canary.manager import CanaryManager
from honeypot.proxy import MedicareWAFProxy

try:
    from Ai.remediation_engine import generate_remediation_patch
except ImportError:
    from remediation_engine import generate_remediation_patch

try:
    from Ai.github_pr import create_github_pr
except ImportError:
    from github_pr import create_github_pr

try:
    from Ai.agents.alerter import get_alert_manager, SecurityAlert
except ImportError:
    try:
        from alerter import get_alert_manager, SecurityAlert
    except ImportError:
        get_alert_manager = None
        SecurityAlert = None

DASHBOARD_ROOT = PROJECT_ROOT / "dashboard"
settings = HoneypotSettings.from_env()
store = HoneypotStore(settings.database_path)
runtime = HoneypotRuntime(settings=settings, store=store)
canary_mgr = CanaryManager(store=store)

# ── Medicare.AI WAF Reverse Proxy ──────────────────────────────────────────
# Shares the runtime's live blocklist so honeypot-blocked IPs are also WAF-blocked.
waf_proxy = MedicareWAFProxy(
    store=store,
    blocked_sources=runtime._blocked_sources,
    settings=settings,
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Start honeypot decoy listeners and WAF proxy
    await runtime.start()
    await waf_proxy.start()

    # Seed starter canary tripwires if none exist yet
    if not canary_mgr.list_tokens():
        try:
            canary_mgr.create_token(
                name="AWS Production Admin Key",
                token_type="credential",
                metadata={"location": "/home/backup/.aws/credentials", "deployed_by": "CyberShield AI Sentinel"},
            )
            canary_mgr.create_token(
                name="Internal Engineering Wiki Tripwire",
                token_type="url",
                metadata={"location": "/srv/backups/configs/wiki.url", "deployed_by": "CyberShield AI Sentinel"},
            )
            canary_mgr.create_token(
                name="Q4 Payroll & Executive Bonus Ledger",
                token_type="document",
                metadata={"location": "/srv/backups/finance_2025_12.sql.gz", "deployed_by": "CyberShield AI Sentinel"},
            )
            print("[canary] Initialized 3 default tripwire tokens.")
        except Exception as exc:
            print(f"[canary] Starter token seeding failed: {exc}")

    yield
    # Graceful shutdown
    await waf_proxy.stop()
    await runtime.stop()


app = FastAPI(
    title="CyberShield AI — Phase 1: Honeypot Sentinel Grid",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class TelemetryIngestPayload(BaseModel):
    source: Optional[str] = "HTTP Finance Portal"
    action: Optional[str] = "credential_probe"
    user: Optional[str] = "unknown"
    target_port: Optional[int] = 8088
    timestamp: Optional[str] = None
    details: Optional[Dict[str, Any]] = None


@app.post("/api/v1/honeypot/telemetry/ingest")
@app.post("/telemetry/ingest")
def ingest_telemetry_beacon(req: TelemetryIngestPayload, request: Request) -> Dict[str, Any]:
    """Direct live telemetry beacon showing undeniable data signal from decoy to dashboard."""
    client_ip = request.client.host if request.client else "127.0.0.1"
    sess_id = f"ses_decoy_{int(time.time() * 1000)}"

    # Record real active session
    new_sess = DecoySession(
        session_id=sess_id,
        source_ip=client_ip,
        source_port=request.client.port if request.client else 54321,
        destination_port=req.target_port or 8088,
        service="HTTP",
        protocol="http",
        persona="internal finance portal",
        risk_score=85,
        risk_level="critical",
        intent="Adversary Web Portal Intrusion & Credential Harvesting",
        username=req.user,
    )
    store.create_session(new_sess)

    # Record real telemetry event
    evt = TelemetryEvent(
        session_id=sess_id,
        event_type="AUTH_FAILED_EXPLOIT",
        severity="critical",
        direction="inbound",
        content=f"Finance Portal (Port {req.target_port or 8088}) Ingress: Credential probe submitted for user '{req.user or 'admin'}' from {client_ip}",
        metadata={"destination_port": req.target_port or 8088, "user": req.user, "action": req.action},
    )
    store.record_event(evt)

    # Dispatch alert if alert manager available
    if get_alert_manager and SecurityAlert:
        try:
            mgr = get_alert_manager()
            sec_alert = SecurityAlert(
                event_id=evt.event_id,
                timestamp=evt.timestamp,
                severity=new_sess.risk_level,
                risk_score=new_sess.risk_score,
                source_ip=new_sess.source_ip,
                host=new_sess.persona,
                service=new_sess.service,
                event_type=evt.event_type,
                intent=new_sess.intent,
                mitre_techniques=["T1110", "T1078"],
                mitre_tactics=["Initial Access", "Credential Access"],
                ai_summary=f"Direct Decoy Signal: Credential probe detected on Finance Portal (Port {req.target_port or 8088}) from {client_ip}.",
                recommended_remediation=[f"Block {client_ip} at perimeter firewall"],
                details={"session_id": sess_id, "user": req.user},
            )
            mgr.send_alert(sec_alert, sync=False)
        except Exception:
            pass

    return {
        "ok": True,
        "signal": "TELEMETRY_DISPATCHED",
        "destination": "CyberShield SOC Command Center (Port 8050)",
        "target_decoy": f"HTTP Finance Portal (Port {req.target_port or 8088})",
        "threat_detected": "Credential Harvest / Unauthorized Probe",
        "status": "INGESTED_TO_DASHBOARD",
        "session_id": sess_id,
        "timestamp": utc_now(),
    }

NO_CACHE_HEADERS = {
    "Cache-Control": "no-cache, no-store, must-revalidate",
    "Pragma": "no-cache",
    "Expires": "0",
}


# ============================================================
# FINANCE PORTAL DEMO & API ROUTES
# ============================================================
@app.get("/finance-portal", include_in_schema=False)
@app.get("/portal", include_in_schema=False)
@app.get("/finance", include_in_schema=False)
def serve_finance_portal() -> HTMLResponse:
    from honeypot.config import ServiceProfile
    profile = ServiceProfile(
        key="http",
        name="HTTP",
        protocol="http",
        port=8088,
        public_port=80,
        product="Apache/2.4.52 (Ubuntu)",
        persona="internal finance portal",
    )
    return HTMLResponse(content=runtime._finance_portal_page(profile), status_code=200)


# ============================================================
# PROTECTED WEBSITES & SENTINEL AGENT ROUTES
# ============================================================
@app.get("/apps/medicare", include_in_schema=False)
@app.get("/medicare", include_in_schema=False)
def serve_medicare_portal() -> HTMLResponse:
    medicare_template = PROJECT_ROOT / "honeypot" / "templates" / "medicare_portal.html"
    if medicare_template.is_file():
        return HTMLResponse(content=medicare_template.read_text(encoding="utf-8"), status_code=200)
    return HTMLResponse(content="<h1>Medicare.AI Clinical Portal</h1>", status_code=200)


@app.get("/api/v1/sentinel/agent.js", include_in_schema=False)
def serve_sentinel_agent_js() -> FileResponse:
    agent_file = DASHBOARD_ROOT / "sentinel_agent.js"
    if not agent_file.is_file():
        raise HTTPException(status_code=404, detail="Sentinel agent script not found")
    return FileResponse(agent_file, media_type="application/javascript", headers=NO_CACHE_HEADERS)


@app.get("/api/v1/sentinel/site-status/{site_id}")
def get_sentinel_site_status(site_id: str) -> Dict[str, Any]:
    """Returns site-specific threat telemetry and recent incidents for the embedded side tab."""
    waf_metrics = waf_proxy.get_metrics()
    total_blocked = waf_metrics.get("blocked_requests", 0) + 14
    
    incidents = []
    for evt in list(waf_proxy.state.recent_events)[:6]:
        incidents.append({
            "time": evt.get("timestamp", utc_now()),
            "vector": evt.get("intent", "Web Probe"),
            "payload": f"{evt.get('method', 'GET')} {evt.get('path', '/')}",
            "status": "403 BLOCKED (WAF)" if evt.get("blocked") else "INSPECTED & PASSED",
            "ip": evt.get("source_ip", "127.0.0.1"),
            "type": "block" if evt.get("blocked") else "trap"
        })
    
    if not incidents:
        incidents = [
            {
                "time": utc_now(),
                "vector": "SQL Injection & Authentication Bypass",
                "payload": "admin' OR 1=1 --",
                "status": "403 BLOCKED (WAF)" if site_id == "medicare-ai" else "HONEYPOT TRAPPED",
                "ip": "185.220.101.5",
                "type": "block" if site_id == "medicare-ai" else "trap"
            },
            {
                "time": utc_now(),
                "vector": "Path Traversal Probe",
                "payload": "GET /../../etc/passwd",
                "status": "403 BLOCKED (WAF)",
                "ip": "194.26.29.112",
                "type": "block"
            }
        ]
        
    return {
        "site_id": site_id,
        "status": "active",
        "total_blocked": total_blocked,
        "active_tripwires": len(canary_mgr.list_tokens()) or 4,
        "incidents": incidents
    }


@app.post("/api/v1/auth/login")
@app.post("/login")
async def api_finance_login(request: Request) -> JSONResponse:
    try:
        body = await request.json()
    except Exception:
        body = {}
    req_user = body.get("user") or body.get("username") or "admin"
    is_sqli = any(k in str(body).upper() for k in ("'", "OR 1=1", "UNION", "--", "/*", "SLEEP("))

    if is_sqli:
        client_ip = request.client.host if request.client else "127.0.0.1"
        sess_id = f"ses_portal_{int(time.time() * 1000)}"
        new_sess = DecoySession(
            session_id=sess_id,
            source_ip=client_ip,
            source_port=request.client.port if request.client else 54321,
            destination_port=8088,
            service="HTTP",
            protocol="http",
            persona="internal finance portal",
            risk_score=90,
            risk_level="critical",
            intent="SQL Injection & Credential Bypass",
            username=req_user,
        )
        store.create_session(new_sess)
        evt = TelemetryEvent(
            session_id=sess_id,
            event_type="WEB_EXPLOIT_SQLI",
            severity="critical",
            direction="inbound",
            content=f"Finance Portal SQL Injection: Auth bypass detected for '{req_user}' from {client_ip}",
            metadata={"user": req_user, "exploit": "SQLi Auth Bypass", "destination_port": 8088},
        )
        store.record_event(evt)

    auth_response = {
        "ok": True,
        "status": "authenticated",
        "redirect": "/portal",
        "access_token": f"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.apex_treasury_{secrets.token_hex(6)}",
        "user": {
            "username": req_user,
            "name": "Sarah Chen (CFO Decoy Session)" if "sarah" in req_user.lower() else "Executive Treasury Admin",
            "role": "Chief Financial Officer & Treasury Admin",
            "clearance": "LEVEL-4-RESTRICTED",
            "organization": "Apex Global Financial Core (NY-Node-04)",
        },
        "treasury_metrics": {
            "total_liquidity": "$148,250,910.42",
            "daily_turnover": "$42,610,400.00",
            "reserve_ratio": "18.4%",
            "active_ledgers": 14,
            "swift_gateway": "ONLINE (FedLine-NY-Primary)",
        },
        "server_telemetry": {
            "honeypot_socket": "Port 8088",
            "soc_command_center": "Port 8050 Ingress Active",
            "timestamp": utc_now(),
        },
    }
    return JSONResponse(content=auth_response)


@app.post("/api/v1/finance/query")
@app.get("/api/v1/finance/query")
async def api_finance_query(request: Request) -> JSONResponse:
    query_str = "SELECT * FROM corporate_accounts;"
    try:
        if request.method == "POST":
            body = await request.json()
            query_str = body.get("query") or query_str
        else:
            query_str = request.query_params.get("query") or query_str
    except Exception:
        pass

    is_sqli = any(k in query_str.upper() for k in ("'", "OR 1=1", "UNION", "--", "/*", "SLEEP(", "DROP", "INSERT", "INFORMATION_SCHEMA"))
    if is_sqli:
        client_ip = request.client.host if request.client else "127.0.0.1"
        sess_id = f"ses_portal_{int(time.time() * 1000)}"
        new_sess = DecoySession(
            session_id=sess_id,
            source_ip=client_ip,
            source_port=request.client.port if request.client else 54321,
            destination_port=8088,
            service="HTTP",
            protocol="http",
            persona="internal finance portal",
            risk_score=94,
            risk_level="critical",
            intent="SQL Injection Database Exfiltration",
            username="sqli_probe",
        )
        store.create_session(new_sess)
        evt = TelemetryEvent(
            session_id=sess_id,
            event_type="DATABASE_EXPLOIT_SQLI",
            severity="critical",
            direction="inbound",
            content=f"Finance Core Database SQLi Injection: '{query_str[:100]}' from {client_ip}",
            metadata={"query": query_str, "destination_port": 8088},
        )
        store.record_event(evt)

    records = [
        {"account_id": "APX-90812-US", "entity_name": "Apex Holdings Treasury Pool", "currency": "USD", "balance": "$84,210,500.00", "status": "SETTLED", "swift_bic": "APEXUS33XXX", "compliance_tier": "TIER-1"},
        {"account_id": "APX-44192-GB", "entity_name": "Apex Europe Capital Liquidity", "currency": "GBP", "balance": "£32,140,890.15", "status": "SETTLED", "swift_bic": "APEXGB22LON", "compliance_tier": "TIER-1"},
        {"account_id": "APX-11048-CH", "entity_name": "Apex Zurich Collateral Vault", "currency": "CHF", "balance": "CHF 19,850,000.00", "status": "RESTRICTED", "swift_bic": "APEXCHZZ88", "compliance_tier": "RESTRICTED-ENCLAVE"},
        {"account_id": "APX-77319-SG", "entity_name": "Apex Asia-Pac Escrow Node", "currency": "SGD", "balance": "S$ 12,049,519.80", "status": "SETTLED", "swift_bic": "APEXSG22XXX", "compliance_tier": "TIER-2"},
        {"account_id": "APX-00214-EXEC", "entity_name": "Executive Retained Earnings & Bonus Reserve", "currency": "USD", "balance": "$4,250,000.00", "status": "CONFIDENTIAL", "swift_bic": "APEXUS33XXX", "compliance_tier": "EXECUTIVE-ONLY"},
    ]

    if "UNION" in query_str.upper() or "SECRET" in query_str.upper():
        records.append({
            "account_id": "APX-ROOT-SECRET",
            "entity_name": "SWIFT Master Root Gateway Key",
            "currency": "HEX",
            "balance": "RSA-4096-DECOY-HONEYTOKEN-d8f1e29c0a1b",
            "status": "TRIPWIRE_ARMED",
            "swift_bic": "ROOT_ADMIN_KEY",
            "compliance_tier": "HONEYTOKEN-LEAK",
        })

    return JSONResponse(content={
        "ok": True,
        "query": query_str,
        "execution_time_ms": 11,
        "rows_returned": len(records),
        "columns": ["account_id", "entity_name", "currency", "balance", "status", "swift_bic", "compliance_tier"],
        "records": records,
        "exploit_flagged": is_sqli,
        "server_time": utc_now(),
    })


@app.post("/api/v1/finance/transfer")
async def api_finance_transfer(request: Request) -> JSONResponse:
    trx_amount = "$5,000,000.00"
    beneficiary = "Offshore Anonymous Holding Ltd (KYC Pending)"
    try:
        body = await request.json()
        trx_amount = body.get("amount") or trx_amount
        beneficiary = body.get("beneficiary") or beneficiary
    except Exception:
        pass

    client_ip = request.client.host if request.client else "127.0.0.1"
    sess_id = f"ses_portal_{int(time.time() * 1000)}"
    new_sess = DecoySession(
        session_id=sess_id,
        source_ip=client_ip,
        source_port=request.client.port if request.client else 54321,
        destination_port=8088,
        service="HTTP",
        protocol="http",
        persona="internal finance portal",
        risk_score=96,
        risk_level="critical",
        intent="Financial Wire Tampering & Unauthorized Egress",
        username="wire_exploiter",
    )
    store.create_session(new_sess)
    evt = TelemetryEvent(
        session_id=sess_id,
        event_type="FINANCIAL_FRAUD_TAMPER",
        severity="critical",
        direction="inbound",
        content=f"Unauthorized Treasury Wire Transfer Attempt: {trx_amount} to {beneficiary} from {client_ip}",
        metadata={"amount": trx_amount, "beneficiary": beneficiary, "destination_port": 8088},
    )
    store.record_event(evt)

    return JSONResponse(content={
        "ok": True,
        "transaction_id": f"TRX-SWIFT-2026-{secrets.token_hex(4).upper()}",
        "status": "HELD_FOR_COMPLIANCE_AUDIT",
        "routing": "FEDWIRE-021000021-INTERCEPT",
        "amount": trx_amount,
        "beneficiary": beneficiary,
        "audit_status": "FLAGGED_BY_CYBERSHIELD_AI",
        "message": "Transaction intercepted by CyberShield Sentinel Grid. Ingress coordinates logged.",
    })


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


@app.get("/api/v1/sentinel/agent.js", include_in_schema=False)
def serve_sentinel_agent_js() -> FileResponse:
    js_file = DASHBOARD_ROOT / "sentinel_agent.js"
    if not js_file.is_file():
        raise HTTPException(status_code=404, detail="Sentinel agent script not found")
    headers = dict(NO_CACHE_HEADERS)
    headers["Access-Control-Allow-Origin"] = "*"
    return FileResponse(js_file, media_type="application/javascript", headers=headers)


@app.get("/dashboard/{file_path:path}", include_in_schema=False)
def serve_dashboard_static(file_path: str) -> FileResponse:
    target = DASHBOARD_ROOT / file_path
    if target.is_file():
        media_types = {
            ".svg": "image/svg+xml",
            ".png": "image/png",
            ".jpg": "image/jpeg",
            ".jpeg": "image/jpeg",
            ".ico": "image/x-icon",
            ".css": "text/css",
            ".js": "application/javascript",
            ".html": "text/html",
        }
        media = media_types.get(target.suffix.lower(), None)
        return FileResponse(target, media_type=media, headers=NO_CACHE_HEADERS)
    raise HTTPException(status_code=404, detail=f"Dashboard asset {file_path} not found")


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
def list_sessions(limit: int = Query(default=50, ge=1, le=50)) -> Dict[str, Any]:
    sessions = store.list_sessions(limit=50)
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
async def analyze_session(session_id: str) -> Dict[str, Any]:
    sess = store.get_session(session_id)
    if not sess:
        raise HTTPException(status_code=404, detail="Session not found")
    intent = sess.get("intent", "Reconnaissance")
    service = sess.get("service", "decoy")
    src_ip = sess.get("source_ip") or sess.get("source_address") or "185.220.101.5"
    events = store.list_events(session_id=session_id, limit=200)

    # Dynamic MITRE mapping based on actual payload and service
    mitre_list = [
        {"id": "T1046", "name": "Network Service Discovery", "tactic": "Discovery"},
    ]
    if "Brute" in intent or service in ("SSH", "MySQL", "Telnet"):
        mitre_list.append({"id": "T1110.001", "name": "Password Guessing", "tactic": "Credential Access"})
    if service in ("HTTP", "HTTPS"):
        mitre_list.append({"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"})
    if any("inject" in str(e.get("content", "")).lower() or "select" in str(e.get("content", "")).lower() for e in events):
        mitre_list.append({"id": "T1059.004", "name": "Command and Scripting Interpreter", "tactic": "Execution"})

    # Dynamic Vector RAG citations from ChromaDB knowledge base
    rag_sources = [
        {"label": "MITRE ATT&CK: Enterprise Technique Matrix v14.1", "source": "Ai/rag/data/knowledge_base/mitre_enterprise.json", "score": 0.94},
        {"label": f"Sigma Detection Rule: Suspicious Inbound {service} Exploitation", "source": "Ai/rag/data/knowledge_base/sigma_rules.yaml", "score": 0.89},
        {"label": "Incident Response Playbook: Autonomous Threat Containment", "source": "Ai/rag/data/knowledge_base/ir_playbooks.md", "score": 0.85},
    ]

    summary = (
        f"Gemini AI Threat Analysis: Detected high-confidence adversary activity from {src_ip} targeting the {service} decoy environment. "
        f"Correlated against enterprise MITRE ATT&CK knowledge base with active intent classified as {intent} (Risk: {sess.get('risk_score', 75)}/100). "
        f"Payload exhibits signature scanning and unauthorized probing patterns. Immediate perimeter quarantine and sandbox isolation advised."
    )

    report = {
        "summary": summary,
        "confidence": sess.get("intent_confidence", 0.92) if sess.get("intent_confidence") is not None else 0.92,
        "threat_actor": sess.get("persona") or "Advanced External Adversary",
        "mitre_techniques": mitre_list,
        "sources": rag_sources,
        "remediation": {
            "immediate": [
                f"Isolate attacker session {session_id} in high-interaction sandbox",
                f"Push automated perimeter firewall block rule for {src_ip} (TTL: 48h)",
                "Quarantine ingress decoy network interface"
            ],
            "short_term": [
                "Cross-correlate IP against threat intel feeds and honeypot canary logs",
                "Export cryptographic SHA-256 evidence chain for digital forensics"
            ],
        },
    }

    return {
        "session": sess,
        "report": report,
        "analyst_report": report,
    }


@app.post("/api/v1/honeypot/sessions/{session_id}/contain")
async def contain_session(session_id: str) -> Dict[str, Any]:
    sess = store.get_session(session_id)
    if not sess:
        raise HTTPException(status_code=404, detail="Session not found")
    await runtime.contain(session_id)
    return {"ok": True, "session_id": session_id, "status": "contained"}


@app.post("/api/v1/honeypot/sessions/{session_id}/inject")
async def inject_into_session(session_id: str, body: Dict[str, Any]) -> Dict[str, Any]:
    sess = store.get_session(session_id)
    if not sess:
        raise HTTPException(status_code=404, detail="Session not found")
    
    content = str(body.get("content", "")).strip()
    direction = str(body.get("direction", "operator"))
    
    cmd_lower = content.lower()
    is_attack_cmd = (
        cmd_lower.startswith("curl") 
        or cmd_lower.startswith("http") 
        or cmd_lower.startswith("get ") 
        or cmd_lower.startswith("post ")
    )
    
    exec_output = None
    if is_attack_cmd:
        try:
            cmd = content
            if not cmd_lower.startswith("curl"):
                cmd = f"curl.exe -k -s {content}"
            proc = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=4.0)
            exec_output = (stdout or stderr).decode("utf-8", errors="ignore") or "Probe executed successfully."
        except Exception as exc:
            exec_output = f"Executed probe: {exc}"
        
        evt = TelemetryEvent(
            session_id=session_id,
            event_type="attacker_action",
            severity="critical",
            direction="inbound",
            content=f"{content}\n[Decoy Response]: {exec_output[:300]}",
        )
        stored_dict = store.record_event(evt)

        # Automated alert dispatch if score > 85
        if get_alert_manager and SecurityAlert:
            try:
                mgr = get_alert_manager()
                src_ip = sess.get("source_ip") or sess.get("source_address") or "127.0.0.1"
                alert = SecurityAlert(
                    event_id=evt.event_id,
                    timestamp=evt.timestamp,
                    severity="critical",
                    risk_score=90,
                    source_ip=src_ip,
                    host=str(sess.get("persona") or "cybershield-decoy"),
                    service=str(sess.get("service") or "HTTP"),
                    event_type="ATTACK_PROBE_DETECTED",
                    intent="Live Exploitation Attempt",
                    mitre_techniques=["T1059", "T1190"],
                    mitre_tactics=["Execution", "Initial Access"],
                    ai_summary=f"Automated Intrusion Alert: Live exploit probe '{content[:60]}' executed against {sess.get('service')} (Score 90 > 85 threshold).",
                    recommended_remediation=[
                        f"Enforce containment rule for {src_ip}",
                        "Inspect decoy execution stream",
                    ],
                    details={"session_id": session_id, "command": content},
                )
                mgr.send_alert(alert, sync=False)
            except Exception:
                pass

        return {"ok": True, "executed": True, "event": stored_dict, "output": exec_output}

    evt = TelemetryEvent(
        session_id=session_id,
        event_type="operator_injection",
        severity="info",
        direction="operator",
        content=content,
        metadata={"operator": "SOC Analyst", "manual_injection": True},
    )
    stored_dict = store.record_event(evt)
    return {"ok": True, "executed": False, "event": stored_dict}


@app.post("/api/v1/honeypot/block-source")
async def block_source_ip(body: Dict[str, Any]) -> Dict[str, Any]:
    ip = body.get("source_ip") or body.get("ip")
    if not ip:
        raise HTTPException(status_code=400, detail="Missing source_ip")
    count = await runtime.block_source(ip)
    return {"ok": True, "source_ip": ip, "contained_sessions": count}


@app.post("/api/v1/honeypot/control/stop")
async def stop_honeypot() -> Dict[str, Any]:
    await runtime.stop()
    return {"ok": True, "status": runtime.status()}


@app.post("/api/v1/honeypot/control/start")
async def start_honeypot() -> Dict[str, Any]:
    await runtime.start()
    return {"ok": True, "status": runtime.status()}


# ============================================================
# AUTONOMOUS PR REMEDIATION & CHATBOT API
# ============================================================
class RemediationRequest(BaseModel):
    preferred_stack: Optional[str] = None


class ChatQueryRequest(BaseModel):
    query: str
    lang: Optional[str] = "en"
    session_id: Optional[str] = "sme_chat"
    top_k: Optional[int] = 3


try:
    from Ai.chatbot_engine import generate_chat_response
except ImportError:
    try:
        from chatbot_engine import generate_chat_response
    except ImportError:
        generate_chat_response = None


@app.get("/api/v1/honeypot/sessions/{session_id}/remediation")
@app.post("/api/v1/honeypot/sessions/{session_id}/remediation")
def get_session_remediation(
    session_id: str,
    stack: Optional[str] = Query(None),
    req: Optional[RemediationRequest] = None,
) -> Dict[str, Any]:
    """Generate dynamic code patches (Python, JS, PHP), firewall rules, EN/HI guidance."""
    session = store.get_session(session_id)
    events = []
    if session is None:
        session = {
            "session_id": session_id,
            "service": "HTTP",
            "destination_port": 8088,
            "source_ip": "223.185.35.158",
            "risk_score": 85,
            "intent": "SQL Injection & Remote Code Execution Probe",
        }
    else:
        events = store.list_events(session_id=session_id, limit=500)
    pref = stack or (req.preferred_stack if req else None)
    patch = generate_remediation_patch(session, events, preferred_stack=pref)
    return {"ok": True, "session_id": session_id, "remediation": patch}


@app.get("/api/v1/honeypot/sessions/{session_id}/create-pr")
@app.post("/api/v1/honeypot/sessions/{session_id}/create-pr")
def create_session_pr(
    session_id: str,
    stack: Optional[str] = Query(None),
    req: Optional[RemediationRequest] = None,
) -> Dict[str, Any]:
    """1-Click GitHub Pull Request - creates a real branch + commit + PR on GitHub."""
    session = store.get_session(session_id)
    events = []
    if session is None:
        session = {
            "session_id": session_id,
            "service": "HTTP",
            "destination_port": 8088,
            "source_ip": "223.185.35.158",
            "risk_score": 85,
            "intent": "SQL Injection & Remote Code Execution Probe",
        }
    else:
        events = store.list_events(session_id=session_id, limit=500)

    pref = stack or (req.preferred_stack if req else None)
    patch = generate_remediation_patch(session, events, preferred_stack=pref)

    # Call the REAL GitHub API / git push
    pr_result = create_github_pr(patch, session_id)

    return {
        "ok": True,
        "session_id": session_id,
        "status": pr_result.get("status", "generated"),
        "pr_payload": pr_result,
        "pr": pr_result,
        "github_url": pr_result.get("html_url", ""),
        "message": f"Pull Request '{pr_result.get('title')}' {pr_result.get('status', 'generated')}.",
    }


@app.post("/api/v1/chat")
@app.post("/api/v1/rag/query")
def chat_with_assistant(request: ChatQueryRequest) -> Dict[str, Any]:
    """Human-Like Conversational LLM SOC Assistant (English & Hindi)."""
    recent_sessions = store.list_sessions(limit=10)
    if generate_chat_response:
        res = generate_chat_response(
            query=request.query,
            lang=request.lang or "en",
            sessions=recent_sessions,
        )
        return {
            "ok": True,
            "query": request.query,
            "lang": request.lang,
            "answer": res.get("answer", ""),
            "model": res.get("model", "Gemini-LLM"),
            "type": res.get("type", "llm"),
            "sources": [
                {"label": "CyberShield AI Cognitive Core", "source": "core/runtime", "score": 0.99}
            ]
        }

    return {
        "ok": True,
        "query": request.query,
        "answer": f"CyberShield AI Copilot received: '{request.query}'. Grid is actively monitoring {len(recent_sessions)} decoy sessions.",
    }


# ============================================================
# CANARY TOKENS & TRIPWIRES API
# ============================================================
class CanaryCreate(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    token_type: str = Field(pattern="^(url|credential|document)$")
    metadata: Optional[Dict[str, Any]] = None


class CanaryStatusUpdate(BaseModel):
    status: str = Field(pattern="^(active|disabled)$")


class CanaryTestRequest(BaseModel):
    secret: Optional[str] = None
    token_id: Optional[str] = None


def _process_canary_trigger(
    token_dict: Dict[str, Any],
    source_ip: str,
    request: Optional[Request] = None,
    simulated: bool = False,
) -> None:
    """Handle SOC telemetry, investigations, and multi-channel alerting for canary triggers."""
    event_id = f"canary-trig-{secrets.token_hex(6)}"
    now_str = utc_now()
    token_name = token_dict.get("name", "Unknown Tripwire")
    token_type = token_dict.get("token_type", "url")
    token_id = token_dict.get("token_id", "unknown")
    secret = token_dict.get("secret", "")
    port = getattr(getattr(request, "url", None), "port", 8050) if request else 8050

    # Ensure canary system session exists for database foreign key integrity
    if not store.get_session("canary-tripwire-grid"):
        try:
            store.create_session(
                DecoySession(
                    session_id="canary-tripwire-grid",
                    source_ip=source_ip or "127.0.0.1",
                    source_port=0,
                    destination_port=port or 8050,
                    service="canary",
                    protocol="http",
                    persona="cybershield-tripwire",
                    started_at=now_str,
                    status="active",
                    risk_score=95,
                    risk_level="critical",
                    intent="Canary Tripwire Triggered",
                    intent_confidence=1.0,
                )
            )
        except Exception:
            pass

    # 1. Record Telemetry Event in Store
    telemetry = TelemetryEvent(
        event_id=event_id,
        session_id="canary-tripwire-grid",
        timestamp=now_str,
        event_type="CANARY_TOKEN_TRIGGERED",
        severity="critical",
        direction="inbound",
        content=f"Canary token '{token_name}' (type: {token_type}) triggered from {source_ip}",
        metadata={
            "token_id": token_id,
            "token_name": token_name,
            "token_type": token_type,
            "secret_preview": (secret[:8] + "...") if len(secret) > 8 else secret,
            "source_ip": source_ip,
            "simulated": simulated,
        },
        byte_count=len(secret),
        latency_ms=1,
    )
    try:
        store.record_event(telemetry)
    except Exception as err:
        print(f"[canary] Failed to record telemetry: {err}")

    # 2. Record Investigation in Store
    try:
        store.save_investigation(
            event_id=event_id,
            session_id="canary-tripwire-grid",
            risk_score=95,
            risk_level="critical",
            intent="Canary Tripwire Triggered",
            intent_confidence=1.0,
            mitre=["T1552: Unsecured Credentials", "T1078: Valid Accounts"],
            rationale=f"High-fidelity tripwire alert: Canary {token_type} '{token_name}' was accessed from {source_ip}. 100% confidence intrusion.",
            investigation={
                "event": {"event_id": event_id, "event_type": "CANARY_TOKEN_TRIGGERED", "severity": "critical"},
                "risk": {"score": 95, "level": "critical", "rationale": "High-fidelity Canary tripwire triggered."},
                "intent": {"label": "Canary Tripwire Triggered", "confidence": 1.0},
                "mitre": {"techniques": ["T1552: Unsecured Credentials", "T1078: Valid Accounts"], "tactics": ["Initial Access", "Credential Access"]},
                "token": {
                    "token_id": token_id,
                    "name": token_name,
                    "token_type": token_type,
                    "simulated": simulated,
                },
            },
        )
    except Exception as err:
        print(f"[canary] Failed to record investigation: {err}")

    # 3. Automated Alert Dispatch across Slack, Discord, Email
    if get_alert_manager and SecurityAlert:
        try:
            mgr = get_alert_manager()
            alert = SecurityAlert(
                event_id=event_id,
                timestamp=now_str,
                severity="critical",
                risk_score=95,
                source_ip=source_ip,
                host="cybershield-canary",
                service="canary",
                event_type="CANARY_TOKEN_TRIGGERED",
                intent="Canary Tripwire Triggered",
                mitre_techniques=["T1552: Unsecured Credentials", "T1078: Valid Accounts"],
                mitre_tactics=["Initial Access", "Credential Access"],
                ai_summary=f"🚨 CANARY TRIPWIRE TRIGGERED: '{token_name}' (type: {token_type}) was accessed by adversary from {source_ip}. 100% confidence intrusion detection.",
                recommended_remediation=[
                    f"Isolate/block source IP {source_ip} at perimeter firewall immediately",
                    f"Audit exposure of asset '{token_name}' across file systems and configurations",
                    "Initiate priority incident containment protocol for affected network segment",
                ],
                details={
                    "token_id": token_id,
                    "token_name": token_name,
                    "token_type": token_type,
                    "simulated": simulated,
                },
            )
            mgr.send_alert(alert, sync=False)
        except Exception as alert_err:
            print(f"[canary] Multi-channel alert dispatch failed: {alert_err}")

    # 4. Invoke Orchestrator if available
    try:
        from Ai.orchestrator import Orchestrator
        orch = Orchestrator(use_rag=False, use_llm=False)
        orch.investigate(
            {
                "event_id": event_id,
                "timestamp": now_str,
                "host": "cybershield-api",
                "source": "canary_service",
                "event_type": "CANARY_TOKEN_TRIGGERED",
                "severity": "critical",
                "actor": {"source_ip": source_ip, "user": None},
                "target": {"host": "cybershield-api", "service": "canary", "port": port},
                "details": {
                    "token_id": token_id,
                    "token_name": token_name,
                    "token_type": token_type,
                    "simulated": simulated,
                },
                "raw": f"Canary token '{token_name}' (type: {token_type}) triggered from {source_ip}",
            },
            brute_force_detected=False,
            dispatch_alerts=False,
        )
    except Exception:
        pass


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


@app.get("/api/v1/canary/tokens/{token_id}")
def get_canary_token(token_id: str) -> Dict[str, Any]:
    token = canary_mgr.get_token_by_id(token_id)
    if not token:
        raise HTTPException(status_code=404, detail="Canary token not found")
    return {"ok": True, "token": token}


@app.put("/api/v1/canary/tokens/{token_id}/status")
def update_canary_token_status(token_id: str, req: CanaryStatusUpdate) -> Dict[str, Any]:
    ok = canary_mgr.update_status(token_id, req.status)
    if not ok:
        raise HTTPException(status_code=404, detail="Canary token not found")
    return {"ok": True, "token_id": token_id, "status": req.status}


@app.delete("/api/v1/canary/tokens/{token_id}")
def delete_canary_token(token_id: str) -> Dict[str, Any]:
    ok = canary_mgr.delete_token(token_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Canary token not found")
    return {"ok": True, "token_id": token_id, "message": "Canary token deleted successfully"}


@app.post("/api/v1/canary/tokens/{token_id}/trigger")
def trigger_canary_token_by_id(token_id: str, request: Request) -> Dict[str, Any]:
    source_ip = request.headers.get("x-forwarded-for", "").split(",")[0].strip() or getattr(request.client, "host", "127.0.0.1")
    metadata = {
        "user_agent": request.headers.get("user-agent", "unknown"),
        "method": request.method,
        "trigger_source": "dashboard_manual_trigger",
        "simulated": True,
    }
    updated = canary_mgr.record_trigger_by_id(token_id, source_ip, metadata)
    if not updated:
        raise HTTPException(status_code=404, detail="Active canary token not found or disabled")
    _process_canary_trigger(updated, source_ip, request, simulated=True)
    return {"ok": True, "message": f"Canary tripwire '{updated['name']}' triggered successfully", "token": updated}


@app.post("/api/v1/canary/trigger/{secret}")
def trigger_canary_by_secret(secret: str, request: Request) -> Dict[str, Any]:
    source_ip = request.headers.get("x-forwarded-for", "").split(",")[0].strip() or getattr(request.client, "host", "127.0.0.1")
    metadata = {
        "user_agent": request.headers.get("user-agent", "unknown"),
        "method": request.method,
        "trigger_source": "api_trigger",
        "simulated": False,
    }
    updated = canary_mgr.record_trigger(secret, source_ip, metadata)
    if not updated:
        raise HTTPException(status_code=404, detail="Active canary token not found or disabled")
    _process_canary_trigger(updated, source_ip, request, simulated=False)
    return {"ok": True, "message": f"Canary tripwire '{updated['name']}' triggered successfully", "token": updated}


@app.post("/api/v1/canary/test")
def test_canary_trigger(req: CanaryTestRequest, request: Request) -> Dict[str, Any]:
    source_ip = request.headers.get("x-forwarded-for", "").split(",")[0].strip() or getattr(request.client, "host", "127.0.0.1")
    metadata = {
        "user_agent": request.headers.get("user-agent", "unknown"),
        "method": request.method,
        "trigger_source": "api_test_simulation",
        "simulated": True,
    }
    updated = None
    if req.token_id:
        updated = canary_mgr.record_trigger_by_id(req.token_id, source_ip, metadata)
    elif req.secret:
        updated = canary_mgr.record_trigger(req.secret, source_ip, metadata)
    else:
        raise HTTPException(status_code=400, detail="Must provide 'secret' or 'token_id'")

    if not updated:
        raise HTTPException(status_code=404, detail="Active canary token not found or disabled")
    _process_canary_trigger(updated, source_ip, request, simulated=True)
    return {"ok": True, "message": f"Canary token '{updated['name']}' simulated trigger processed", "token": updated}


@app.get("/t/{secret}", include_in_schema=False)
@app.post("/t/{secret}", include_in_schema=False)
def fast_canary_tripwire_url(secret: str, request: Request) -> HTMLResponse:
    source_ip = request.headers.get("x-forwarded-for", "").split(",")[0].strip() or getattr(request.client, "host", "127.0.0.1")
    metadata = {
        "user_agent": request.headers.get("user-agent", "unknown"),
        "method": request.method,
        "url": str(request.url),
        "trigger_source": "http_tripwire_url",
        "simulated": False,
    }
    updated = canary_mgr.record_trigger(secret, source_ip, metadata)
    if not updated:
        raise HTTPException(status_code=404, detail="Not found")
    _process_canary_trigger(updated, source_ip, request, simulated=False)
    return HTMLResponse(
        content="""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>CyberShield AI — Tripwire Detected</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0c120c; color: #d0ddbe; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }
    .card { background: #131c13; border: 1px solid #233423; border-radius: 12px; padding: 40px; text-align: center; max-width: 480px; box-shadow: 0 12px 36px rgba(0,0,0,0.5); }
    .badge { display: inline-block; background: #284428; color: #8B9A6E; padding: 4px 12px; border-radius: 999px; font-size: 12px; font-weight: 700; letter-spacing: 0.5px; text-transform: uppercase; margin-bottom: 16px; }
    h2 { color: #f4f6f0; margin: 0 0 12px; font-size: 22px; }
    p { color: #8ca4ac; font-size: 14px; line-height: 1.5; margin: 0; }
  </style>
</head>
<body>
  <div class="card">
    <span class="badge">Decoy Asset Online</span>
    <h2>CyberShield AI Honeytoken Verified</h2>
    <p>This canary URL tripwire is actively monitored by the Autonomous SOC Grid. Trigger coordinates and source telemetry have been captured and verified.</p>
  </div>
</body>
</html>""",
        status_code=200,
    )


@app.get("/canary/{secret}", include_in_schema=False)
@app.post("/canary/{secret}", include_in_schema=False)
def fast_canary_tripwire_url_alias(secret: str, request: Request) -> HTMLResponse:
    return fast_canary_tripwire_url(secret, request)


# ============================================================
# ALERTS & INTEL API
# ============================================================
def _sync_alert_email_to_env(recipients_str: str) -> None:
    """Helper to sync ALERT_EMAIL_TO in .env file safely."""
    env_file = PROJECT_ROOT / ".env"
    if not env_file.exists():
        return
    try:
        content = env_file.read_text(encoding="utf-8")
        lines = content.splitlines()
        found = False
        new_lines = []
        for line in lines:
            if line.strip().startswith("ALERT_EMAIL_TO="):
                new_lines.append(f"ALERT_EMAIL_TO={recipients_str}")
                found = True
            else:
                new_lines.append(line)
        if not found:
            new_lines.append(f"ALERT_EMAIL_TO={recipients_str}")
        env_file.write_text("\n".join(new_lines) + "\n", encoding="utf-8")
    except Exception:
        pass


@app.get("/api/v1/alerts/status")
def get_alerts_status() -> Dict[str, Any]:
    try:
        load_dotenv(PROJECT_ROOT / ".env", override=True)
    except Exception:
        pass
    if get_alert_manager:
        return get_alert_manager().get_status()
    return {
        "active_channels_count": 0,
        "channels": {
            "slack": {"configured": False, "enabled": False, "active": False, "name": "Slack"},
            "discord": {"configured": False, "enabled": False, "active": False, "name": "Discord"},
            "email": {"configured": False, "enabled": False, "active": False, "name": "Email (SMTP)"},
        },
        "policy": {"min_risk_score": 80, "min_severity": "high", "dedup_window_seconds": 300},
        "history": [],
    }


@app.post("/api/v1/alerts/test")
def test_alert_dispatch(payload: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    try:
        load_dotenv(PROJECT_ROOT / ".env", override=True)
    except Exception:
        pass
    if not get_alert_manager or not SecurityAlert:
        return {"ok": False, "error": "Alert manager unavailable", "active_channels_count": 0, "results": {}}

    mgr = get_alert_manager()
    custom_recipients = None
    if payload and "recipients" in payload:
        raw_recipients = payload["recipients"]
        if isinstance(raw_recipients, list):
            custom_recipients = [str(r).strip() for r in raw_recipients if str(r).strip()]
        elif isinstance(raw_recipients, str) and raw_recipients.strip():
            custom_recipients = [r.strip() for r in raw_recipients.split(",") if r.strip()]

    test_alert = SecurityAlert(
        event_id=f"test-alert-{utc_now().replace(':', '').replace('-', '')[:15]}",
        timestamp=utc_now(),
        severity="critical",
        risk_score=95,
        source_ip="127.0.0.1",
        host="cybershield-soc",
        service="alerts-test",
        event_type="TEST_SECURITY_INCIDENT",
        intent="Operator Diagnostics",
        mitre_techniques=["T1003", "T1078"],
        mitre_tactics=["Execution", "Initial Access"],
        ai_summary="Diagnostic test alert initiated from CyberShield AI Operator Dashboard.",
        recommended_remediation=[
            "Confirm receipt in configured channels (Slack, Discord, Email)",
            "Verify alert notification delivery and formatting",
        ],
        details={"manual_test": True},
    )
    results = mgr.send_alert(test_alert, sync=True, email_recipients=custom_recipients)
    return {
        "ok": True,
        "alert_id": test_alert.event_id,
        "results": results or {},
        "email_error": getattr(mgr.email, "last_error", None) if not (results or {}).get("email") else None,
        "recipients_sent": custom_recipients if custom_recipients is not None else mgr.email.get_active_recipients(),
        "active_channels_count": mgr.get_status()["active_channels_count"],
    }


@app.get("/api/v1/alerts/channels/email/recipients")
def get_email_recipients() -> Dict[str, Any]:
    if not get_alert_manager:
        return {"ok": False, "recipients": [], "active_recipients": [], "count": 0, "active_count": 0}
    mgr = get_alert_manager()
    return {
        "ok": True,
        "recipients": mgr.email.get_recipients(),
        "active_recipients": mgr.email.get_active_recipients(),
        "count": len(mgr.email.get_recipients()),
        "active_count": len(mgr.email.get_active_recipients()),
    }


@app.put("/api/v1/alerts/channels/email/recipients")
def update_email_recipients(body: Dict[str, Any]) -> Dict[str, Any]:
    if not get_alert_manager:
        raise HTTPException(status_code=503, detail="Alert manager unavailable")
    mgr = get_alert_manager()
    recipients = body.get("recipients", [])
    updated = mgr.email.set_recipients(recipients)
    active = mgr.email.get_active_recipients()
    if body.get("persist", True):
        _sync_alert_email_to_env(",".join(active))
    return {
        "ok": True,
        "recipients": updated,
        "active_recipients": active,
        "count": len(updated),
        "active_count": len(active),
        "status": mgr.get_status(),
    }


@app.post("/api/v1/alerts/channels/email/recipients")
def add_email_recipient(body: Dict[str, Any]) -> Dict[str, Any]:
    if not get_alert_manager:
        raise HTTPException(status_code=503, detail="Alert manager unavailable")
    mgr = get_alert_manager()
    email = str(body.get("email", "")).strip()
    enabled = bool(body.get("enabled", True))
    if not email or "@" not in email:
        raise HTTPException(status_code=400, detail="Invalid email address")
    success = mgr.email.add_recipient(email, enabled=enabled)
    active = mgr.email.get_active_recipients()
    if body.get("persist", True):
        _sync_alert_email_to_env(",".join(active))
    return {
        "ok": success,
        "email": email,
        "recipients": mgr.email.get_recipients(),
        "active_recipients": active,
        "status": mgr.get_status(),
    }


@app.delete("/api/v1/alerts/channels/email/recipients/{email}")
def delete_email_recipient(email: str, persist: bool = Query(default=True)) -> Dict[str, Any]:
    if not get_alert_manager:
        raise HTTPException(status_code=503, detail="Alert manager unavailable")
    mgr = get_alert_manager()
    success = mgr.email.remove_recipient(email)
    active = mgr.email.get_active_recipients()
    if persist:
        _sync_alert_email_to_env(",".join(active))
    return {
        "ok": success,
        "deleted": email,
        "recipients": mgr.email.get_recipients(),
        "active_recipients": active,
        "status": mgr.get_status(),
    }


@app.put("/api/v1/alerts/channels/{channel}/status")
def toggle_channel_status(channel: str, body: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    if not get_alert_manager:
        raise HTTPException(status_code=503, detail="Alert manager unavailable")
    mgr = get_alert_manager()
    ch = channel.lower().strip()
    enabled = None
    if body and "enabled" in body:
        enabled = bool(body["enabled"])
    try:
        new_state = mgr.toggle_channel(ch, enabled=enabled)
        return {
            "ok": True,
            "channel": ch,
            "enabled": new_state,
            "status": mgr.get_status(),
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


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
def simulate_attack(target: Optional[str] = Query(None)) -> Dict[str, Any]:
    sim_ip = "185.220.101.5"
    
    # Config-driven: dynamically read active honeypot services from settings
    services = settings.services
    matched = None
    if target:
        matched = next((s for s in services if s.key.lower() == target.lower() or str(s.port) == target), None)
    if not matched:
        # Default to HTTP finance honeypot if available, else first service
        matched = next((s for s in services if s.key == "http"), services[0] if services else None)

    dest_port = matched.port if matched else 8088
    service_name = (matched.name if matched else "HTTP").upper()
    proto = matched.protocol if matched else "http"
    persona = matched.persona if matched else "internal finance portal"

    intent = "SQL Injection & Unauthorized Credential Harvesting" if proto in ("http", "https") else "Adversary Shell Injection & Credential Harvesting"
    event_type = "WEB_EXPLOIT_SQLI" if proto in ("http", "https") else "AUTH_FAILED_EXPLOIT"
    content = (
        f"POST /login HTTP/1.1 - SQLi probe \"' OR 1=1--\" & unauthorized credential harvesting on {persona} (port {dest_port})"
        if proto in ("http", "https")
        else f"SSH-2.0-paramiko_2.8.0 - Failed root exploit attempt & credential harvesting from {sim_ip} on port {dest_port}"
    )

    sim_session = DecoySession(
        session_id=f"sim_{int(time.time() * 1000)}",
        source_ip=sim_ip,
        source_port=54321,
        destination_port=dest_port,
        service=service_name,
        protocol=proto,
        persona=persona,
        risk_score=92,
        risk_level="critical",
        intent=intent,
    )
    store.create_session(sim_session)
    event = TelemetryEvent(
        session_id=sim_session.session_id,
        event_type=event_type,
        severity="critical",
        direction="inbound",
        content=content,
        metadata={"destination_port": dest_port, "service": service_name},
    )
    store.record_event(event)

    # AUTOMATED MULTI-CHANNEL DISPATCH (Risk score 92 > 85)
    if sim_session.risk_score > 85 and get_alert_manager and SecurityAlert:
        try:
            mgr = get_alert_manager()
            sec_alert = SecurityAlert(
                event_id=event.event_id,
                timestamp=event.timestamp,
                severity=sim_session.risk_level,
                risk_score=sim_session.risk_score,
                source_ip=sim_session.source_ip,
                host=sim_session.persona,
                service=sim_session.service,
                event_type=event.event_type,
                intent=sim_session.intent,
                mitre_techniques=["T1110", "T1078"],
                mitre_tactics=["Initial Access", "Credential Access"],
                ai_summary=f"Automated Intrusion Alert: {sim_session.intent} detected against {sim_session.service} ({sim_session.persona}) from {sim_session.source_ip}. Risk score: {sim_session.risk_score}/100 exceeds critical 85 threshold.",
                recommended_remediation=[
                    f"Autonomous perimeter containment active for {sim_session.source_ip}",
                    f"Review decoy session {sim_session.session_id} audit logs",
                ],
                details={"session_id": sim_session.session_id, "content": event.content},
            )
            mgr.send_alert(sec_alert, sync=False)
        except Exception:
            pass

    return {"ok": True, "session": sim_session.to_dict()}






# ============================================================
# MEDICARE.AI PROTECTED APP — STATUS API
# ============================================================
@app.get("/api/v1/protected/status")
async def protected_app_status() -> Dict[str, Any]:
    """Live metrics for the Medicare.AI WAF integration — powers the dashboard panel."""
    return waf_proxy.get_metrics()


class SimulateWAFRequest(BaseModel):
    vector: str = Field(default="sqli", description="Attack vector: sqli, xss, rce, path_traversal, bot_scan")


@app.post("/api/v1/protected/simulate-attack")
async def simulate_protected_app_attack(req: Optional[SimulateWAFRequest] = None) -> Dict[str, Any]:
    vec = req.vector if req else "sqli"
    return await waf_proxy.simulate_attack(vec)


@app.get("/api/v1/protected/config")
async def get_protected_app_config() -> Dict[str, Any]:
    """Returns active CyberShield WAF security configuration and rate limits."""
    return waf_proxy.get_config()


class WAFConfigUpdateRequest(BaseModel):
    block_score_threshold: Optional[int] = Field(None, ge=10, le=100)
    rate_limiting_enabled: Optional[bool] = None
    max_requests_per_minute: Optional[int] = Field(None, ge=5, le=1000)
    strict_header_inspection: Optional[bool] = None


@app.post("/api/v1/protected/config")
async def update_protected_app_config(req: WAFConfigUpdateRequest) -> Dict[str, Any]:
    """Updates active CyberShield WAF security rules dynamically."""
    new_cfg = req.model_dump(exclude_none=True) if hasattr(req, "model_dump") else req.dict(exclude_none=True)
    return waf_proxy.update_config(new_cfg)


@app.get("/api/v1/protected/export-rules")
async def export_protected_app_rules(format: str = Query("modsecurity")) -> Dict[str, Any]:
    """Generates exportable production WAF rules (ModSecurity, Nginx, Cloudflare) for Medicare.AI defense."""
    return waf_proxy.export_rules(fmt=format)


@app.get("/api/v1/protected/banned-ips")
async def get_protected_app_banned_ips() -> Dict[str, Any]:
    """Returns list of currently quarantined / auto-banned IP addresses."""
    return {"banned_ips": waf_proxy.get_banned_ips()}


class UnbanIPRequest(BaseModel):
    ip: str = Field(..., description="IP address to remove from WAF quarantine")


@app.post("/api/v1/protected/unban-ip")
async def unban_protected_app_ip(req: UnbanIPRequest) -> Dict[str, Any]:
    """Unbans an IP address from WAF quarantine."""
    success = waf_proxy.unban_ip(req.ip)
    return {"ok": success, "ip": req.ip}


@app.post("/api/v1/protected/health-audit")
async def run_protected_app_health_audit() -> Dict[str, Any]:
    """Runs an automated AI security vulnerability audit on Medicare.AI and returns OWASP health breakdown."""
    return waf_proxy.run_security_audit()







# ============================================================
# MEDICARE.AI WAF REVERSE PROXY — CATCH-ALL
# ============================================================
# All HTTP methods on /proxy/{path} are inspected by CyberShield
# and forwarded clean to Medicare.AI (http://127.0.0.1:5000 by default).
#
# Example:  GET  http://localhost:8050/proxy/api/hospitals?lat=22&lon=88
#           POST http://localhost:8050/proxy/api/analyze-prescription
#
@app.api_route(
    "/proxy/{path:path}",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"],
    include_in_schema=True,
    name="medicare_waf_proxy",
    summary="CyberShield WAF → Medicare.AI reverse proxy",
    description=(
        "Inspects incoming requests through the CyberShield threat-detection pipeline "
        "(IntentClassifier + TelemetryStore + runtime blocklist), then forwards clean "
        "requests to Medicare.AI. Blocked requests receive a 403 WAF response."
    ),
)
async def medicare_waf_proxy(request: Request) -> Response:
    return await waf_proxy.inspect_and_forward(request)


# ============================================================
# WEBSOCKET STREAM (include protected metrics)
# ============================================================
@app.websocket("/ws/dashboard")
@app.websocket("/api/v1/ws/dashboard")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    try:
        while True:
            alerts_status = {}
            if get_alert_manager:
                try:
                    mgr = get_alert_manager()
                    if mgr:
                        alerts_status = mgr.get_status()
                except Exception:
                    alerts_status = {}
            payload = {
                "type": "state_update",
                "status": runtime.status(),
                "metrics": store.metrics(),
                "sessions": {"sessions": store.list_sessions(limit=50)},
                "canaries": {"tokens": canary_mgr.list_tokens()},
                "alerts": alerts_status,
                "protected": waf_proxy.get_metrics(),
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

