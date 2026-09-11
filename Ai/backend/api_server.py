"""FastAPI backend for CyberShield AI SOC analysis and the deception grid."""

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


ROOT = Path(__file__).resolve().parent
AI_ROOT = ROOT.parent
if str(AI_ROOT) not in sys.path:
    sys.path.insert(0, str(AI_ROOT))

PROJECT_ROOT = AI_ROOT.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

try:
    from dotenv import load_dotenv
    load_dotenv(PROJECT_ROOT / ".env", override=True)
except Exception:
    pass

from honeypot import HoneypotRuntime, HoneypotSettings, TelemetryStore  # noqa: E402
from honeypot.models import utc_now  # noqa: E402
from canary import CanaryManager # noqa: E402
from agents.alerter import get_alert_manager, SecurityAlert  # noqa: E402
from intel.geo_tracker import get_geo_tracker, KNOWN_THREAT_ACTORS  # noqa: E402



DASHBOARD_ROOT = PROJECT_ROOT / "dashboard"


class LogEventRequest(BaseModel):
    event: Dict[str, Any]
    brute_force_detected: bool = False


class BatchLogEventRequest(BaseModel):
    events: List[Dict[str, Any]] = Field(default_factory=list)
    brute_force_detected: bool = False


class RagQueryRequest(BaseModel):
    query: str
    session_id: str = "api"
    top_k: int = Field(default=5, ge=1, le=10)


class BlockSourceRequest(BaseModel):
    source_ip: str = Field(min_length=1, max_length=128)


class CanaryTokenCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    token_type: str = Field(pattern="^(url|credential|document)$")
    metadata: Optional[Dict[str, Any]] = None


class CanaryTokenStatusRequest(BaseModel):
    status: str = Field(pattern="^(active|disabled)$")


class CanaryTestRequest(BaseModel):
    secret: str = Field(min_length=1)


def _string_list(value: Any, fallback: Optional[List[str]] = None) -> List[str]:
    if isinstance(value, list):
        return [str(item)[:1000] for item in value if str(item).strip()][:20]
    if isinstance(value, str) and value.strip():
        return [value[:1000]]
    return list(fallback or [])


def _build_session_analysis_event(
    session: Dict[str, Any], events: List[Dict[str, Any]]
) -> Dict[str, Any]:
    inbound = [event for event in events if event.get("direction") == "inbound"]
    transcript = "\n".join(
        f"{event.get('timestamp', '?')} {event.get('event_type', 'ACTIVITY')}: "
        f"{event.get('content', '')}" for event in inbound[-50:]
    )[:8000]
    return {
        "event_id": f"session-report-{session['session_id']}",
        "timestamp": utc_now(),
        "host": session.get("persona", "cybershield-decoy"),
        "source": "cybershield_honeypot",
        "event_type": "HONEYPOT_SESSION_REVIEW",
        "severity": session.get("risk_level", "info"),
        "actor": {
            "source_ip": session.get("source_ip"),
            "source_port": session.get("source_port"),
            "user": session.get("username"),
        },
        "target": {
            "host": "cybershield-decoy",
            "service": session.get("service"),
            "port": session.get("destination_port"),
        },
        "details": {
            "session_id": session.get("session_id"),
            "attacker_actions": session.get("interactions", 0),
            "client_fingerprint": session.get("client_fingerprint"),
            "intent": session.get("intent"),
            "sandboxed": True,
            "executed": False,
        },
        "raw": transcript or "Connection established; no inbound payload captured.",
    }


def _format_analyst_report(
    session: Dict[str, Any], pipeline_result: Dict[str, Any], pipeline: Any
) -> Dict[str, Any]:
    deterministic = (session.get("analysis") or {}).get("investigation") or {}
    analysis = pipeline_result.get("analysis") or {}
    if not isinstance(analysis, dict):
        analysis = {}
    chunks = pipeline_result.get("rag_chunks") or []
    sources = []
    for index, chunk in enumerate(chunks[:5], 1):
        metadata = chunk.get("metadata") or {}
        label = (
            metadata.get("technique_id")
            or metadata.get("rule_id")
            or metadata.get("file")
            or f"reference-{index}"
        )
        score = next(
            (
                chunk.get(key)
                for key in ("rerank_score", "hybrid_score", "vector_score", "bm25_score")
                if chunk.get(key) is not None
            ),
            None,
        )
        sources.append(
            {
                "label": str(label)[:160],
                "source": str(metadata.get("source", "knowledge-base"))[:160],
                "snippet": str(chunk.get("text", "")).strip().replace("\n", " ")[:420],
                "score": round(float(score), 3) if score is not None else None,
            }
        )

    risk = deterministic.get("risk") or {}
    mitre = _string_list(
        analysis.get("mitre_techniques"),
        _string_list(
            pipeline_result.get("rag_mitre_techniques"),
            (session.get("analysis") or {}).get("mitre") or [],
        ),
    )
    default_findings = [
        f"Observed {session.get('interactions', 0)} attacker action(s) against "
        f"the {session.get('service', 'unknown')} decoy.",
        f"Deterministic SOC intent: {session.get('intent', 'Reconnaissance')} "
        f"with risk {session.get('risk_score', 0)}/100.",
    ]
    remediation = analysis.get("remediation") or {}
    if not isinstance(remediation, dict):
        remediation = {"immediate": _string_list(remediation)}
    normalized_remediation = {
        "immediate": _string_list(
            remediation.get("immediate"),
            ["Preserve and export this decoy session for investigation."],
        ),
        "short_term": _string_list(
            remediation.get("short_term"),
            ["Correlate the source with firewall, identity, endpoint, and DNS telemetry."],
        ),
        "long_term": _string_list(remediation.get("long_term")),
    }
    error = analysis.get("error") or getattr(getattr(pipeline, "llm", None), "last_error", None)
    summary = str(analysis.get("summary") or risk.get("rationale") or (
        f"CyberShield AI observed {session.get('intent', 'reconnaissance').lower()} activity "
        f"from {session.get('source_ip', 'an unknown source')} against the "
        f"{session.get('service', 'decoy')} service."
    ))[:3000]
    llm = getattr(pipeline, "llm", None)
    return {
        "session_id": session["session_id"],
        "generated_at": utc_now(),
        "status": "complete" if analysis.get("summary") and not error else "evidence-only",
        "summary": summary,
        "severity": str(analysis.get("severity") or session.get("risk_level", "info")),
        "findings": _string_list(analysis.get("findings"), default_findings),
        "mitre_techniques": mitre,
        "remediation": normalized_remediation,
        "sources": sources,
        "query": str(pipeline_result.get("query", ""))[:8000],
        "evidence": {
            "attacker_actions": int(session.get("interactions", 0)),
            "source_ip": session.get("source_ip"),
            "service": session.get("service"),
        },
        "rag": {"enabled": getattr(pipeline, "retriever", None) is not None, "references": len(sources)},
        "llm": {
            "enabled": llm is not None,
            "model": getattr(llm, "model_name", None),
            "error": str(error)[:500] if error else None,
        },
        "safety": {"sandboxed": True, "attacker_input_executed": False},
    }


def _env_flag(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def create_app(
    use_rag: bool = True,
    use_llm: bool = True,
    *,
    honeypot_store: Optional[TelemetryStore] = None,
    honeypot_runtime: Optional[HoneypotRuntime] = None,
    honeypot_autostart: Optional[bool] = None,
) -> FastAPI:
    settings = HoneypotSettings.from_env()
    store = honeypot_store or (
        honeypot_runtime.store
        if honeypot_runtime is not None
        else TelemetryStore(settings.database_path)
    )
    runtime = honeypot_runtime or HoneypotRuntime(settings=settings, store=store)
    should_autostart = settings.autostart if honeypot_autostart is None else honeypot_autostart

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        if should_autostart:
            await runtime.start()
        yield
        await runtime.stop()

    app = FastAPI(title="CyberShield AI API", version="1.0.0", lifespan=lifespan)
    app.state.use_rag = use_rag
    app.state.use_llm = use_llm
    app.state.orchestrator = None
    app.state.rag_pipeline = None
    app.state.honeypot_store = store
    app.state.honeypot_runtime = runtime

    canary_manager = CanaryManager(store)
    app.state.canary_manager = canary_manager

    class DashboardConnectionManager:
        def __init__(self):
            self.active_connections: List[WebSocket] = []
            self.running = False
            self.task: Optional[asyncio.Task] = None

        async def connect(self, websocket: WebSocket):
            await websocket.accept()
            self.active_connections.append(websocket)
            if not self.running:
                self.running = True
                self.task = asyncio.create_task(self.broadcast_loop())

        def disconnect(self, websocket: WebSocket):
            if websocket in self.active_connections:
                self.active_connections.remove(websocket)
            if not self.active_connections:
                self.running = False
                if self.task:
                    self.task.cancel()
                    self.task = None

        async def broadcast_loop(self):
            while self.running:
                if not self.active_connections:
                    break
                try:
                    geo_tracker = get_geo_tracker()
                    raw_sessions = store.list_sessions(limit=100)
                    canary_tokens = canary_manager.list_tokens()
                    attackers = geo_tracker.get_tracked_attackers(raw_sessions, canary_tokens)
                    enriched_sessions = [geo_tracker.enrich_session(s) for s in raw_sessions]
                    payload = {
                        "type": "state_update",
                        "status": runtime.status(),
                        "metrics": store.metrics(),
                        "sessions": {"sessions": enriched_sessions},
                        "canaries": {"tokens": canary_tokens},
                        "alerts": get_alert_manager().get_status(),
                        "attackers": attackers,
                    }
                    disconnected = []
                    for connection in self.active_connections:
                        try:
                            await connection.send_json(payload)
                        except Exception:
                            disconnected.append(connection)
                    for d in disconnected:
                        self.disconnect(d)
                except asyncio.CancelledError:
                    break
                except Exception as e:
                    print(f"[ws] broadcast error: {e}")
                await asyncio.sleep(1)

    ws_manager = DashboardConnectionManager()

    def get_orchestrator() -> Any:
        if app.state.orchestrator is None:
            from orchestrator import Orchestrator

            app.state.orchestrator = Orchestrator(use_rag=use_rag, use_llm=use_llm)
        return app.state.orchestrator

    def get_rag_pipeline() -> Any:
        if app.state.rag_pipeline is None:
            from rag.core.pipeline import RAGPipeline

            app.state.rag_pipeline = RAGPipeline(enable_retrieval=use_rag, enable_llm=use_llm)
        return app.state.rag_pipeline

    @app.get("/health")
    def health() -> Dict[str, Any]:
        rag_pipeline = app.state.rag_pipeline
        return {
            "status": "ok",
            "service": "cybershield-api",
            "configured": {
                "use_rag": app.state.use_rag,
                "use_llm": app.state.use_llm,
            },
            "initialized": {
                "orchestrator": app.state.orchestrator is not None,
                "rag_pipeline": rag_pipeline is not None,
            },
            "rag_enabled": rag_pipeline.retriever is not None if rag_pipeline else False,
            "llm_enabled": rag_pipeline.llm is not None if rag_pipeline else False,
            "memory_backend": rag_pipeline.memory.backend if rag_pipeline else "uninitialized",
            "honeypot": runtime.status(),
        }

    @app.get("/", include_in_schema=False)
    def root_redirect() -> RedirectResponse:
        return RedirectResponse(url="/dashboard")

    NO_CACHE_HEADERS = {
        "Cache-Control": "no-cache, no-store, must-revalidate",
        "Pragma": "no-cache",
        "Expires": "0",
    }

    @app.get("/dashboard", include_in_schema=False)
    def dashboard() -> FileResponse:
        return FileResponse(DASHBOARD_ROOT / "index.html", media_type="text/html", headers=NO_CACHE_HEADERS)

    @app.get("/dashboard/styles.css", include_in_schema=False)
    def dashboard_styles() -> FileResponse:
        return FileResponse(DASHBOARD_ROOT / "styles.css", media_type="text/css", headers=NO_CACHE_HEADERS)

    @app.get("/dashboard/app.js", include_in_schema=False)
    def dashboard_script() -> FileResponse:
        return FileResponse(
            DASHBOARD_ROOT / "app.js", media_type="application/javascript", headers=NO_CACHE_HEADERS
        )

    @app.post("/api/v1/logs")
    def ingest_log(request: LogEventRequest) -> Dict[str, Any]:
        try:
            result = get_orchestrator().investigate(
                request.event,
                brute_force_detected=request.brute_force_detected,
            )
            
            # Map external Event into Honeypot models for dashboard UI
            from honeypot.models import DecoySession, TelemetryEvent
            session_id = f"ext_{request.event['actor'].get('source_ip', 'unknown').replace('.', '_')}"
            
            if not store.get_session(session_id):
                session = DecoySession(
                    session_id=session_id,
                    source_ip=request.event["actor"].get("source_ip", "0.0.0.0"),
                    source_port=0,
                    destination_port=0,
                    service=request.event["target"].get("service", "endpoint"),
                    protocol=request.event.get("source", "log"),
                    persona=request.event["target"].get("host", "unknown"),
                    risk_level=result.risk.level,
                    risk_score=result.risk.score,
                    intent="Endpoint Activity",
                )
                store.create_session(session)
            
            tel_event = TelemetryEvent(
                session_id=session_id,
                event_type=request.event.get("event_type", "LOG"),
                severity=result.risk.level,
                direction="inbound",
                content=request.event.get("raw", ""),
                metadata={"external_event": True, "details": request.event.get("details", {})}
            )
            store.record_event(tel_event)

            return result.to_dict()
        except Exception as exc:
            raise HTTPException(status_code=500, detail=str(exc)) from exc

    @app.post("/api/v1/logs/batch")
    def ingest_logs(request: BatchLogEventRequest) -> Dict[str, Any]:
        results = []
        errors = []
        orchestrator = get_orchestrator()
        for index, event in enumerate(request.events):
            try:
                result = orchestrator.investigate(
                    event,
                    brute_force_detected=request.brute_force_detected,
                )
                results.append(result.to_dict())
            except Exception as exc:
                errors.append(
                    {"index": index, "error": str(exc), "event_id": event.get("event_id")}
                )
        return {
            "processed": len(results),
            "failed": len(errors),
            "results": results,
            "errors": errors,
        }

    @app.post("/api/v1/rag/query")
    def rag_query(request: RagQueryRequest) -> Dict[str, Any]:
        try:
            return get_rag_pipeline().answer_query(
                query=request.query,
                session_id=request.session_id,
                top_k=request.top_k,
            )
        except Exception as exc:
            raise HTTPException(status_code=500, detail=str(exc)) from exc

    @app.get("/api/v1/honeypot/status")
    def honeypot_status() -> Dict[str, Any]:
        return runtime.status()

    @app.post("/api/v1/honeypot/control/start")
    async def honeypot_start() -> Dict[str, Any]:
        return await runtime.start()

    @app.post("/api/v1/honeypot/control/stop")
    async def honeypot_stop() -> Dict[str, Any]:
        return await runtime.stop()

    @app.get("/api/v1/honeypot/metrics")
    def honeypot_metrics() -> Dict[str, Any]:
        return store.metrics()

    @app.get("/api/v1/honeypot/sessions")
    def honeypot_sessions(
        limit: int = Query(default=100, ge=1, le=500),
        status: Optional[str] = Query(default=None, max_length=32),
    ) -> Dict[str, Any]:
        sessions = store.list_sessions(limit=limit, status=status)
        geo_tracker = get_geo_tracker()
        enriched = [geo_tracker.enrich_session(s) for s in sessions]
        return {"count": len(enriched), "sessions": enriched}

    @app.websocket("/api/v1/ws/dashboard")
    async def websocket_dashboard(websocket: WebSocket):
        await ws_manager.connect(websocket)
        try:
            while True:
                # Keep connection alive and wait for client messages if any
                await websocket.receive_text()
        except WebSocketDisconnect:
            ws_manager.disconnect(websocket)
        except Exception:
            ws_manager.disconnect(websocket)

    @app.get("/api/v1/honeypot/sessions/{session_id}")
    def honeypot_session(session_id: str) -> Dict[str, Any]:
        session = store.get_session(session_id)
        if session is None:
            raise HTTPException(status_code=404, detail="Session not found")
        geo_tracker = get_geo_tracker()
        enriched = geo_tracker.enrich_session(session)
        return {
            "session": enriched,
            "events": list(
                reversed(store.list_events(session_id=session_id, limit=500))
            ),
        }

    @app.post("/api/v1/honeypot/sessions/{session_id}/analyze")
    async def analyze_honeypot_session(session_id: str) -> Dict[str, Any]:
        """Generate and persist an on-demand Gemini + RAG session report."""

        session = store.get_session(session_id)
        if session is None:
            raise HTTPException(status_code=404, detail="Session not found")
        events = list(reversed(store.list_events(session_id=session_id, limit=500)))
        deterministic = (session.get("analysis") or {}).get("investigation") or {}
        try:
            pipeline = get_rag_pipeline()
            pipeline_result = await asyncio.to_thread(
                pipeline.analyze,
                _build_session_analysis_event(session, events),
                deterministic.get("threat_intel") or {},
                deterministic.get("correlation") or {},
                deterministic.get("mitre") or {},
                deterministic.get("risk") or {},
            )
            report = _format_analyst_report(session, pipeline_result, pipeline)
            store.save_analyst_report(session_id, report)
            return {"report": report}
        except Exception as exc:
            raise HTTPException(status_code=500, detail=str(exc)) from exc

    @app.post("/api/v1/honeypot/sessions/{session_id}/contain")
    async def contain_honeypot_session(session_id: str) -> Dict[str, Any]:
        if not await runtime.contain(session_id):
            raise HTTPException(status_code=404, detail="Session not found")
        return {"ok": True, "session_id": session_id, "status": "contained"}

    @app.post("/api/v1/honeypot/block-source")
    async def block_honeypot_source(request: BlockSourceRequest) -> Dict[str, Any]:
        contained = await runtime.block_source(request.source_ip)
        return {
            "ok": True,
            "source_ip": request.source_ip,
            "contained_sessions": contained,
            "scope": "CyberShield AI runtime blocklist",
        }

    @app.get("/api/v1/honeypot/events")
    def honeypot_events(
        session_id: Optional[str] = Query(default=None, max_length=80),
        limit: int = Query(default=200, ge=1, le=2000),
    ) -> Dict[str, Any]:
        events = store.list_events(session_id=session_id, limit=limit)
        return {"count": len(events), "events": events}

    @app.get("/api/v1/honeypot/sessions/{session_id}/export")
    def export_honeypot_session(session_id: str) -> JSONResponse:
        evidence = store.export_session(session_id)
        if evidence is None:
            raise HTTPException(status_code=404, detail="Session not found")
        return JSONResponse(
            content=evidence,
            headers={
                "Content-Disposition": f'attachment; filename="cybershield-{session_id}.json"'
            },
        )

    @app.post("/api/v1/canary/tokens")
    def create_canary_token(request: CanaryTokenCreateRequest) -> Dict[str, Any]:
        token = canary_manager.create_token(request.name, request.token_type, request.metadata)
        return {"ok": True, "token": token}

    @app.get("/api/v1/canary/tokens")
    def list_canary_tokens() -> Dict[str, Any]:
        tokens = canary_manager.list_tokens()
        return {"count": len(tokens), "tokens": tokens}

    @app.get("/api/v1/canary/tokens/{token_id}")
    def get_canary_token(token_id: str) -> Dict[str, Any]:
        token = canary_manager.get_token_by_id(token_id)
        if not token:
            raise HTTPException(status_code=404, detail="Token not found")
        return {"token": token}

    @app.put("/api/v1/canary/tokens/{token_id}/status")
    def update_canary_token_status(token_id: str, request: CanaryTokenStatusRequest) -> Dict[str, Any]:
        if not canary_manager.update_status(token_id, request.status):
            raise HTTPException(status_code=404, detail="Token not found")
        return {"ok": True, "status": request.status}

    def _trigger_canary(secret: str, request: Request, simulated: bool = False) -> Dict[str, Any]:
        source_ip = getattr(request.client, "host", "127.0.0.1")
        headers = dict(request.headers)
        metadata = {
            "user_agent": headers.get("user-agent", "unknown"),
            "method": request.method,
            "url": str(request.url),
            "simulated": simulated,
            "headers": {k: v[:200] for k, v in headers.items() if k.lower() not in {"authorization", "cookie"}},
        }
        updated = canary_manager.record_trigger(secret, source_ip, metadata)
        if not updated:
            # Return 404 to obscure invalid/disabled tokens
            raise HTTPException(status_code=404, detail="Not found")

        # SOC Integration
        event = {
            "event_id": f"canary-trig-{utc_now().replace(':', '')}-{secret[:8]}",
            "timestamp": utc_now(),
            "host": "cybershield-api",
            "source": "canary_service",
            "event_type": "CANARY_TOKEN_TRIGGERED",
            "severity": "critical",
            "actor": {
                "source_ip": source_ip,
                "user": None,
            },
            "target": {
                "host": "cybershield-api",
                "service": "canary",
                "port": request.url.port or 80,
            },
            "details": {
                "token_id": updated["token_id"],
                "token_name": updated["name"],
                "token_type": updated["token_type"],
                "simulated": simulated,
            },
            "raw": f"Canary token '{updated['name']}' (type: {updated['token_type']}) triggered from {source_ip}",
        }
        try:
            get_orchestrator().investigate(event, brute_force_detected=False)
        except Exception as exc:
            print(f"[canary] SOC pipeline failed: {exc}")

        return {"ok": True, "message": "Trigger processed"}

    @app.get("/t/{secret}", include_in_schema=False)
    @app.post("/t/{secret}", include_in_schema=False)
    def fast_canary_trigger(secret: str, request: Request) -> JSONResponse:
        try:
            _trigger_canary(secret, request, simulated=False)
        except HTTPException:
            return JSONResponse(status_code=404, content={"detail": "Not found"})
        # Always return 200 OK so scanners don't see 404 if token is active
        return JSONResponse(status_code=200, content={"status": "ok"})

    @app.post("/api/v1/canary/trigger/{secret}")
    def api_canary_trigger(secret: str, request: Request) -> Dict[str, Any]:
        return _trigger_canary(secret, request, simulated=False)

    @app.post("/api/v1/canary/test")
    def test_canary_trigger(test_request: CanaryTestRequest, request: Request) -> Dict[str, Any]:
        """A test endpoint to simulate a trigger safely, useful for credential/document tokens."""
        return _trigger_canary(test_request.secret, request, simulated=True)

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
        except Exception as err:
            logger.warning("[api] Could not sync .env ALERT_EMAIL_TO: %s", err)

    @app.get("/api/v1/alerts/status")
    def get_alerts_status() -> Dict[str, Any]:
        try:
            from dotenv import load_dotenv
            load_dotenv(PROJECT_ROOT / ".env", override=True)
        except Exception:
            pass
        return get_alert_manager().get_status()

    @app.post("/api/v1/alerts/test")
    def test_alert_dispatch(payload: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        try:
            from dotenv import load_dotenv
            load_dotenv(PROJECT_ROOT / ".env", override=True)
        except Exception:
            pass
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
            "recipients_sent": custom_recipients if custom_recipients is not None else mgr.email.get_active_recipients(),
            "active_channels_count": mgr.get_status()["active_channels_count"],
        }

    @app.get("/api/v1/alerts/channels/email/recipients")
    def get_email_recipients() -> Dict[str, Any]:
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

    # --- Geolocation & Threat IP Tracking Endpoints ---

    @app.get("/api/v1/intel/attackers")
    def get_intel_attackers() -> Dict[str, Any]:
        geo_tracker = get_geo_tracker()
        sessions = store.list_sessions(limit=500)
        canaries = canary_manager.list_tokens()
        attackers = geo_tracker.get_tracked_attackers(sessions, canaries)
        return {"count": len(attackers), "attackers": attackers}

    @app.get("/api/v1/intel/ip/{ip}")
    def get_intel_ip(ip: str) -> Dict[str, Any]:
        geo_tracker = get_geo_tracker()
        intel = geo_tracker.lookup(ip)
        all_sessions = store.list_sessions(limit=500)
        ip_sessions = [
            s for s in all_sessions 
            if (s.get("source_ip") or s.get("source_address")) == ip
        ]
        canaries = [
            c for c in canary_manager.list_tokens() 
            if c.get("last_source_ip") == ip
        ]
        return {
            "ok": True,
            "ip": ip,
            "geo": intel.to_dict(),
            "session_count": len(ip_sessions),
            "sessions": [geo_tracker.enrich_session(s) for s in ip_sessions[:20]],
            "canary_triggers": canaries,
        }

    class SimulateAttackRequest(BaseModel):
        country_code: Optional[str] = None
        target_port: Optional[int] = None
        service: Optional[str] = None

    @app.post("/api/v1/intel/simulate-attack")
    async def simulate_attack(req: Optional[SimulateAttackRequest] = None) -> Dict[str, Any]:
        import random
        from honeypot.models import DecoySession, TelemetryEvent, new_id

        candidates = list(KNOWN_THREAT_ACTORS.items())
        if req and req.country_code:
            filtered = [
                c for c in candidates 
                if c[1].get("country_code", "").upper() == req.country_code.upper()
            ]
            if filtered:
                candidates = filtered

        attacker_ip, info = random.choice(candidates)
        ports = [
            (2222, "SSH", "ssh", "finance-backup"),
            (8088, "HTTP", "http", "portal-nginx"),
            (33060, "MySQL", "mysql", "mariadb-core"),
            (2323, "Telnet", "telnet", "cisco-router"),
        ]
        port_choice = random.choice(ports)
        dest_port = req.target_port if (req and req.target_port) else port_choice[0]
        service_name = req.service if (req and req.service) else port_choice[1]
        proto = port_choice[2]
        persona = port_choice[3]

        ses_id = new_id("sim")
        session = DecoySession(
            session_id=ses_id,
            source_ip=attacker_ip,
            source_port=random.randint(40000, 65000),
            destination_port=dest_port,
            service=service_name,
            protocol=proto,
            persona=persona,
            risk_score=info.get("threat_score", 75),
            risk_level="high" if info.get("threat_score", 75) >= 70 else "medium",
            intent=info.get("threat_type", "Reconnaissance"),
            interactions=random.randint(3, 15),
        )
        store.create_session(session)

        event = TelemetryEvent(
            session_id=ses_id,
            event_type="HONEYPOT_SESSION_STARTED",
            severity=session.risk_level,
            direction="system",
            content=f"External adversary connection from {info.get('city')}, {info.get('country')} ({info.get('asn')})",
            metadata={"source_ip": attacker_ip, "geo": info},
        )
        store.record_event(event)

        geo_tracker = get_geo_tracker()
        enriched = geo_tracker.enrich_session(session.to_dict())
        return {"ok": True, "session": enriched, "actor": info}

    return app


app = create_app(
    use_rag=_env_flag("API_USE_RAG", True),
    use_llm=_env_flag("API_USE_LLM", True),
)
