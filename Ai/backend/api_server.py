#!/usr/bin/env python3
"""FastAPI backend for ARGUS SOC analysis and the deception grid."""

from __future__ import annotations

import asyncio
import os
import sys
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from pydantic import BaseModel, Field


ROOT = Path(__file__).resolve().parent
AI_ROOT = ROOT.parent
if str(AI_ROOT) not in sys.path:
    sys.path.insert(0, str(AI_ROOT))

PROJECT_ROOT = AI_ROOT.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from honeypot import HoneypotRuntime, HoneypotSettings, TelemetryStore  # noqa: E402
from honeypot.models import utc_now  # noqa: E402


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
        "host": session.get("persona", "argus-decoy"),
        "source": "argus_honeypot",
        "event_type": "HONEYPOT_SESSION_REVIEW",
        "severity": session.get("risk_level", "info"),
        "actor": {
            "source_ip": session.get("source_ip"),
            "source_port": session.get("source_port"),
            "user": session.get("username"),
        },
        "target": {
            "host": "argus-decoy",
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
        f"ARGUS observed {session.get('intent', 'reconnaissance').lower()} activity "
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

    app = FastAPI(title="ARGUS API", version="1.0.0", lifespan=lifespan)
    app.state.use_rag = use_rag
    app.state.use_llm = use_llm
    app.state.orchestrator = None
    app.state.rag_pipeline = None
    app.state.honeypot_store = store
    app.state.honeypot_runtime = runtime

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
            "service": "argus-api",
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

    @app.get("/dashboard", include_in_schema=False)
    def dashboard() -> FileResponse:
        return FileResponse(DASHBOARD_ROOT / "index.html", media_type="text/html")

    @app.get("/dashboard/styles.css", include_in_schema=False)
    def dashboard_styles() -> FileResponse:
        return FileResponse(DASHBOARD_ROOT / "styles.css", media_type="text/css")

    @app.get("/dashboard/app.js", include_in_schema=False)
    def dashboard_script() -> FileResponse:
        return FileResponse(
            DASHBOARD_ROOT / "app.js", media_type="application/javascript"
        )

    @app.post("/api/v1/logs")
    def ingest_log(request: LogEventRequest) -> Dict[str, Any]:
        try:
            result = get_orchestrator().investigate(
                request.event,
                brute_force_detected=request.brute_force_detected,
            )
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
        return {"count": len(sessions), "sessions": sessions}

    @app.get("/api/v1/honeypot/sessions/{session_id}")
    def honeypot_session(session_id: str) -> Dict[str, Any]:
        session = store.get_session(session_id)
        if session is None:
            raise HTTPException(status_code=404, detail="Session not found")
        return {
            "session": session,
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
            "scope": "ARGUS runtime blocklist",
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
                "Content-Disposition": f'attachment; filename="argus-{session_id}.json"'
            },
        )

    return app


app = create_app(
    use_rag=_env_flag("API_USE_RAG", True),
    use_llm=_env_flag("API_USE_LLM", True),
)
