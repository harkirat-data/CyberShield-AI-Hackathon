"""
orchestrator.py - Coordinates all AI sub-agents for incident investigation

This is what the API calls. One function: investigate(event_dict).

Returns a full Investigation object with all sub-agent results.
"""
import time
from typing import Dict, Optional

from schema import Event, ThreatIntel, CorrelationResult, MitreMapping, RiskScore, Investigation
from agents import (
    threat_intel_check,
    correlate,
    add_correlation_event,
    map_mitre,
    merge_mitre_with_rag,
    score_risk,
)
from rag.core.pipeline import RAGPipeline


class Orchestrator:
    def __init__(self, use_rag: bool = True, use_llm: bool = True):
        self.use_rag = use_rag
        self.use_llm = use_llm
        self.pipeline = RAGPipeline() if (use_rag or use_llm) else None
        print(f"[orchestrator] ready (rag={use_rag}, llm={use_llm})")

    def investigate(
        self,
        event_dict: Dict,
        brute_force_detected: bool = False,
    ) -> Investigation:
        """
        Run full investigation on a single event.

        Steps:
        1. Normalize event
        2. Threat intel check
        3. Correlation (find related events)
        4. MITRE mapping (rules + RAG augmentation)
        5. Risk scoring (deterministic)
        6. LLM analysis (with RAG context)
        7. Final severity decision
        """
        start = time.time()
        event = Event.from_dict(event_dict)

        # Add to correlation store so future events can find this one
        add_correlation_event(event)

        # 1. Threat intel
        print(f"[orchestrator] investigating {event.event_id} ({event.event_type})")
        threat = threat_intel_check(event)

        # 2. Correlation
        corr = correlate(event)

        # 3. MITRE mapping (rules first)
        mitre = map_mitre(event)

        # 4. Risk scoring (deterministic, fast)
        risk = score_risk(
            event,
            correlation_count=len(corr.related_events),
            threat_intel_malicious=threat.is_malicious,
            brute_force_detected=brute_force_detected,
        )

        # 5. RAG + LLM (if enabled)
        rag_chunks = []
        llm_analysis = None
        rag_mitre_techs = []

        if self.pipeline and (self.use_rag or self.use_llm):
            try:
                result = self.pipeline.analyze(
                    event,
                    threat_intel_dict=threat.to_dict(),
                    correlation_dict=corr.to_dict(),
                    mitre_dict=mitre.to_dict(),
                    risk_dict=risk.to_dict(),
                )
                rag_chunks = result.get("rag_chunks", [])
                llm_analysis = result.get("analysis")
                rag_mitre_techs = result.get("rag_mitre_techniques", [])

                # Merge RAG-discovered techniques into MITRE mapping
                mitre = merge_mitre_with_rag(mitre, rag_mitre_techs)
            except Exception as e:
                print(f"[orchestrator] pipeline failed: {e}")
                llm_analysis = {"error": str(e), "fallback": True}

        # 6. Final severity decision
        # If LLM gave a different severity, blend with rules-based risk
        final_severity = risk.level
        if llm_analysis and isinstance(llm_analysis, dict):
            llm_sev = llm_analysis.get("severity", "").lower()
            if llm_sev in ("critical", "high", "medium", "low"):
                # Take the higher of risk engine and LLM
                levels = ["info", "low", "medium", "high", "critical"]
                risk_idx = levels.index(risk.level) if risk.level in levels else 0
                llm_idx = levels.index(llm_sev) if llm_sev in levels else 0
                final_severity = levels[max(risk_idx, llm_idx)]

        # 7. Final remediation: prefer LLM's if available, else use MITRE-based defaults
        final_remediation = self._build_default_remediation(event, mitre, threat) if not llm_analysis else \
                           llm_analysis.get("remediation", self._build_default_remediation(event, mitre, threat))

        latency = int((time.time() - start) * 1000)

        inv = Investigation(
            event=event,
            threat_intel=threat,
            correlation=corr,
            mitre=mitre,
            risk=risk,
            rag_chunks=rag_chunks,
            llm_analysis=llm_analysis,
            final_severity=final_severity,
            final_remediation=final_remediation,
            latency_ms=latency,
            model_version="gemini-1.5-flash" if self.use_llm else "rules-only",
        )

        print(f"[orchestrator] complete: severity={inv.final_severity}, latency={latency}ms")
        return inv

    @staticmethod
    def _build_default_remediation(event: Event, mitre: MitreMapping, threat: ThreatIntel) -> Dict:
        """Fallback remediation when LLM is unavailable."""
        immediate = []
        short_term = []
        long_term = []

        ip = event.actor.get("source_ip")
        user = event.actor.get("user")

        if event.event_type in ("AUTH_FAILURE", "LOGON_FAILURE"):
            if ip:
                immediate.append(f"Block source IP {ip} at firewall if external")
                immediate.append(f"Check for successful logins from {ip} after the failures")
            if user:
                immediate.append(f"Verify user '{user}' activity is legitimate")
            short_term.append("Enforce account lockout policy after N failures")
            short_term.append("Enable MFA for affected account")
            long_term.append("Deploy rate limiting on authentication endpoints")
            long_term.append("Implement geo-blocking for admin services")

        elif event.event_type in ("USER_CREATED",):
            immediate.append("Verify user creation was authorized")
            immediate.append("Check if account has been used since creation")
            if event.details.get("uid") == 0 or "uid=0" in (event.raw or "").lower():
                immediate.append("CRITICAL: UID 0 account created - investigate immediately")

        elif event.event_type in ("MIMIKATZ_DETECTED",):
            immediate.append("Isolate affected host from network")
            immediate.append("Force password reset for all users on affected host")
            immediate.append("Check for lateral movement to other hosts")
            short_term.append("Enable Credential Guard (Windows)")
            short_term.append("Audit LSASS access logs")
            long_term.append("Deploy EDR with credential theft detection")

        elif event.event_type in ("SUSPICIOUS_SERVICE", "SERVICE_INSTALLED"):
            svc = event.details.get("service_name", "unknown")
            immediate.append(f"Stop and quarantine service '{svc}'")
            immediate.append(f"Check service binary at: {event.details.get('image_path', 'unknown')}")
            short_term.append("Audit recent service installations")
            long_term.append("Implement application whitelisting")

        elif event.event_type in ("EVENT_LOG_CLEARED", "AUDIT_LOG_CLEARED"):
            immediate.append("CRITICAL: Logs were cleared - attacker may be covering tracks")
            immediate.append("Check for other indicators on this host")
            immediate.append("Pull backup logs from log server if available")
            short_term.append("Restrict who can clear event logs")
            long_term.append("Forward logs to write-once storage (SIEM)")

        else:
            immediate.append(f"Investigate {event.event_type} on host {event.host}")
            if ip:
                immediate.append(f"Check source IP {ip} reputation")
            short_term.append("Review related events in the last 24h")
            long_term.append("Update detection rules based on findings")

        return {
            "immediate": immediate,
            "short_term": short_term,
            "long_term": long_term,
        }


# === FastAPI entry point (optional) ===

def create_app():
    """Create a minimal FastAPI app exposing the orchestrator."""
    try:
        from fastapi import FastAPI, HTTPException
    except ImportError:
        print("FastAPI not installed. Run: pip install fastapi uvicorn")
        return None

    app = FastAPI(title="ARGUS AI Orchestrator", version="1.0")
    orch = Orchestrator(use_rag=True, use_llm=True)

    @app.get("/health")
    def health():
        return {"status": "ok", "service": "argus-ai"}

    @app.post("/api/v1/investigate")
    def investigate(event: Dict):
        try:
            inv = orch.investigate(event)
            return inv.to_dict()
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    return app


if __name__ == "__main__":
    import sys
    import json

    # CLI mode: python orchestrator.py '<event_json>'
    if len(sys.argv) > 1:
        event_dict = json.loads(sys.argv[1])
    else:
        # Default test event
        event_dict = {
            "event_id": "test-001",
            "timestamp": "2025-01-15T10:23:00Z",
            "host": "server01",
            "source": "linux_auth",
            "event_type": "AUTH_FAILURE",
            "severity": "high",
            "actor": {"source_ip": "198.51.100.42", "user": "admin"},
            "target": {"host": "server01", "service": "ssh"},
            "details": {"attempts": 7},
            "raw": "Failed password for invalid user admin from 198.51.100.42 port 22 ssh2"
        }

    orch = Orchestrator(use_rag=True, use_llm=True)
    result = orch.investigate(event_dict, brute_force_detected=True)
    print("\n" + "=" * 60)
    print(result.to_json())
