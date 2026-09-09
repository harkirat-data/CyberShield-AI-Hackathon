"""Normalize honeypot activity into the existing ARGUS SOC analysis layer."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict

from .deception import IntentClassifier
from .models import TelemetryEvent
from .store import TelemetryStore


AI_ROOT = Path(__file__).resolve().parents[1] / "Ai"
if str(AI_ROOT) not in sys.path:
    sys.path.insert(0, str(AI_ROOT))

from agents import (  # noqa: E402
    add_correlation_event,
    correlate,
    map_mitre,
    score_risk,
    threat_intel_check,
)
from schema import Event  # noqa: E402


class SocBridge:
    """Run fast deterministic triage for each meaningful decoy event."""

    ANALYZED_DIRECTIONS = {"inbound", "system"}

    def __init__(self, store: TelemetryStore):
        self.store = store

    def analyze(
        self,
        telemetry: TelemetryEvent,
        *,
        session: Dict[str, Any],
        username: str | None = None,
    ) -> Dict[str, Any]:
        intent = IntentClassifier.classify(
            telemetry.content,
            auth_attempt=telemetry.event_type == "DECOY_AUTH_ATTEMPT",
        )
        event_type = (
            telemetry.event_type
            if telemetry.event_type not in {"HONEYPOT_INTERACTION", "DECOY_COMMAND"}
            else intent.event_type
        )
        event = Event.from_dict(
            {
                "event_id": telemetry.event_id,
                "timestamp": telemetry.timestamp,
                "host": session.get("persona", "argus-decoy"),
                "source": "argus_honeypot",
                "event_type": event_type,
                "severity": telemetry.severity or intent.severity,
                "actor": {
                    "source_ip": session.get("source_ip"),
                    "source_port": session.get("source_port"),
                    "user": username or session.get("username"),
                },
                "target": {
                    "host": "argus-decoy",
                    "service": session.get("service"),
                    "port": session.get("destination_port"),
                },
                "details": {
                    "command": telemetry.content[:1000],
                    "session_id": telemetry.session_id,
                    "sandboxed": True,
                    "executed": False,
                    **telemetry.metadata,
                },
                "raw": telemetry.content[:2000],
            }
        )
        add_correlation_event(event)
        correlation = correlate(event)
        threat = threat_intel_check(event)
        mitre = map_mitre(event)
        brute_force = event_type == "DECOY_AUTH_ATTEMPT" and len(
            correlation.related_events
        ) >= 2
        risk = score_risk(
            event,
            correlation_count=len(correlation.related_events),
            threat_intel_malicious=threat.is_malicious,
            brute_force_detected=brute_force,
        )

        # The session-facing intent classifier adds context the generic SOC
        # risk engine does not have, while risk itself remains deterministic.
        if intent.severity == "critical" and risk.score < 85:
            risk.score = 85
            risk.level = "critical"
            risk.factors.append({"factor": "honeypot_intent", "points": 25})
        elif intent.severity == "high" and risk.score < 65:
            risk.score = 65
            risk.level = "high"
            risk.factors.append({"factor": "honeypot_intent", "points": 20})

        result = {
            "event": event.to_dict(),
            "threat_intel": threat.to_dict(),
            "correlation": correlation.to_dict(),
            "mitre": mitre.to_dict(),
            "risk": risk.to_dict(),
            "intent": {
                "label": intent.label,
                "confidence": intent.confidence,
            },
            "safety": {"sandboxed": True, "executed": False},
        }
        self.store.save_investigation(
            event_id=telemetry.event_id,
            session_id=telemetry.session_id,
            risk_score=risk.score,
            risk_level=risk.level,
            intent=intent.label,
            intent_confidence=intent.confidence,
            mitre=mitre.techniques,
            rationale=risk.rationale,
            investigation=result,
        )
        return result
