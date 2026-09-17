"""
risk_scorer.py - Deterministic risk scoring for fast triage.
"""
from typing import Dict, List

from schema import Event, RiskScore


SEVERITY_POINTS = {
    "critical": 40,
    "high": 25,
    "medium": 15,
    "low": 5,
    "info": 0,
}


def _level_from_score(score: int) -> str:
    if score >= 85:
        return "critical"
    if score >= 65:
        return "high"
    if score >= 40:
        return "medium"
    if score >= 15:
        return "low"
    return "info"


def score(
    event: Event,
    correlation_count: int = 0,
    threat_intel_malicious: bool = False,
    brute_force_detected: bool = False,
) -> RiskScore:
    total = 0
    factors: List[Dict] = []

    base_points = SEVERITY_POINTS.get((event.severity or "info").lower(), 0)
    if base_points:
        total += base_points
        factors.append({"factor": "event_severity", "points": base_points})

    event_type = event.event_type or ""
    if event_type in {"MIMIKATZ_DETECTED", "EVENT_LOG_CLEARED", "AUDIT_LOG_CLEARED"}:
        total += 35
        factors.append({"factor": "high_risk_event_type", "points": 35})
    elif event_type in {"CREDENTIAL_DISCOVERY", "PAYLOAD_TRANSFER"}:
        total += 35
        factors.append({"factor": "confirmed_honeypot_intrusion", "points": 35})
    elif event_type in {"PERSISTENCE_ATTEMPT", "PRIVILEGE_ESCALATION", "DATABASE_DISCOVERY"}:
        total += 25
        factors.append({"factor": "high_intent_honeypot_activity", "points": 25})
    elif event_type in {"PORT_SCAN", "DECOY_AUTH_ATTEMPT"}:
        total += 20
        factors.append({"factor": "decoy_access_signal", "points": 20})
    elif event_type in {"SYSTEM_DISCOVERY", "HONEYPOT_INTERACTION", "HTTP_REQUEST"}:
        total += 15
        factors.append({"factor": "decoy_discovery", "points": 15})
    elif event_type in {"SUSPICIOUS_SERVICE", "SERVICE_INSTALLED", "USER_CREATED"}:
        total += 20
        factors.append({"factor": "persistence_signal", "points": 20})
    elif event_type in {"AUTH_FAILURE", "LOGON_FAILURE"}:
        total += 15
        factors.append({"factor": "auth_failure_pattern", "points": 15})

    if threat_intel_malicious:
        total += 30
        factors.append({"factor": "malicious_threat_intel", "points": 30})

    if brute_force_detected:
        total += 25
        factors.append({"factor": "brute_force_detected", "points": 25})

    if correlation_count > 0:
        points = min(20, correlation_count * 5)
        total += points
        factors.append({"factor": "correlated_events", "points": points, "count": correlation_count})

    total = max(0, min(100, total))
    level = _level_from_score(total)
    confidence = min(0.98, 0.45 + (len(factors) * 0.1))

    return RiskScore(
        score=total,
        level=level,
        factors=factors,
        confidence=confidence,
        rationale=f"Scored from {len(factors)} contributing factors for {event_type}.",
    )
