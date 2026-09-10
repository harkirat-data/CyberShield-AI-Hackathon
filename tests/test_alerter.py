"""
test_alerter.py - Unit and integration tests for CyberShield AI alerting layer.

Tests:
1. Slack payload generation
2. Discord payload generation
3. Email subject and body generation
4. Missing Slack configuration does not crash
5. Missing Discord configuration does not crash
6. Missing SMTP configuration does not crash
7. Low-risk events do not generate alerts
8. High-risk events generate alerts
9. Failed webhook/SMTP delivery does not crash backend
10. Deduplication prevents alert storms
11. Canary trigger -> Investigation -> Alert decision integration flow
"""

import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Ensure Ai/ is in path
AI_PATH = Path(__file__).parent.parent / "Ai"
if str(AI_PATH) not in sys.path:
    sys.path.insert(0, str(AI_PATH))
ROOT_PATH = Path(__file__).parent.parent
if str(ROOT_PATH) not in sys.path:
    sys.path.insert(0, str(ROOT_PATH))

from agents.alerter import (
    AlertManager,
    DiscordAlerter,
    EmailAlerter,
    SecurityAlert,
    SlackAlerter,
    get_alert_manager,
    reset_alert_manager,
)
from schema import Event, Investigation, MitreMapping, RiskScore, ThreatIntel, CorrelationResult


@pytest.fixture(autouse=True)
def clean_alert_manager():
    """Reset the global alert manager between tests."""
    reset_alert_manager()
    yield
    reset_alert_manager()


def sample_alert(severity="critical", risk_score=90, event_id="evt-test-001"):
    return SecurityAlert(
        event_id=event_id,
        timestamp="2026-09-10T22:00:00Z",
        severity=severity,
        risk_score=risk_score,
        source_ip="192.168.1.100",
        host="prod-db-01",
        service="ssh",
        event_type="MIMIKATZ_DETECTED",
        intent="Credential Access",
        mitre_techniques=["T1003", "T1078"],
        mitre_tactics=["Credential Access", "Defense Evasion"],
        ai_summary="LSASS memory dump detected indicative of Mimikatz credential dumping.",
        recommended_remediation=[
            "Isolate prod-db-01 from the network",
            "Reset credentials for affected accounts",
        ],
        details={"process": "mimikatz.exe", "pid": 4820},
    )


def sample_investigation(severity="critical", risk_score=95, event_id="inv-test-001"):
    event = Event(
        event_id=event_id,
        timestamp="2026-09-10T22:00:00Z",
        host="prod-api-01",
        source="endpoint",
        event_type="MIMIKATZ_DETECTED",
        severity=severity,
        actor={"source_ip": "10.0.0.55", "user": "SYSTEM"},
        target={"host": "prod-api-01", "service": "endpoint"},
        details={"tool": "mimikatz"},
        raw="mimikatz executed on prod-api-01",
    )
    return Investigation(
        event=event,
        threat_intel=ThreatIntel(is_malicious=True),
        correlation=CorrelationResult(),
        mitre=MitreMapping(techniques=["T1003"], tactics=["Credential Access"]),
        risk=RiskScore(score=risk_score, level=severity, rationale="Confirmed credential theft artifact"),
        llm_analysis={"summary": "Malicious credential dumping detected using Mimikatz."},
        final_severity=severity,
        final_remediation={"immediate": ["Isolate host immediately", "Revoke active sessions"]},
    )


# ---------------------------------------------------------------------------
# Test 1: Slack Payload Generation
# ---------------------------------------------------------------------------
def test_slack_payload_generation():
    alert = sample_alert()
    slack = SlackAlerter(webhook_url="https://hooks.slack.com/services/test")
    payload = slack.build_payload(alert)

    assert "blocks" in payload
    assert "text" in payload
    assert alert.event_type in payload["text"]
    assert "MIMIKATZ_DETECTED" in payload["text"]

    # Verify blocks content
    header_text = payload["blocks"][0]["text"]["text"]
    assert "CRITICAL" in header_text
    assert "CyberShield AI" in header_text

    # Verify section fields
    fields = payload["blocks"][1]["fields"]
    field_texts = [f["text"] for f in fields]
    assert any("MIMIKATZ_DETECTED" in t for t in field_texts)
    assert any("90/100" in t for t in field_texts)
    assert any("192.168.1.100" in t for t in field_texts)
    assert any("T1003" in t for t in field_texts)


# ---------------------------------------------------------------------------
# Test 2: Discord Payload Generation
# ---------------------------------------------------------------------------
def test_discord_payload_generation():
    alert = sample_alert(severity="critical", risk_score=95)
    discord = DiscordAlerter(webhook_url="https://discord.com/api/webhooks/test")
    payload = discord.build_payload(alert)

    assert "embeds" in payload
    embed = payload["embeds"][0]
    assert "🚨 [CyberShield AI] CRITICAL Incident Detected" in embed["title"]
    assert embed["color"] == 0xDC2626  # Red for critical

    field_dict = {f["name"]: f["value"] for f in embed["fields"]}
    assert field_dict["Event Type"] == "`MIMIKATZ_DETECTED`"
    assert field_dict["Risk Score"] == "`95/100`"
    assert field_dict["Source IP"] == "`192.168.1.100`"
    assert "T1003" in field_dict["MITRE ATT&CK"]


# ---------------------------------------------------------------------------
# Test 3: Email Subject & Body Generation
# ---------------------------------------------------------------------------
def test_email_subject_and_body_generation():
    alert = sample_alert(severity="high", risk_score=85)
    email = EmailAlerter(
        smtp_host="smtp.test.local",
        alert_to="soc-tier2@example.com",
    )
    subject, text_body, html_body = email.build_message(alert)

    assert subject == "[CyberShield][HIGH] Security Incident Detected: MIMIKATZ_DETECTED"
    assert "MIMIKATZ_DETECTED" in text_body
    assert "85/100" in text_body
    assert "192.168.1.100" in text_body
    assert "T1003" in text_body
    assert "Isolate prod-db-01 from the network" in text_body

    assert "<html>" in html_body
    assert "CyberShield AI" in html_body
    assert "HIGH" in html_body
    assert "192.168.1.100" in html_body


# ---------------------------------------------------------------------------
# Test 4: Missing Slack Configuration Does Not Crash
# ---------------------------------------------------------------------------
def test_missing_slack_config_does_not_crash(monkeypatch):
    monkeypatch.delenv("SLACK_WEBHOOK_URL", raising=False)
    slack = SlackAlerter(webhook_url="")
    assert slack.is_configured is False

    # Should safely return False without exception
    result = slack.send(sample_alert())
    assert result is False


# ---------------------------------------------------------------------------
# Test 5: Missing Discord Configuration Does Not Crash
# ---------------------------------------------------------------------------
def test_missing_discord_config_does_not_crash(monkeypatch):
    monkeypatch.delenv("DISCORD_WEBHOOK_URL", raising=False)
    discord = DiscordAlerter(webhook_url="")
    assert discord.is_configured is False

    # Should safely return False without exception
    result = discord.send(sample_alert())
    assert result is False


# ---------------------------------------------------------------------------
# Test 6: Missing SMTP Configuration Does Not Crash
# ---------------------------------------------------------------------------
def test_missing_smtp_config_does_not_crash(monkeypatch):
    monkeypatch.delenv("SMTP_HOST", raising=False)
    monkeypatch.delenv("ALERT_EMAIL_TO", raising=False)
    email = EmailAlerter(smtp_host="", alert_to="")
    assert email.is_configured is False

    # Should safely return False without exception
    result = email.send(sample_alert())
    assert result is False


# ---------------------------------------------------------------------------
# Test 7: Low-Risk Events Do Not Generate Alerts
# ---------------------------------------------------------------------------
def test_low_risk_events_do_not_generate_alerts():
    manager = AlertManager(
        min_risk_score=80,
        min_severity="high",
    )
    low_alert = sample_alert(severity="low", risk_score=25)

    assert manager.should_alert(low_alert) is False
    result = manager.send_alert(low_alert, sync=True)
    assert result is None


# ---------------------------------------------------------------------------
# Test 8: High-Risk Events Generate Alerts
# ---------------------------------------------------------------------------
def test_high_risk_events_generate_alerts():
    mock_slack = MagicMock()
    mock_slack.send.return_value = True

    mock_discord = MagicMock()
    mock_discord.send.return_value = True

    mock_email = MagicMock()
    mock_email.send.return_value = True

    manager = AlertManager(
        slack=mock_slack,
        discord=mock_discord,
        email=mock_email,
        min_risk_score=80,
        min_severity="high",
    )

    high_alert = sample_alert(severity="critical", risk_score=95)
    assert manager.should_alert(high_alert) is True

    result = manager.send_alert(high_alert, sync=True)
    assert result == {"slack": True, "discord": True, "email": True}
    mock_slack.send.assert_called_once_with(high_alert)
    mock_discord.send.assert_called_once_with(high_alert)
    mock_email.send.assert_called_once_with(high_alert)


# ---------------------------------------------------------------------------
# Test 9: Failed Webhook / SMTP Delivery Does Not Crash Backend
# ---------------------------------------------------------------------------
def test_failed_webhook_and_smtp_does_not_crash():
    alert = sample_alert(severity="critical", risk_score=95)

    # 1. Slack failure
    slack = SlackAlerter(webhook_url="https://hooks.slack.com/services/invalid")
    with patch("urllib.request.urlopen", side_effect=Exception("Connection refused")):
        assert slack.send(alert) is False

    # 2. Discord failure
    discord = DiscordAlerter(webhook_url="https://discord.com/api/webhooks/invalid")
    with patch("urllib.request.urlopen", side_effect=Exception("HTTP 500 Internal Error")):
        assert discord.send(alert) is False

    # 3. SMTP failure
    email = EmailAlerter(smtp_host="smtp.unreachable.net", alert_to="soc@example.com")
    with patch("smtplib.SMTP", side_effect=Exception("SMTP connect timeout")):
        assert email.send(alert) is False

    # 4. AlertManager dispatch with all failing
    manager = AlertManager(slack=slack, discord=discord, email=email, min_risk_score=80)
    with patch("urllib.request.urlopen", side_effect=Exception("Delivery failed")), \
         patch("smtplib.SMTP", side_effect=Exception("SMTP failed")):
        result = manager.send_alert(alert, sync=True)
        assert result == {"slack": False, "discord": False, "email": False}


# ---------------------------------------------------------------------------
# Test 10: Deduplication Prevents Alert Storms
# ---------------------------------------------------------------------------
def test_deduplication_prevents_alert_storms():
    mock_slack = MagicMock(return_value=True)
    manager = AlertManager(
        slack=MagicMock(send=mock_slack),
        discord=MagicMock(send=MagicMock(return_value=True)),
        email=MagicMock(send=MagicMock(return_value=True)),
        min_risk_score=80,
        dedup_window_seconds=60,
    )

    alert = sample_alert(event_id="unique-storm-event-1", risk_score=90)

    # First send -> should succeed
    res1 = manager.send_alert(alert, sync=True)
    assert res1 is not None

    # Immediate second send with same event_id -> should be suppressed
    res2 = manager.send_alert(alert, sync=True)
    assert res2 is None


# ---------------------------------------------------------------------------
# Test 11: End-to-End Canary Trigger -> Investigation -> Alert Dispatch Flow
# ---------------------------------------------------------------------------
def test_canary_trigger_to_alert_flow(tmp_path):
    from orchestrator import Orchestrator

    # Prepare an orchestrator with mocked alert manager
    mock_dispatch = MagicMock()
    custom_manager = AlertManager(
        slack=MagicMock(send=mock_dispatch),
        min_risk_score=40,  # Lower threshold for canary event
        min_severity="critical",
    )

    with patch("agents.alerter.get_alert_manager", return_value=custom_manager), \
         patch("orchestrator.get_alert_manager", return_value=custom_manager):

        orch = Orchestrator(use_rag=False, use_llm=False)

        # Simulate Canary Token Trigger event exactly as api_server does
        canary_event = {
            "event_id": "canary-trig-test-abc12345",
            "timestamp": "2026-09-10T22:00:00Z",
            "host": "cybershield-api",
            "source": "canary_service",
            "event_type": "CANARY_TOKEN_TRIGGERED",
            "severity": "critical",
            "actor": {
                "source_ip": "203.0.113.42",
                "user": None,
            },
            "target": {
                "host": "cybershield-api",
                "service": "canary",
                "port": 80,
            },
            "details": {
                "token_id": "tok-999",
                "token_name": "Honey-AWS-Key",
                "token_type": "credential",
                "simulated": False,
            },
            "raw": "Canary token 'Honey-AWS-Key' (type: credential) triggered from 203.0.113.42",
        }

        # Run investigation
        inv = orch.investigate(canary_event, brute_force_detected=False, dispatch_alerts=True)

        assert inv.event.event_type == "CANARY_TOKEN_TRIGGERED"
        assert inv.final_severity in ("critical", "medium")  # Base points 40

        # Verify that process_investigation was triggered
        # Allow thread execution
        import time
        time.sleep(0.1)

        assert mock_dispatch.called
        sent_alert = mock_dispatch.call_args[0][0]
        assert isinstance(sent_alert, SecurityAlert)
        assert sent_alert.event_id == "canary-trig-test-abc12345"
        assert sent_alert.source_ip == "203.0.113.42"
        assert sent_alert.event_type == "CANARY_TOKEN_TRIGGERED"
