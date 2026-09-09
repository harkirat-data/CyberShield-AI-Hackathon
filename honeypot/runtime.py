"""Async network runtime for the five ARGUS decoy services."""

from __future__ import annotations

import asyncio
import hashlib
import html
import os
import re
import secrets
import ssl
import struct
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Tuple
from urllib.parse import unquote_plus

from .config import HoneypotSettings, ServiceProfile
from .deception import GeminiDeceptionEngine, IntentClassifier
from .models import DecoySession, TelemetryEvent, new_id
from .soc_bridge import SocBridge
from .store import TelemetryStore


SHELL_PROMPT = "backup@finance-prod-01:/srv/backups$ "
SECRET_HEADERS = {"authorization", "cookie", "proxy-authorization", "x-api-key"}


class HoneypotRuntime:
    """Own the listeners, active connections, AI personas, and telemetry flow."""

    def __init__(
        self,
        settings: Optional[HoneypotSettings] = None,
        store: Optional[TelemetryStore] = None,
    ):
        self.settings = settings or HoneypotSettings.from_env()
        self.store = store or TelemetryStore(self.settings.database_path)
        self.brain = GeminiDeceptionEngine(self.settings)
        self.soc = SocBridge(self.store)
        self._servers: Dict[str, asyncio.AbstractServer] = {}
        self._service_state: Dict[str, Dict[str, Any]] = {}
        self._writers: Dict[str, asyncio.StreamWriter] = {}
        self._active_by_ip: Dict[str, int] = defaultdict(int)
        self._blocked_sources: set[str] = set()

    @property
    def running(self) -> bool:
        return any(server.is_serving() for server in self._servers.values())

    async def start(self) -> Dict[str, Any]:
        """Open all configured ports; failed services remain visible as degraded."""

        if self.running:
            return self.status()
        self._service_state = {}
        for profile in self.settings.services:
            try:
                tls = self._tls_context() if profile.protocol == "https" else None
                server = await asyncio.start_server(
                    lambda reader, writer, selected=profile: self._handle_connection(
                        selected, reader, writer
                    ),
                    host=self.settings.bind_host,
                    port=profile.port,
                    ssl=tls,
                    limit=max(self.settings.max_input_bytes * 2, 65_536),
                )
                self._servers[profile.key] = server
                sockets = server.sockets or []
                bound_port = sockets[0].getsockname()[1] if sockets else profile.port
                self._service_state[profile.key] = {
                    "key": profile.key,
                    "name": profile.name,
                    "protocol": profile.protocol,
                    "configured_port": profile.port,
                    "port": bound_port,
                    "public_port": profile.public_port,
                    "product": profile.product,
                    "persona": profile.persona,
                    "status": "listening",
                    "error": None,
                }
            except Exception as exc:
                self._service_state[profile.key] = {
                    "key": profile.key,
                    "name": profile.name,
                    "protocol": profile.protocol,
                    "configured_port": profile.port,
                    "port": profile.port,
                    "public_port": profile.public_port,
                    "product": profile.product,
                    "persona": profile.persona,
                    "status": "failed",
                    "error": str(exc),
                }
                print(f"[honeypot] failed to bind {profile.name}:{profile.port}: {exc}")
        return self.status()

    async def stop(self) -> Dict[str, Any]:
        for writer in list(self._writers.values()):
            writer.close()
        for server in self._servers.values():
            server.close()
        if self._servers:
            await asyncio.gather(
                *(server.wait_closed() for server in self._servers.values()),
                return_exceptions=True,
            )
        self._servers.clear()
        for service in self._service_state.values():
            if service["status"] == "listening":
                service["status"] = "stopped"
        return self.status()

    async def contain(self, session_id: str) -> bool:
        """Disconnect a decoy session and mark it contained."""

        found = self.store.contain_session(session_id)
        writer = self._writers.get(session_id)
        if writer is not None:
            try:
                writer.write(b"\r\nConnection closed by remote host.\r\n")
                await writer.drain()
            except Exception:
                pass
            writer.close()
        return found

    async def block_source(self, source_ip: str) -> int:
        """Block an address inside this runtime and disconnect its live sessions.

        This intentionally does not mutate the host firewall.  Network-level
        blocking remains an operator-controlled deployment action.
        """

        self._blocked_sources.add(source_ip)
        matching = [
            item
            for item in self.store.list_sessions(limit=500, status="active")
            if item.get("source_ip") == source_ip
        ]
        for session in matching:
            await self.contain(str(session["session_id"]))
        return len(matching)

    def status(self) -> Dict[str, Any]:
        active = self.store.list_sessions(limit=500, status="active")
        active_counts: Dict[str, int] = defaultdict(int)
        for session in active:
            active_counts[str(session["service"])] += 1
        services = []
        known = self._service_state or {
            profile.key: {
                "key": profile.key,
                "name": profile.name,
                "protocol": profile.protocol,
                "configured_port": profile.port,
                "port": profile.port,
                "public_port": profile.public_port,
                "product": profile.product,
                "persona": profile.persona,
                "status": "stopped",
                "error": None,
            }
            for profile in self.settings.services
        }
        for value in known.values():
            item = dict(value)
            item["active_sessions"] = active_counts.get(item["name"], 0)
            services.append(item)
        return {
            "running": self.running,
            "bind_host": self.settings.bind_host,
            "sandboxed": True,
            "exec_enabled": False,
            "egress_required_blocked": True,
            "gemini": {
                "enabled": self.settings.enable_gemini,
                "configured": self.brain.client is not None,
                "healthy": (
                    self.brain.last_provider.startswith("gemini:")
                    if self.brain.last_provider != "not-used"
                    else None
                ),
                "backend": self.brain.backend,
                "last_provider": self.brain.last_provider,
                "last_error": self.brain.last_error,
            },
            "blocked_sources": len(self._blocked_sources),
            "services": services,
        }

    async def _handle_connection(
        self,
        profile: ServiceProfile,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        peer = writer.get_extra_info("peername") or ("unknown", 0)
        source_ip = str(peer[0])
        source_port = int(peer[1] or 0)
        session_id = new_id("ses")
        session = DecoySession(
            session_id=session_id,
            source_ip=source_ip,
            source_port=source_port,
            destination_port=self._local_port(writer, profile.port),
            service=profile.name,
            protocol=profile.protocol,
            persona=profile.persona,
        )
        self.store.create_session(session)
        self._writers[session_id] = writer
        self._active_by_ip[source_ip] += 1
        await self._event(
            session_id,
            "HONEYPOT_SESSION_STARTED",
            "medium",
            "system",
            f"Connection opened on {profile.name}:{session.destination_port}",
            metadata={
                "source_ip": source_ip,
                "source_port": source_port,
                "destination_port": session.destination_port,
                "tls": profile.protocol == "https",
            },
            analyze=True,
        )
        await self._detect_port_scan(session_id, source_ip)

        if source_ip in self._blocked_sources:
            await self._event(
                session_id,
                "SOURCE_BLOCKED",
                "high",
                "system",
                "Connection rejected by ARGUS runtime blocklist",
                metadata={"source_ip": source_ip},
                analyze=True,
            )
            self.store.end_session(session_id, "blocked")
            writer.close()
            self._connection_finished(session_id, source_ip)
            return

        if self._active_by_ip[source_ip] > self.settings.max_sessions_per_ip:
            await self._event(
                session_id,
                "SESSION_RATE_LIMITED",
                "high",
                "system",
                "Per-source concurrent session limit exceeded",
                metadata={"limit": self.settings.max_sessions_per_ip},
                analyze=True,
            )
            self.store.end_session(session_id, "rate_limited")
            writer.close()
            self._connection_finished(session_id, source_ip)
            return

        try:
            handler = {
                "ssh": self._handle_ssh,
                "telnet": self._handle_telnet,
                "http": self._handle_http,
                "https": self._handle_http,
                "mysql": self._handle_mysql,
            }[profile.protocol]
            await asyncio.wait_for(
                handler(session_id, profile, reader, writer),
                timeout=self.settings.session_timeout_seconds,
            )
        except asyncio.TimeoutError:
            await self._event(
                session_id,
                "SESSION_TIMEOUT",
                "low",
                "system",
                "Session idle or lifetime limit reached",
            )
        except (ConnectionError, asyncio.IncompleteReadError, BrokenPipeError):
            pass
        except Exception as exc:
            await self._event(
                session_id,
                "PROTOCOL_ERROR",
                "low",
                "system",
                str(exc)[:300],
                metadata={"exception": type(exc).__name__},
            )
        finally:
            current = self.store.get_session(session_id)
            if current and current["status"] == "active":
                self.store.end_session(session_id)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            self._connection_finished(session_id, source_ip)

    async def _handle_ssh(
        self,
        session_id: str,
        profile: ServiceProfile,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        banner = f"SSH-2.0-{profile.product}\r\n"
        await self._send(session_id, writer, banner.encode(), "SSH_BANNER")
        first = await self._read_line(reader)
        if not first:
            return
        preview = self._preview(first)
        await self._event(
            session_id,
            "SSH_CLIENT_HELLO",
            "medium",
            "inbound",
            preview,
            byte_count=len(first),
            metadata={"binary_sha256": hashlib.sha256(first).hexdigest()},
            analyze=True,
        )
        if first.startswith(b"SSH-"):
            self.store.set_fingerprint(session_id, preview[:200])
            # A protocol-correct SSH implementation can be enabled later with
            # Paramiko.  The sensor still captures scanners and client banners.
            await self._send(
                session_id,
                writer,
                b"Protocol negotiation failed: no matching key exchange method\r\n",
                "SSH_NEGOTIATION_RESPONSE",
            )
            return

        username = preview.strip()[:128] or "root"
        await self._capture_credentials(session_id, reader, writer, username=username)
        await self._shell_loop(session_id, profile, reader, writer)

    async def _handle_telnet(
        self,
        session_id: str,
        profile: ServiceProfile,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        banner = (
            "Ubuntu 22.04.3 LTS finance-prod-01 ttyS0\r\n\r\n"
            "finance-prod-01 login: "
        ).encode()
        await self._send(session_id, writer, banner, "TELNET_BANNER")
        username_bytes = await self._read_line(reader)
        username = self._preview(username_bytes).strip()[:128] or "root"
        await self._capture_credentials(session_id, reader, writer, username=username)
        await self._shell_loop(session_id, profile, reader, writer)

    async def _capture_credentials(
        self,
        session_id: str,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        *,
        username: str,
    ) -> None:
        await self._send(session_id, writer, b"Password: ", "AUTH_PROMPT")
        password = await self._read_line(reader)
        password_hash = hashlib.sha256(password.rstrip(b"\r\n")).hexdigest()
        self.store.set_fingerprint(session_id, "interactive-terminal", username=username)
        await self._event(
            session_id,
            "DECOY_AUTH_ATTEMPT",
            "high",
            "inbound",
            f"username={username} password=[HASHED]",
            byte_count=len(password),
            metadata={
                "username": username,
                "password_sha256": password_hash,
                "password_length": len(password.rstrip(b"\r\n")),
                "raw_password_stored": False,
                "accepted_by_decoy": True,
            },
            analyze=True,
            username=username,
        )
        await self._send(
            session_id,
            writer,
            b"\r\nLast login: Fri Sep  4 13:57:22 2026 from 10.42.7.9\r\n" + SHELL_PROMPT.encode(),
            "DECOY_AUTH_SUCCESS",
        )

    async def _shell_loop(
        self,
        session_id: str,
        profile: ServiceProfile,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        for _ in range(self.settings.max_interactions_per_session):
            line = await self._read_line(reader)
            if not line:
                return
            command = self._preview(line).strip()
            if not command:
                await self._send(session_id, writer, SHELL_PROMPT.encode(), "DECOY_PROMPT")
                continue
            intent = IntentClassifier.classify(command)
            await self._event(
                session_id,
                intent.event_type,
                intent.severity,
                "inbound",
                command,
                byte_count=len(line),
                metadata={
                    "intent": intent.label,
                    "intent_confidence": intent.confidence,
                    "executed": False,
                },
                analyze=True,
            )
            response, ai_meta = await self.brain.respond(
                session_id=session_id,
                profile=profile,
                attacker_input=command,
                context={"cwd": "/srv/backups"},
            )
            output = (response + "\r\n" + SHELL_PROMPT).encode("utf-8", errors="replace")
            await self._send(
                session_id,
                writer,
                output,
                "DECOY_AI_RESPONSE",
                metadata=ai_meta,
                latency_ms=ai_meta.get("latency_ms"),
            )
            if command.lower() in {"exit", "logout", "quit"}:
                return

    async def _handle_http(
        self,
        session_id: str,
        profile: ServiceProfile,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        try:
            raw = await self._read_http_request(reader, writer)
        except (
            ValueError,
            asyncio.TimeoutError,
            asyncio.LimitOverrunError,
            asyncio.IncompleteReadError,
        ):
            await self._send(
                session_id,
                writer,
                b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                "DECOY_HTTP_RESPONSE",
                metadata={"provider": "protocol-handler"},
            )
            return
        if not raw:
            return
        method, path, version, headers, body = self._parse_http(raw)
        fingerprint = headers.get("user-agent", "unknown")[:240]
        self.store.set_fingerprint(session_id, fingerprint)
        safe_headers = {
            key: ("[REDACTED]" if key.lower() in SECRET_HEADERS else value[:500])
            for key, value in headers.items()
        }
        decoded_body = self._preview(body)
        if "application/x-www-form-urlencoded" in headers.get("content-type", ""):
            decoded_body = unquote_plus(decoded_body)
        safe_body = self._redact_http_body(decoded_body)
        path = self._redact_http_body(unquote_plus(path))
        request_summary = f"{method} {path} {version}\n{safe_body}".strip()
        intent = IntentClassifier.classify(request_summary)
        event_type = "HTTP_REQUEST" if intent.event_type == "HONEYPOT_INTERACTION" else intent.event_type
        await self._event(
            session_id,
            event_type,
            intent.severity,
            "inbound",
            request_summary,
            byte_count=len(raw),
            metadata={
                "method": method,
                "path": path,
                "headers": safe_headers,
                "body_sha256": hashlib.sha256(body).hexdigest(),
                "body_bytes": len(body),
                "intent": intent.label,
                "intent_confidence": intent.confidence,
            },
            analyze=True,
        )

        if path == "/" and method == "GET":
            payload = self._login_page(profile).encode()
            status = "200 OK"
            content_type = "text/html; charset=utf-8"
            ai_meta = {"provider": "static-decoy", "latency_ms": 0}
        elif path.startswith("/login") and method in {"POST", "PUT"}:
            payload = b'{"ok":true,"redirect":"/admin"}'
            status = "200 OK"
            content_type = "application/json"
            ai_meta = {"provider": "static-decoy", "latency_ms": 0}
        else:
            response, ai_meta = await self.brain.respond(
                session_id=session_id,
                profile=profile,
                attacker_input=request_summary,
                context={"method": method, "path": path},
            )
            response, status, content_type = self._normalize_http_ai_response(response)
            payload = response.encode("utf-8", errors="replace")

        response_headers = (
            f"HTTP/1.1 {status}\r\n"
            f"Server: {profile.product}\r\n"
            f"Content-Type: {content_type}\r\n"
            f"Content-Length: {len(payload)}\r\n"
            "X-Content-Type-Options: nosniff\r\n"
            "Connection: close\r\n\r\n"
        ).encode()
        if method == "HEAD":
            payload = b""
        await self._send(
            session_id,
            writer,
            response_headers + payload,
            "DECOY_HTTP_RESPONSE",
            metadata=ai_meta,
            latency_ms=ai_meta.get("latency_ms"),
        )

    @staticmethod
    def _normalize_http_ai_response(response: str) -> Tuple[str, str, str]:
        """Turn imperfect model output into one valid outer HTTP response.

        The runtime owns HTTP framing. If a model nevertheless emits a status
        line and headers, preserve the safe status/body while removing the
        nested envelope. Literal escaped angle brackets are also normalized so
        an HTML body remains valid markup rather than escaped angle-bracket text.
        """

        text = response.strip().replace("\\<", "<").replace("\\>", ">")
        status = "200 OK"

        status_match = re.match(
            r"^HTTP/\d(?:\.\d)?\s+(\d{3})(?:\s+([^\r\n]+))?",
            text,
            flags=re.IGNORECASE,
        )
        if status_match:
            code = int(status_match.group(1))
            allowed_codes = {200, 201, 202, 204, 400, 401, 403, 404, 409, 429, 500, 502, 503}
            if code in allowed_codes:
                reason = re.sub(r"[^A-Za-z0-9 .'-]", "", status_match.group(2) or "")[:80].strip()
                default_reasons = {
                    200: "OK",
                    201: "Created",
                    202: "Accepted",
                    204: "No Content",
                    400: "Bad Request",
                    401: "Unauthorized",
                    403: "Forbidden",
                    404: "Not Found",
                    409: "Conflict",
                    429: "Too Many Requests",
                    500: "Internal Server Error",
                    502: "Bad Gateway",
                    503: "Service Unavailable",
                }
                status = f"{code} {reason or default_reasons[code]}"

            envelope = re.split(r"\r?\n\r?\n", text, maxsplit=1)
            text = envelope[1].strip() if len(envelope) == 2 else ""

        if text.lstrip().startswith(("{", "[")):
            content_type = "application/json"
        elif text.lstrip().lower().startswith(("<!doctype html", "<html", "<head", "<body")):
            content_type = "text/html; charset=utf-8"
        else:
            content_type = "text/plain; charset=utf-8"

        return text, status, content_type

    async def _handle_mysql(
        self,
        session_id: str,
        profile: ServiceProfile,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        salt = secrets.token_bytes(20)
        handshake = self._mysql_handshake(profile.product, salt)
        await self._send(session_id, writer, handshake, "MYSQL_HANDSHAKE")
        login = await self._read_mysql_packet(reader)
        if login is None:
            return
        sequence, payload = login
        username = self._mysql_username(payload)
        self.store.set_fingerprint(session_id, "mysql-client", username=username)
        await self._event(
            session_id,
            "DECOY_AUTH_ATTEMPT",
            "high",
            "inbound",
            f"mysql username={username or 'unknown'} auth_response=[HASHED]",
            byte_count=len(payload) + 4,
            metadata={
                "username": username,
                "packet_sha256": hashlib.sha256(payload).hexdigest(),
                "raw_auth_stored": False,
                "accepted_by_decoy": True,
            },
            analyze=True,
            username=username,
        )
        await self._send(
            session_id,
            writer,
            self._mysql_packet(b"\x00\x00\x00\x02\x00\x00\x00", (sequence + 1) & 0xFF),
            "MYSQL_AUTH_OK",
        )

        for _ in range(self.settings.max_interactions_per_session):
            packet = await self._read_mysql_packet(reader)
            if packet is None:
                return
            _, payload = packet
            if not payload:
                continue
            command = payload[0]
            if command == 0x01:  # COM_QUIT
                return
            if command != 0x03:  # COM_QUERY
                await self._send(
                    session_id,
                    writer,
                    self._mysql_error(1064, "Unsupported command in reporting replica"),
                    "MYSQL_ERROR",
                )
                continue
            query = self._preview(payload[1:]).strip()
            intent = IntentClassifier.classify(query)
            await self._event(
                session_id,
                "DATABASE_DISCOVERY",
                max(intent.severity, "high", key=self._severity_rank),
                "inbound",
                query,
                byte_count=len(payload) + 4,
                metadata={"database": "finance_core", "executed": False},
                analyze=True,
                username=username,
            )
            response, ai_meta = await self.brain.respond(
                session_id=session_id,
                profile=profile,
                attacker_input=query,
                context={"database": "finance_core", "username": username},
            )
            await self._send(
                session_id,
                writer,
                self._mysql_text_result(response),
                "DECOY_MYSQL_RESULT",
                metadata=ai_meta,
                latency_ms=ai_meta.get("latency_ms"),
            )

    async def _detect_port_scan(self, session_id: str, source_ip: str) -> None:
        ports = self.store.recent_destination_ports(source_ip, limit=8)
        unique_ports = sorted(set(ports))
        if len(unique_ports) >= 3:
            await self._event(
                session_id,
                "PORT_SCAN",
                "high",
                "system",
                f"Source touched {len(unique_ports)} decoy ports: {unique_ports}",
                metadata={"ports": unique_ports, "source_ip": source_ip},
                analyze=True,
            )

    async def _event(
        self,
        session_id: str,
        event_type: str,
        severity: str,
        direction: str,
        content: str,
        *,
        byte_count: int = 0,
        metadata: Optional[Dict[str, Any]] = None,
        latency_ms: Optional[int] = None,
        analyze: bool = False,
        username: Optional[str] = None,
    ) -> TelemetryEvent:
        clean_content = self._clean_event_content(content)
        event = TelemetryEvent(
            session_id=session_id,
            event_type=event_type,
            severity=severity,
            direction=direction,
            content=clean_content,
            metadata=metadata or {},
            byte_count=byte_count,
            latency_ms=latency_ms,
        )
        self.store.record_event(event)
        if analyze:
            session = self.store.get_session(session_id)
            if session:
                self.soc.analyze(event, session=session, username=username)
        return event

    async def _send(
        self,
        session_id: str,
        writer: asyncio.StreamWriter,
        data: bytes,
        event_type: str,
        *,
        metadata: Optional[Dict[str, Any]] = None,
        latency_ms: Optional[int] = None,
    ) -> None:
        writer.write(data)
        await writer.drain()
        await self._event(
            session_id,
            event_type,
            "info",
            "outbound",
            self._preview(data),
            byte_count=len(data),
            metadata={"simulated": True, "executed": False, **(metadata or {})},
            latency_ms=latency_ms,
        )

    async def _read_line(self, reader: asyncio.StreamReader) -> bytes:
        try:
            line = await asyncio.wait_for(
                reader.readline(), timeout=self.settings.read_timeout_seconds
            )
            return line[: self.settings.max_input_bytes]
        except (asyncio.LimitOverrunError, ValueError):
            return await reader.read(self.settings.max_input_bytes)

    async def _read_http_request(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> bytes:
        async def read(awaitable):
            return await asyncio.wait_for(awaitable, self.settings.read_timeout_seconds)

        headers = await read(reader.readuntil(b"\r\n\r\n"))
        budget = self.settings.max_input_bytes - len(headers)
        if budget < 0:
            raise ValueError("Request headers too large")
        _, _, _, fields, _ = self._parse_http(headers)
        if fields.get("transfer-encoding") and fields.get("content-length"):
            raise ValueError("Ambiguous request framing")
        length = int(fields.get("content-length", "0"))
        if length < 0 or length > budget:
            raise ValueError("Request body too large")
        if fields.get("expect", "").lower() == "100-continue":
            writer.write(b"HTTP/1.1 100 Continue\r\n\r\n")
            await writer.drain()
        if "transfer-encoding" not in fields:
            return headers + (await read(reader.readexactly(length)) if length else b"")
        if fields["transfer-encoding"].lower() != "chunked":
            raise ValueError("Unsupported transfer encoding")
        chunks = []
        # Bound decoded body AND framing/trailers, including many tiny chunks.
        while True:
            line = await read(reader.readuntil(b"\r\n"))
            budget -= len(line)
            size = int(line.split(b";", 1)[0].strip(), 16)
            if size < 0 or size > budget or budget < 0:
                raise ValueError("Chunk exceeds request limit")
            if size == 0:
                while True:
                    trailer = await read(reader.readuntil(b"\r\n"))
                    budget -= len(trailer)
                    if budget < 0:
                        raise ValueError("Trailers exceed request limit")
                    if trailer == b"\r\n":
                        return headers + b"".join(chunks)
            chunk = await read(reader.readexactly(size + 2))
            budget -= len(chunk)
            if budget < 0 or not chunk.endswith(b"\r\n"):
                raise ValueError("Malformed chunk")
            chunks.append(chunk[:-2])

    async def _read_mysql_packet(
        self, reader: asyncio.StreamReader
    ) -> Optional[Tuple[int, bytes]]:
        try:
            header = await asyncio.wait_for(
                reader.readexactly(4), timeout=self.settings.read_timeout_seconds
            )
            length = int.from_bytes(header[:3], "little")
            if length > self.settings.max_input_bytes:
                payload = await reader.readexactly(self.settings.max_input_bytes)
                return header[3], payload
            payload = await reader.readexactly(length)
            return header[3], payload
        except (asyncio.TimeoutError, asyncio.IncompleteReadError):
            return None

    @staticmethod
    def _parse_http(raw: bytes) -> Tuple[str, str, str, Dict[str, str], bytes]:
        head, _, body = raw.partition(b"\r\n\r\n")
        lines = head.decode("latin-1", errors="replace").split("\r\n")
        parts = lines[0].split(" ", 2) if lines else []
        method = parts[0][:16] if parts else "UNKNOWN"
        path = parts[1][:2048] if len(parts) > 1 else "/"
        version = parts[2][:32] if len(parts) > 2 else "HTTP/1.1"
        headers: Dict[str, str] = {}
        for line in lines[1:]:
            if ":" in line:
                key, value = line.split(":", 1)
                headers[key.strip().lower()[:100]] = value.strip()[:1000]
        return method, path, version, headers, body

    def _clean_event_content(self, content: str) -> str:
        content = content.replace("\x00", "")
        content = "".join(
            character
            for character in content
            if character in "\r\n\t" or ord(character) >= 32
        )
        return content[: self.settings.max_event_preview_chars]

    @staticmethod
    def _preview(data: bytes) -> str:
        return data.decode("utf-8", errors="replace").replace("\x00", "")[:4096]

    @staticmethod
    def _redact_http_body(value: str) -> str:
        # Preserve useful parameter names while never persisting submitted
        # passwords, session tokens, cookies, or authorization values.
        value = re.sub(
            r"(?i)(password|passwd|pwd|token|secret|api[_-]?key)=([^&\s]+)",
            r"\1=[REDACTED]",
            value,
        )
        value = re.sub(
            r'(?i)("(?:password|passwd|pwd|token|secret|api[_-]?key)"\s*:\s*)"[^"]*"',
            r'\1"[REDACTED]"',
            value,
        )
        return value

    @staticmethod
    def _local_port(writer: asyncio.StreamWriter, fallback: int) -> int:
        sockname = writer.get_extra_info("sockname")
        return int(sockname[1]) if sockname else fallback

    def _connection_finished(self, session_id: str, source_ip: str) -> None:
        self._writers.pop(session_id, None)
        self.brain.forget(session_id)
        self._active_by_ip[source_ip] = max(0, self._active_by_ip[source_ip] - 1)

    def _tls_context(self) -> ssl.SSLContext:
        cert_path, key_path = self._ensure_certificate(self.settings.certificate_dir)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(str(cert_path), str(key_path))
        return context

    @staticmethod
    def _ensure_certificate(directory: Path) -> Tuple[Path, Path]:
        cert_path = directory / "argus-decoy-cert.pem"
        key_path = directory / "argus-decoy-key.pem"
        if cert_path.exists() and key_path.exists():
            return cert_path, key_path
        directory.mkdir(parents=True, exist_ok=True)
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Northstar Finance"),
                x509.NameAttribute(NameOID.COMMON_NAME, "finance-prod.internal.invalid"),
            ]
        )
        now = datetime.now(timezone.utc)
        certificate = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=365))
            .add_extension(
                x509.SubjectAlternativeName(
                    [
                        x509.DNSName("finance-prod.internal.invalid"),
                        x509.DNSName("localhost"),
                    ]
                ),
                critical=False,
            )
            .sign(key, hashes.SHA256())
        )
        key_path.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
        try:
            os.chmod(key_path, 0o600)
        except OSError:
            pass
        return cert_path, key_path

    @staticmethod
    def _login_page(profile: ServiceProfile) -> str:
        product = html.escape(profile.product)
        return f"""<!doctype html><html><head><title>Northstar Finance Portal</title></head>
<body style="font-family:Arial;background:#eef1f4;color:#17202a;padding:60px">
<main style="width:360px;margin:auto;background:white;padding:32px;border:1px solid #ccd3da">
<h2>Finance Operations</h2><p>Sign in to continue.</p>
<form method="post" action="/login"><label>User</label><input name="user" style="display:block;width:100%;margin:6px 0 14px">
<label>Password</label><input type="password" name="password" style="display:block;width:100%;margin:6px 0 18px">
<button type="submit">Sign in</button></form><small>{product}</small></main></body></html>"""

    @staticmethod
    def _mysql_packet(payload: bytes, sequence: int) -> bytes:
        return len(payload).to_bytes(3, "little") + bytes([sequence & 0xFF]) + payload

    @classmethod
    def _mysql_handshake(cls, version: str, salt: bytes) -> bytes:
        capabilities = 0x00088201
        payload = (
            b"\x0a"
            + version.encode()[:60]
            + b"\x00"
            + struct.pack("<I", secrets.randbelow(2**31))
            + salt[:8]
            + b"\x00"
            + struct.pack("<H", capabilities & 0xFFFF)
            + b"\x21"
            + struct.pack("<H", 2)
            + struct.pack("<H", (capabilities >> 16) & 0xFFFF)
            + bytes([21])
            + b"\x00" * 10
            + salt[8:]
            + b"\x00mysql_native_password\x00"
        )
        return cls._mysql_packet(payload, 0)

    @staticmethod
    def _mysql_username(payload: bytes) -> str:
        if len(payload) <= 32:
            return ""
        return payload[32:].split(b"\x00", 1)[0].decode("utf-8", errors="replace")[:128]

    @classmethod
    def _mysql_error(cls, code: int, message: str) -> bytes:
        payload = b"\xff" + struct.pack("<H", code) + b"#42000" + message.encode()[:500]
        return cls._mysql_packet(payload, 1)

    @staticmethod
    def _lenenc(value: bytes) -> bytes:
        if len(value) < 251:
            return bytes([len(value)]) + value
        return b"\xfc" + struct.pack("<H", len(value)) + value

    @classmethod
    def _mysql_text_result(cls, value: str) -> bytes:
        column = b"result"
        definition = b"".join(
            cls._lenenc(item)
            for item in (b"def", b"finance_core", b"", b"", column, column)
        ) + b"\x0c\x21\x00\x00\x04\x00\x00\xfd\x00\x00\x00\x00\x00"
        packets = [
            cls._mysql_packet(b"\x01", 1),
            cls._mysql_packet(definition, 2),
            cls._mysql_packet(b"\xfe\x00\x00\x02\x00", 3),
            cls._mysql_packet(cls._lenenc(value.encode()[:1500]), 4),
            cls._mysql_packet(b"\xfe\x00\x00\x02\x00", 5),
        ]
        return b"".join(packets)

    @staticmethod
    def _severity_rank(value: str) -> int:
        return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}.get(value, 0)
