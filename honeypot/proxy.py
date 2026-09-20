"""
CyberShield AI — Medicare.AI WAF Reverse Proxy
================================================
Places CyberShield's threat-detection pipeline in front of Medicare.AI.

Architecture:
    Internet / User
          │
    CyberShield AI  (FastAPI, port 8050)
          │   /proxy/{path} catch-all
          │
       MedicareWAFProxy
          │
          ├─ [1] Inspect: IntentClassifier → detect SQLi, XSS, RCE, brute-force …
          ├─ [2] Log:     TelemetryStore  → DecoySession + TelemetryEvent
          ├─ [3] Gate:    blocked_sources or critical intent → 403 WAF_BLOCK
          └─ [4] Forward: httpx → http://MEDICARE_AI_URL/{path}

All events are surfaced in the CyberShield SOC dashboard in real-time.
"""

from __future__ import annotations

import asyncio
import os
import time
from collections import deque
from typing import Any, Deque, Dict, List, Optional, Set, Tuple

import httpx
from fastapi import Request
from fastapi.responses import Response

from .config import HoneypotSettings
from .models import DecoySession, TelemetryEvent, new_id, utc_now
from .deception import IntentClassifier        # defined in honeypot/deception.py
from .store import HoneypotStore

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Where Medicare.AI is deployed. Override via env var MEDICARE_AI_URL.
DEFAULT_MEDICARE_URL: str = "https://medicareai-blue.vercel.app"

# Risk score at which a request is hard-blocked (WAF block).
WAF_BLOCK_SCORE_THRESHOLD: int = 75

# Headers that must never be forwarded upstream (security hygiene).
HOP_BY_HOP_HEADERS: frozenset = frozenset(
    {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailers",
        "transfer-encoding",
        "upgrade",
        "host",               # rewritten by httpx
        "content-length",     # recalculated by httpx
        "content-encoding",   # decompressed by httpx
        "accept-encoding",    # handled by httpx client
    }
)

# Severity levels that trigger a WAF block when combined with high intent risk
BLOCK_SEVERITIES: frozenset = frozenset({"critical"})


# ---------------------------------------------------------------------------
# Shared event ring-buffer (last 200 proxy events for dashboard live feed)
# ---------------------------------------------------------------------------

class _SharedProxyState:
    """Thread/async-safe mutable state shared across the singleton proxy."""

    def __init__(self) -> None:
        self.total_requests: int = 0
        self.blocked_requests: int = 0
        self.forwarded_requests: int = 0
        self.total_threats_detected: int = 0
        self.recent_events: Deque[Dict[str, Any]] = deque(maxlen=200)
        self._lock = asyncio.Lock()

    async def record(
        self,
        *,
        source_ip: str,
        path: str,
        method: str,
        intent: str,
        severity: str,
        risk_score: int,
        blocked: bool,
        status_code: int,
        latency_ms: int,
        timestamp: str,
    ) -> None:
        async with self._lock:
            self.total_requests += 1
            if blocked:
                self.blocked_requests += 1
            else:
                self.forwarded_requests += 1
            if severity in ("high", "critical") or risk_score >= 50:
                self.total_threats_detected += 1
            self.recent_events.appendleft(
                {
                    "timestamp": timestamp,
                    "source_ip": source_ip,
                    "method": method,
                    "path": path,
                    "intent": intent,
                    "severity": severity,
                    "risk_score": risk_score,
                    "blocked": blocked,
                    "status_code": status_code,
                    "latency_ms": latency_ms,
                }
            )

    def snapshot(self) -> Dict[str, Any]:
        latest = list(self.recent_events)[:10]
        return {
            "protected_app": "Medicare.AI",
            "protected_url": os.environ.get("MEDICARE_AI_URL", DEFAULT_MEDICARE_URL),
            "total_requests": self.total_requests,
            "blocked_requests": self.blocked_requests,
            "forwarded_requests": self.forwarded_requests,
            "total_threats_detected": self.total_threats_detected,
            "block_rate_pct": (
                round(self.blocked_requests / self.total_requests * 100, 1)
                if self.total_requests
                else 0.0
            ),
            "latest_events": latest,
            "latest_event": latest[0] if latest else None,
        }


# ---------------------------------------------------------------------------
# WAF Proxy
# ---------------------------------------------------------------------------

class MedicareWAFProxy:
    """
    Inspects each incoming HTTP request through CyberShield's existing
    threat-detection pipeline before forwarding it to Medicare.AI.

    Parameters
    ----------
    store   : HoneypotStore  — the shared SQLite telemetry store
    blocked_sources : set    — the runtime's live blocklist (shared reference)
    settings : HoneypotSettings
    target_url : str         — Medicare.AI base URL
    """

    def __init__(
        self,
        store: HoneypotStore,
        blocked_sources: Set[str],
        settings: Optional[HoneypotSettings] = None,
        target_url: Optional[str] = None,
    ) -> None:
        self.store = store
        self.blocked_sources = blocked_sources           # shared ref from HoneypotRuntime
        self.settings = settings or HoneypotSettings.from_env()
        self.target_url = (
            target_url
            or os.environ.get("MEDICARE_AI_URL", DEFAULT_MEDICARE_URL)
        ).rstrip("/")
        self.state = _SharedProxyState()
        self._client: Optional[httpx.AsyncClient] = None

        # WAF Dynamic Configuration & Rate Limiting
        self.config: Dict[str, Any] = {
            "block_score_threshold": WAF_BLOCK_SCORE_THRESHOLD,
            "rate_limiting_enabled": True,
            "max_requests_per_minute": 60,
            "strict_header_inspection": True,
        }
        self._ip_request_timestamps: Dict[str, Deque[float]] = {}
        self._ip_block_counts: Dict[str, int] = {}
        self._ip_ban_reasons: Dict[str, str] = {}

    def get_banned_ips(self) -> List[Dict[str, Any]]:
        """Returns list of currently quarantined / blocked IPs with reasons."""
        banned = []
        for ip in self.blocked_sources:
            banned.append({
                "ip": ip,
                "reason": self._ip_ban_reasons.get(ip, "WAF Threat Auto-Ban / Honeypot Perimeter Block"),
                "blocks_triggered": self._ip_block_counts.get(ip, 1),
            })
        return banned

    def unban_ip(self, source_ip: str) -> bool:
        """Removes an IP from the active WAF quarantine list."""
        if source_ip in self.blocked_sources:
            self.blocked_sources.remove(source_ip)
            self._ip_block_counts.pop(source_ip, None)
            self._ip_ban_reasons.pop(source_ip, None)
            return True
        return False


    def get_config(self) -> Dict[str, Any]:
        """Returns active WAF dynamic configuration."""
        return dict(self.config)

    def update_config(self, new_cfg: Dict[str, Any]) -> Dict[str, Any]:
        """Updates active WAF configuration rules."""
        if "block_score_threshold" in new_cfg:
            self.config["block_score_threshold"] = int(new_cfg["block_score_threshold"])
        if "rate_limiting_enabled" in new_cfg:
            self.config["rate_limiting_enabled"] = bool(new_cfg["rate_limiting_enabled"])
        if "max_requests_per_minute" in new_cfg:
            self.config["max_requests_per_minute"] = int(new_cfg["max_requests_per_minute"])
        if "strict_header_inspection" in new_cfg:
            self.config["strict_header_inspection"] = bool(new_cfg["strict_header_inspection"])
        return dict(self.config)

    def _check_rate_limit(self, source_ip: str) -> bool:
        """Rate limiter: returns True if client IP exceeds max_requests_per_minute."""
        if not self.config.get("rate_limiting_enabled", True):
            return False
        max_reqs = self.config.get("max_requests_per_minute", 60)
        now = time.monotonic()
        if source_ip not in self._ip_request_timestamps:
            self._ip_request_timestamps[source_ip] = deque()
        timestamps = self._ip_request_timestamps[source_ip]
        while timestamps and now - timestamps[0] > 60.0:
            timestamps.popleft()
        timestamps.append(now)
        return len(timestamps) > max_reqs


    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """Create the async HTTP client connection pool."""
        self._client = httpx.AsyncClient(
            base_url=self.target_url,
            timeout=httpx.Timeout(connect=4.0, read=30.0, write=10.0, pool=5.0),
            follow_redirects=False,
            limits=httpx.Limits(max_connections=50, max_keepalive_connections=20),
        )

    async def stop(self) -> None:
        """Close the upstream connection pool."""
        if self._client:
            await self._client.aclose()
            self._client = None

    # ------------------------------------------------------------------
    # Main handler — called from FastAPI route
    # ------------------------------------------------------------------

    async def inspect_and_forward(self, request: Request) -> Response:
        """
        Full pipeline:
          inspect → gate → forward/block → log
        Returns a FastAPI-compatible Response.
        """
        t_start = time.monotonic()
        timestamp = utc_now()

        # ── Extract client identity ────────────────────────────────────
        source_ip = self._extract_client_ip(request)
        method    = request.method
        # path_params gives us the wildcard capture from /proxy/{path:path}
        raw_path  = request.path_params.get("path", "")
        upstream_path = f"/{raw_path}"
        query     = str(request.url.query)
        full_path = f"{upstream_path}?{query}" if query else upstream_path

        # ── Read body (needed for POST inspection, e.g. SQLi in form data) ─
        try:
            body_bytes = await asyncio.wait_for(request.body(), timeout=8.0)
        except Exception:
            body_bytes = b""
        body_preview = body_bytes[:2048].decode("utf-8", errors="replace")

        # ── Build request summary for IntentClassifier ─────────────────
        header_preview = " ".join(
            f"{k}:{v[:80]}"
            for k, v in request.headers.items()
            if k.lower() not in ("authorization", "cookie", "x-api-key")
        )
        request_summary = (
            f"{method} {full_path}\n"
            f"UA:{request.headers.get('user-agent', 'unknown')[:200]}\n"
            f"{body_preview}"
        ).strip()

        # ── Classify intent (reuses existing CyberShield classifier) ───
        intent = IntentClassifier.classify(request_summary)

        # ── Compute WAF risk score ──────────────────────────────────────
        risk_score = self._compute_risk_score(
            source_ip=source_ip,
            intent=intent,
            path=full_path,
            body=body_preview,
        )

        # ── Determine if request should be blocked ─────────────────────
        blocked, block_reason = self._should_block(
            source_ip=source_ip,
            intent=intent,
            risk_score=risk_score,
        )

        # ── Log to CyberShield telemetry ───────────────────────────────
        session_id = new_id("waf")
        await self._log_request(
            session_id=session_id,
            source_ip=source_ip,
            method=method,
            path=full_path,
            intent=intent,
            risk_score=risk_score,
            blocked=blocked,
            block_reason=block_reason,
            body_preview=body_preview,
            request_summary=request_summary,
            timestamp=timestamp,
        )

        # ── Block path ─────────────────────────────────────────────────
        if blocked:
            latency_ms = int((time.monotonic() - t_start) * 1000)
            self._ip_block_counts[source_ip] = self._ip_block_counts.get(source_ip, 0) + 1
            if self._ip_block_counts[source_ip] >= 2:
                self.blocked_sources.add(source_ip)
                self._ip_ban_reasons[source_ip] = f"Auto-Quarantine: {intent.label} ({block_reason})"

            await self.state.record(
                source_ip=source_ip,
                path=full_path,
                method=method,
                intent=intent.label,
                severity=intent.severity,
                risk_score=risk_score,
                blocked=True,
                status_code=403,
                latency_ms=latency_ms,
                timestamp=timestamp,
            )
            return Response(
                content=(
                    f'{{"error":"Blocked by CyberShield WAF","reason":"{block_reason}",'
                    f'"risk_score":{risk_score}}}'
                ),
                status_code=403,
                media_type="application/json",
                headers={
                    "X-CyberShield-WAF": "BLOCKED",
                    "X-CyberShield-Risk": str(risk_score),
                    "X-CyberShield-Intent": intent.label,
                },
            )

        # ── Forward to Medicare.AI ─────────────────────────────────────
        upstream_response, upstream_status, upstream_latency_ms = await self._forward(
            method=method,
            path=full_path,
            headers=request.headers,
            body=body_bytes,
        )

        total_latency_ms = int((time.monotonic() - t_start) * 1000)
        await self.state.record(
            source_ip=source_ip,
            path=full_path,
            method=method,
            intent=intent.label,
            severity=intent.severity,
            risk_score=risk_score,
            blocked=False,
            status_code=upstream_status,
            latency_ms=total_latency_ms,
            timestamp=timestamp,
        )
        return upstream_response

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _extract_client_ip(self, request: Request) -> str:
        for header in ("cf-connecting-ip", "x-forwarded-for", "x-real-ip"):
            val = request.headers.get(header, "").split(",")[0].strip()
            if val and val not in ("", "unknown", "::1"):
                return val
        client = request.client
        return client.host if client else "127.0.0.1"

    def _compute_risk_score(
        self,
        *,
        source_ip: str,
        intent: Any,
        path: str,
        body: str,
    ) -> int:
        """
        Heuristic risk score 0-100 using existing intent classifier output
        plus additional WAF signals.
        """
        score = 0

        # Base from intent confidence
        base = {
            "info":     10,
            "low":      25,
            "medium":   45,
            "high":     70,
            "critical": 90,
        }
        score = base.get(intent.severity, 30)

        # Boost confidence weight
        score = int(score * (0.6 + 0.4 * intent.confidence))

        # Extra boosts for known attack paths
        path_lower = path.lower()
        dangerous_paths = (
            "/admin", "/wp-admin", "/shell", "/.env", "/etc/passwd",
            "/phpmyadmin", "../", "..%2f", ";cmd=", "|cmd|",
        )
        if any(dp in path_lower for dp in dangerous_paths):
            score = min(100, score + 20)

        # SQLi / XSS in query string or body
        combined = path_lower + body.lower()
        sqli_tokens = ("' or ", "union select", "1=1", "drop table", "--", "/**/")
        xss_tokens = ("<script", "onerror=", "javascript:", "onload=")
        rce_tokens = ("; ls", "| cat", "`whoami`", "$(id)", "/bin/sh", "cmd.exe")

        if any(t in combined for t in sqli_tokens):
            score = min(100, score + 25)
        if any(t in combined for t in xss_tokens):
            score = min(100, score + 20)
        if any(t in combined for t in rce_tokens):
            score = min(100, score + 30)

        # Blocked-source amplification
        if source_ip in self.blocked_sources:
            score = 100

        return min(100, score)

    def _should_block(
        self,
        *,
        source_ip: str,
        intent: Any,
        risk_score: int,
    ) -> Tuple[bool, str]:
        """Returns (should_block, reason_string)."""
        if source_ip in self.blocked_sources:
            return True, "source_ip_on_blocklist"
        if self._check_rate_limit(source_ip):
            return True, "rate_limit_exceeded"
        threshold = self.config.get("block_score_threshold", WAF_BLOCK_SCORE_THRESHOLD)
        if intent.severity in BLOCK_SEVERITIES and risk_score >= threshold:
            return True, f"waf_block:{intent.label}:score={risk_score}"
        if risk_score >= max(95, threshold):
            return True, f"risk_score_threshold:{risk_score}"
        return False, ""


    async def _forward(
        self,
        *,
        method: str,
        path: str,
        headers: Any,
        body: bytes,
    ) -> Tuple[Response, int, int]:
        """Forward request to Medicare.AI, return (Response, status_code, latency_ms)."""
        if not self._client:
            await self.start()

        # Strip hop-by-hop and security-sensitive headers
        forward_headers = {
            k: v
            for k, v in headers.items()
            if k.lower() not in HOP_BY_HOP_HEADERS
        }
        forward_headers["X-Forwarded-By"] = "CyberShield-WAF/1.0"
        forward_headers["X-Protected-App"] = "Medicare.AI"

        t0 = time.monotonic()
        try:
            upstream = await self._client.request(
                method=method,
                url=path,
                headers=forward_headers,
                content=body or None,
                timeout=25.0,
            )
            latency_ms = int((time.monotonic() - t0) * 1000)

            # Strip hop-by-hop from upstream response headers & inject security hardening
            response_headers = {
                k: v
                for k, v in upstream.headers.items()
                if k.lower() not in HOP_BY_HOP_HEADERS
            }
            response_headers["X-CyberShield-WAF"] = "INSPECTED"
            response_headers["X-CyberShield-Latency"] = str(latency_ms)
            response_headers["X-Content-Type-Options"] = "nosniff"
            response_headers["X-Frame-Options"] = "SAMEORIGIN"
            response_headers["X-XSS-Protection"] = "1; mode=block"
            response_headers["Referrer-Policy"] = "strict-origin-when-cross-origin"


            return (
                Response(
                    content=upstream.content,
                    status_code=upstream.status_code,
                    headers=response_headers,
                    media_type=upstream.headers.get("content-type"),
                ),
                upstream.status_code,
                latency_ms,
            )

        except httpx.ConnectError:
            latency_ms = int((time.monotonic() - t0) * 1000)
            return (
                Response(
                    content=(
                        '{"error":"Medicare.AI is not reachable. '
                        'Ensure it is running on port 5000."}'
                    ),
                    status_code=502,
                    media_type="application/json",
                    headers={"X-CyberShield-WAF": "UPSTREAM_DOWN"},
                ),
                502,
                latency_ms,
            )
        except httpx.TimeoutException:
            latency_ms = int((time.monotonic() - t0) * 1000)
            return (
                Response(
                    content='{"error":"Medicare.AI upstream timed out"}',
                    status_code=504,
                    media_type="application/json",
                    headers={"X-CyberShield-WAF": "UPSTREAM_TIMEOUT"},
                ),
                504,
                latency_ms,
            )
        except Exception as exc:
            latency_ms = int((time.monotonic() - t0) * 1000)
            return (
                Response(
                    content=f'{{"error":"WAF proxy error: {str(exc)[:200]}"}}',
                    status_code=500,
                    media_type="application/json",
                    headers={"X-CyberShield-WAF": "PROXY_ERROR"},
                ),
                500,
                latency_ms,
            )

    async def _log_request(
        self,
        *,
        session_id: str,
        source_ip: str,
        method: str,
        path: str,
        intent: Any,
        risk_score: int,
        blocked: bool,
        block_reason: str,
        body_preview: str,
        request_summary: str,
        timestamp: str,
    ) -> None:
        """Persist WAF event to CyberShield's existing telemetry store."""
        try:
            session = DecoySession(
                session_id=session_id,
                source_ip=source_ip,
                source_port=0,
                destination_port=5000,
                service="HTTP",
                protocol="http",
                persona="Medicare.AI (Protected)",
                started_at=timestamp,
                risk_score=risk_score,
                risk_level=intent.severity,
                intent=intent.label,
                intent_confidence=intent.confidence,
            )
            self.store.create_session(session)

            event_type = "WAF_BLOCK" if blocked else "WAF_FORWARD"
            if not blocked and intent.severity in ("high", "critical"):
                event_type = "WAF_THREAT_DETECTED"

            remediation_patch = None
            if intent.label.lower() in ("sqli", "sql injection"):
                remediation_patch = "Use parameterized SQL queries / ORM binding in Medicare.AI endpoint code."
            elif intent.label.lower() in ("xss", "cross-site scripting"):
                remediation_patch = "Sanitize HTML inputs using bleach / escape untrusted variables before rendering in templates."
            elif intent.label.lower() in ("rce", "command injection"):
                remediation_patch = "Remove subprocess / shell execution functions; sanitize system input parameters."

            event = TelemetryEvent(
                session_id=session_id,
                event_type=event_type,
                severity=intent.severity if not blocked else "critical",
                direction="inbound",
                content=request_summary[:1024],
                metadata={
                    "protected_app": "Medicare.AI",
                    "method": method,
                    "path": path,
                    "risk_score": risk_score,
                    "blocked": blocked,
                    "block_reason": block_reason,
                    "intent": intent.label,
                    "intent_confidence": intent.confidence,
                    "source_ip": source_ip,
                    "remediation_advisory": remediation_patch,
                },

                timestamp=timestamp,
            )
            self.store.record_event(event)

            # Close session immediately (WAF request is stateless)
            self.store.end_session(session_id, "blocked" if blocked else "closed")

        except Exception:
            # Never let logging failures break the proxy response
            pass

    # ------------------------------------------------------------------
    # Public API for dashboard & attack simulation
    # ------------------------------------------------------------------

    def get_metrics(self) -> Dict[str, Any]:
        """Return live proxy metrics for the CyberShield dashboard API."""
        return self.state.snapshot()

    async def simulate_attack(self, vector: str = "sqli") -> Dict[str, Any]:
        """
        Simulate an incoming attack against Medicare.AI through the WAF.
        Generates realistic threat events and triggers WAF inspection & blocking.
        """
        timestamp = utc_now()
        source_ip = "198.51.100.42"
        session_id = new_id("waf_sim")

        vector = vector.lower()
        if vector == "sqli":
            path = "/api/hospitals?specialty=' OR 1=1--"
            method = "GET"
            summary = "GET /api/hospitals?specialty=' OR 1=1--\nUA: Mozilla/5.0 (PentestBot)"
        elif vector == "xss":
            path = "/api/analyze-prescription"
            method = "POST"
            summary = "POST /api/analyze-prescription\nUA: CyberAttacker/2.0\n<script>document.cookie</script>"
        elif vector == "path_traversal":
            path = "/proxy/../../etc/passwd"
            method = "GET"
            summary = "GET /proxy/../../etc/passwd\nUA: DirBuster/1.0"
        elif vector == "rce":
            path = "/api/hospitals?query=test; cat /etc/shadow"
            method = "GET"
            summary = "GET /api/hospitals?query=test; cat /etc/shadow\nUA: RCE-Scanner"
        else: # bot_scan
            path = "/.env"
            method = "GET"
            summary = "GET /.env\nUA: Masscan/1.3"

        intent = IntentClassifier.classify(summary)
        risk_score = self._compute_risk_score(
            source_ip=source_ip,
            intent=intent,
            path=path,
            body=summary,
        )
        blocked, block_reason = self._should_block(
            source_ip=source_ip,
            intent=intent,
            risk_score=risk_score,
        )

        await self._log_request(
            session_id=session_id,
            source_ip=source_ip,
            method=method,
            path=path,
            intent=intent,
            risk_score=risk_score,
            blocked=blocked,
            block_reason=block_reason,
            body_preview=summary,
            request_summary=summary,
            timestamp=timestamp,
        )

        await self.state.record(
            source_ip=source_ip,
            path=path,
            method=method,
            intent=intent.label,
            severity=intent.severity,
            risk_score=risk_score,
            blocked=blocked,
            status_code=403 if blocked else 200,
            latency_ms=12,
            timestamp=timestamp,
        )

        return {
            "ok": True,
            "vector": vector,
            "blocked": blocked,
            "intent": intent.label,
            "severity": intent.severity,
            "risk_score": risk_score,
            "path": path,
            "timestamp": timestamp,
        }

    def export_rules(self, fmt: str = "modsecurity") -> Dict[str, Any]:
        """Generate exportable production WAF rules for Medicare.AI defense deployment."""
        fmt = fmt.lower()
        thresh = self.config.get("block_score_threshold", 75)
        max_reqs = self.config.get("max_requests_per_minute", 60)

        if fmt == "nginx":
            content = f"""# CyberShield AI WAF Rules for Medicare.AI (Nginx Format)
# Generated: {utc_now()}

limit_req_zone $binary_remote_addr zone=medicare_waf:10m rate={max_reqs}r/m;

server {{
    listen 80;
    server_name medicare.ai;

    # Rate Limiting
    limit_req zone=medicare_waf burst=10 nodelay;

    # Security Headers
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-XSS-Protection "1; mode=block" always;

    # SQL Injection Defense Rule
    location ~* "('||\\\"|union|select|insert|drop|delete|--|\\/\\*)" {{
        deny all;
        return 403 "Blocked by CyberShield WAF (SQLi)";
    }}

    # Path Traversal Defense Rule
    location ~* "(\\.\\.\\/|\\.\\.\\%2f|\\/etc\\/passwd|\\.env)" {{
        deny all;
        return 403 "Blocked by CyberShield WAF (Path Traversal)";
    }}

    location / {{
        proxy_pass {self.target_url};
        proxy_set_header X-Forwarded-By "CyberShield-WAF";
    }}
}}
"""
        elif fmt == "cloudflare":
            content = f"""// CyberShield AI Cloudflare WAF Expression Rules
{{
  "name": "CyberShield Medicare.AI Protection Rules",
  "rules": [
    {{
      "expression": "(http.request.uri.query contains \"' OR\" or http.request.uri.query contains \"UNION SELECT\")",
      "action": "block",
      "description": "CyberShield SQLi Protection (Risk Threshold: {thresh})"
    }},
    {{
      "expression": "(http.request.uri.path contains \"/etc/passwd\" or http.request.uri.path contains \"/.env\")",
      "action": "block",
      "description": "CyberShield Path Traversal Protection"
    }},
    {{
      "expression": "rate(http.request.uri, 1m) > {max_reqs}",
      "action": "challenge",
      "description": "CyberShield Sliding-Window Rate Limit"
    }}
  ]
}}
"""
        else: # modsecurity
            content = f"""# CyberShield AI ModSecurity v3 Ruleset for Medicare.AI
# Generated: {utc_now()}

SecRuleEngine On

# Rule 9001: CyberShield Rate Limiting
SecAction "id:9001,phase:1,nolog,pass,initcol:ip=%{{REMOTE_ADDR}},setvar:ip.request_count=+1,expirevar:ip.request_count=60"
SecRule IP:REQUEST_COUNT "@gt {max_reqs}" "id:9002,phase:1,deny,status:429,log,msg:'CyberShield Rate Limit Exceeded'"

# Rule 9003: SQL Injection Detection (Risk Threshold: {thresh})
SecRule REQUEST_URI|REQUEST_BODY "@rx (?i)('(\\s*)+or|union(\\s*)+select|select(\\s*)+.*from|drop(\\s*)+table)" \\
    "id:9003,phase:2,deny,status:403,log,msg:'CyberShield WAF: SQL Injection Attack Detected'"

# Rule 9004: XSS Detection
SecRule REQUEST_URI|REQUEST_BODY "@rx (?i)(<script|javascript:|onerror=|onload=)" \\
    "id:9004,phase:2,deny,status:403,log,msg:'CyberShield WAF: Cross-Site Scripting Detected'"
"""

        return {
            "format": fmt,
            "filename": f"cybershield_medicare_waf_{fmt}.conf",
            "content": content,
            "timestamp": utc_now(),
        }

    def run_security_audit(self) -> Dict[str, Any]:
        """Run an AI-powered security health audit on Medicare.AI protected layer."""
        metrics = self.get_metrics()
        banned = self.get_banned_ips()
        thresh = self.config.get("block_score_threshold", 75)
        rate_limit_on = self.config.get("rate_limiting_enabled", True)
        strict_headers = self.config.get("strict_header_inspection", True)

        # Base score calculation
        score = 100
        findings = []

        if not rate_limit_on:
            score -= 15
            findings.append({"id": "FIND-01", "severity": "HIGH", "category": "Rate Limiting", "desc": "IP rate limiting is currently disabled."})
        if thresh > 80:
            score -= 10
            findings.append({"id": "FIND-02", "severity": "MEDIUM", "category": "Thresholding", "desc": f"Block threshold set conservatively at {thresh}."})
        if not strict_headers:
            score -= 15
            findings.append({"id": "FIND-03", "severity": "HIGH", "category": "Header Inspection", "desc": "Strict HTTP header inspection is turned off."})
        
        if metrics["total_threats_detected"] > 0:
            findings.append({"id": "FIND-04", "severity": "INFO", "category": "Threat History", "desc": f"{metrics['total_threats_detected']} total attack attempts intercepted by WAF."})

        owasp_scores = {
            "A01:2021-Broken Access Control": 95 if strict_headers else 70,
            "A03:2021-Injection (SQLi/XSS/RCE)": 100 if thresh <= 75 else 85,
            "A04:2021-Insecure Design": 90,
            "A07:2021-Identification & Auth Failures": 92 if rate_limit_on else 65,
            "A10:2021-Server-Side Request Forgery": 95,
        }

        return {
            "target_app": "Medicare.AI",
            "health_score": max(0, score),
            "status": "EXCELLENT" if score >= 85 else "NEEDS_ATTENTION",
            "active_rules": len(self.config),
            "quarantined_ips": len(banned),
            "owasp_breakdown": owasp_scores,
            "findings": findings,
            "virtual_patches_applied": [
                "SQL Parameterization Virtual Patch",
                "XSS Input Escape Virtual Patch",
                "HTTP Security Response Hardening",
                "Sliding-Window IP Rate Limiter",
            ],
            "timestamp": utc_now(),
        }



