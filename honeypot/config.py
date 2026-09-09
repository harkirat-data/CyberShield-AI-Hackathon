"""Configuration for the ARGUS deception grid."""

from __future__ import annotations

import os
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Tuple

try:
    from dotenv import load_dotenv
except ImportError:  # pragma: no cover - dependency is optional at runtime
    def load_dotenv(*args: object, **kwargs: object) -> bool:
        return False


# Load project-local settings before HoneypotSettings or the Gemini engine read
# the process environment. This makes a real `.env` file work for Uvicorn while
# still allowing explicitly exported environment variables to take precedence.
load_dotenv(override=False)


@dataclass(frozen=True)
class ServiceProfile:
    """A network-facing decoy service."""

    key: str
    name: str
    protocol: str
    port: int
    public_port: int
    product: str
    persona: str


def default_services() -> Tuple[ServiceProfile, ...]:
    """Return the five deliberately exposed decoy services."""

    return (
        ServiceProfile(
            key="ssh",
            name="SSH",
            protocol="ssh",
            port=2222,
            public_port=22,
            product="OpenSSH 8.9p1 Ubuntu-3ubuntu0.6",
            persona="finance-prod shell gateway",
        ),
        ServiceProfile(
            key="telnet",
            name="Telnet",
            protocol="telnet",
            port=2323,
            public_port=23,
            product="Ubuntu 22.04 serial console",
            persona="legacy backup appliance",
        ),
        ServiceProfile(
            key="http",
            name="HTTP",
            protocol="http",
            port=8088,
            public_port=80,
            product="Apache/2.4.52 (Ubuntu)",
            persona="internal finance portal",
        ),
        ServiceProfile(
            key="https",
            name="HTTPS",
            protocol="https",
            port=8443,
            public_port=443,
            product="nginx/1.22.1",
            persona="operations API gateway",
        ),
        ServiceProfile(
            key="mysql",
            name="MySQL",
            protocol="mysql",
            port=33060,
            public_port=3306,
            product="MySQL 8.0.33",
            persona="finance reporting database",
        ),
    )


def _flag(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass
class HoneypotSettings:
    """Runtime safety limits and paths.

    Loopback is the safe default.  Bind to ``0.0.0.0`` only inside an isolated
    decoy host or container with egress denied.
    """

    bind_host: str = "127.0.0.1"
    database_path: Path = Path("logs/argus_honeypot.db")
    certificate_dir: Path = Path("logs/certs")
    enable_gemini: bool = True
    autostart: bool = False
    read_timeout_seconds: float = 90.0
    ai_timeout_seconds: float = 12.0
    min_response_delay_seconds: float = 1.25
    max_response_delay_seconds: float = 2.75
    session_timeout_seconds: float = 1800.0
    max_sessions_per_ip: int = 8
    max_interactions_per_session: int = 64
    max_input_bytes: int = 16_384
    max_event_preview_chars: int = 4_096
    max_ai_output_chars: int = 2_000
    services: Tuple[ServiceProfile, ...] = default_services()

    @classmethod
    def from_env(cls) -> "HoneypotSettings":
        port_variables = {
            "ssh": "HONEYPOT_SSH_PORT",
            "telnet": "HONEYPOT_TELNET_PORT",
            "http": "HONEYPOT_HTTP_PORT",
            "https": "HONEYPOT_HTTPS_PORT",
            "mysql": "HONEYPOT_MYSQL_PORT",
        }
        services = tuple(
            replace(
                profile,
                port=int(os.environ.get(port_variables[profile.key], profile.port)),
            )
            for profile in default_services()
        )
        minimum_delay = max(
            0.0, float(os.environ.get("HONEYPOT_MIN_RESPONSE_DELAY", "1.25"))
        )
        maximum_delay = max(
            minimum_delay,
            float(os.environ.get("HONEYPOT_MAX_RESPONSE_DELAY", "2.75")),
        )
        return cls(
            bind_host=os.environ.get("HONEYPOT_BIND_HOST", "127.0.0.1"),
            database_path=Path(
                os.environ.get("HONEYPOT_DB_PATH", "logs/argus_honeypot.db")
            ),
            certificate_dir=Path(
                os.environ.get("HONEYPOT_CERT_DIR", "logs/certs")
            ),
            enable_gemini=_flag("HONEYPOT_USE_GEMINI", True),
            autostart=_flag("HONEYPOT_AUTOSTART", False),
            read_timeout_seconds=float(
                os.environ.get("HONEYPOT_READ_TIMEOUT", "90")
            ),
            ai_timeout_seconds=float(os.environ.get("HONEYPOT_AI_TIMEOUT", "12")),
            min_response_delay_seconds=minimum_delay,
            max_response_delay_seconds=maximum_delay,
            session_timeout_seconds=float(
                os.environ.get("HONEYPOT_SESSION_TIMEOUT", "1800")
            ),
            max_sessions_per_ip=int(
                os.environ.get("HONEYPOT_MAX_SESSIONS_PER_IP", "8")
            ),
            max_interactions_per_session=int(
                os.environ.get("HONEYPOT_MAX_INTERACTIONS", "64")
            ),
            max_input_bytes=int(os.environ.get("HONEYPOT_MAX_INPUT_BYTES", "16384")),
            max_event_preview_chars=int(
                os.environ.get("HONEYPOT_MAX_EVENT_PREVIEW", "4096")
            ),
            max_ai_output_chars=int(
                os.environ.get("HONEYPOT_MAX_AI_OUTPUT", "2000")
            ),
            services=services,
        )
