"""ARGUS Gemini deception grid.

The package exposes an isolated five-service honeypot runtime.  It simulates
services and records attacker interaction; it never executes received input.
"""

from .config import HoneypotSettings, ServiceProfile, default_services
from .runtime import HoneypotRuntime
from .store import TelemetryStore

__all__ = [
    "HoneypotRuntime",
    "HoneypotSettings",
    "ServiceProfile",
    "TelemetryStore",
    "default_services",
]
