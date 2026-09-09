#!/usr/bin/env python3
"""ARGUS SOC Log Collector — entry point."""

import sys


def main():
    print("ARGUS SOC + Gemini Deception Grid")
    print("  API Backend:")
    print("    - FastAPI: Ai/backend/api_server.py")
    print("  Collectors:")
    print("    - Windows: collector/win/collector.py")
    print("    - Windows Firewall: collector/win/firewall_collector.py")
    print("    - Linux: collector/linux/collector.py")
    print("    - Linux Firewall: collector/linux/firewall_collector.py")
    print("  Producer: producer/producer_.py")
    print("  Deception grid:")
    print("    - SSH sensor: 2222")
    print("    - Telnet: 2323")
    print("    - HTTP: 8088")
    print("    - HTTPS: 8443")
    print("    - MySQL: 33060")
    print()
    print("Run a collector directly, e.g.:")
    print("  python collector/linux/collector.py")
    print("  python collector/win/collector.py")
    print("Run the API, e.g.:")
    print("  uvicorn Ai.backend.api_server:app --reload")
    print("Run the five-port deception grid directly:")
    print("  python -m honeypot")
    print("Dashboard:")
    print("  http://127.0.0.1:8000/dashboard")


if __name__ == "__main__":
    sys.exit(main())
