#!/usr/bin/env python3
"""
VALENS.AI — Security Operations. Deception. Intelligence
Phase 1: Honeypot Sentinel Grid Launcher.
"""

import sys
import uvicorn

if __name__ == "__main__":
    port = 8050
    print("=" * 60)
    print("VALENS.AI — Security Operations. Deception. Intelligence")
    print("Phase 1: Honeypot Sentinel Grid")
    print(f"[*] Starting multi-port decoy listeners & dashboard on port {port}...")
    print(f"[*] Live Dashboard URL: http://127.0.0.1:{port}/dashboard")
    print("=" * 60)
    uvicorn.run("honeypot.server:app", host="0.0.0.0", port=port, reload=True)
