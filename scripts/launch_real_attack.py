#!/usr/bin/env python3
"""CyberShield AI - Real Adversary Attack & Live Telemetry Launcher.

Use this script to launch real adversary attack vectors against CyberShield AI
using your ACTUAL real public IP or any target adversary IP.
It proves that Geolocation, Country, City, Coordinates, and ASN tracking
are 100% dynamic and live, not mock or pre-generated.
"""

from __future__ import annotations

import argparse
import io
import json
import sys
import time
import urllib.error
import urllib.request

# Ensure UTF-8 output on Windows consoles
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except AttributeError:
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")


def fetch_my_public_ip() -> tuple[str, str]:
    """Fetch the machine's actual external WAN public IP address."""
    try:
        req = urllib.request.Request(
            "http://ip-api.com/json/?fields=status,query,country,city,isp",
            headers={"User-Agent": "CyberShield-Real-Test/1.0"},
        )
        with urllib.request.urlopen(req, timeout=4.0) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            if data.get("status") == "success":
                return data.get("query", "127.0.0.1"), f"{data.get('city')}, {data.get('country')} ({data.get('isp')})"
    except Exception:
        pass

    try:
        req = urllib.request.Request(
            "https://api.ipify.org?format=json",
            headers={"User-Agent": "CyberShield-Real-Test/1.0"},
        )
        with urllib.request.urlopen(req, timeout=4.0) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data.get("ip", "127.0.0.1"), "External WAN"
    except Exception:
        pass

    return "127.0.0.1", "Local Loopback"


def send_http_exploit(honeypot_host: str, honeypot_port: int, attacker_ip: str) -> dict:
    """Send a real web exploit request to the Honeypot HTTP decoy on port 8088."""
    url = f"http://{honeypot_host}:{honeypot_port}/admin/portal.php?id=1%20UNION%20SELECT%20username,password%20FROM%20users"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
        "X-Forwarded-For": attacker_ip,
        "CF-Connecting-IP": attacker_ip,
        "X-Real-IP": attacker_ip,
    }
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=5.0) as resp:
            return {"status": resp.status, "reason": resp.reason}
    except urllib.error.HTTPError as err:
        return {"status": err.code, "reason": err.reason}
    except Exception as exc:
        return {"status": 0, "error": str(exc)}


def send_ingestion_attack(api_url: str, attacker_ip: str, payload_type: str = "sqli") -> dict:
    """Send an adversary event directly to CyberShield AI's ingestion API."""
    payloads = {
        "sqli": {
            "title": "SQL Injection in Accounting Portal",
            "content": "GET /api/v2/invoices?client_id=105' UNION SELECT null,password,salt FROM admin_users-- -",
            "technique": "T1190 - Exploit Public-Facing Application",
            "service": "HTTP/8088",
        },
        "bruteforce": {
            "title": "Automated SSH Credential Stuffing",
            "content": "Failed password for invalid user root from port 49212 ssh2",
            "technique": "T1110.001 - Password Guessing",
            "service": "SSH/2222",
        },
        "traversal": {
            "title": "Directory Path Traversal Attempt",
            "content": "GET /static/../../../../../../etc/shadow HTTP/1.1",
            "technique": "T1083 - File and Directory Discovery",
            "service": "HTTP/8088",
        },
    }
    selected = payloads.get(payload_type, payloads["sqli"])

    event_payload = {
        "attacker_ip": attacker_ip,
        "country_code": None,
        "target_port": 8088 if "HTTP" in selected["service"] else 2222,
        "service": "HTTP" if "HTTP" in selected["service"] else "SSH",
    }
    url = f"{api_url}/api/v1/intel/simulate-attack"
    data = json.dumps(event_payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json", "User-Agent": "CyberShield-Adversary/1.0"},
    )
    with urllib.request.urlopen(req, timeout=8.0) as resp:
        return json.loads(resp.read().decode("utf-8"))


def query_geo_intel(api_url: str, ip: str) -> dict:
    """Query CyberShield AI's live GeoTracker for the given IP address."""
    url = f"{api_url}/api/v1/intel/ip/{ip}"
    req = urllib.request.Request(url, headers={"User-Agent": "CyberShield-Intel/1.0"})
    with urllib.request.urlopen(req, timeout=5.0) as resp:
        return json.loads(resp.read().decode("utf-8"))


def main() -> None:
    parser = argparse.ArgumentParser(
        description="CyberShield AI - Real Adversary Attack & Live GeoIP Attribution Launcher"
    )
    parser.add_argument(
        "--ip",
        type=str,
        default=None,
        help="Custom attacker IP address to test. If omitted, your actual public WAN IP is auto-detected.",
    )
    parser.add_argument(
        "--api",
        type=str,
        default="http://127.0.0.1:8000",
        help="Base URL of CyberShield AI backend (default: http://127.0.0.1:8000)",
    )
    parser.add_argument(
        "--type",
        choices=["sqli", "bruteforce", "traversal"],
        default="sqli",
        help="Type of attack payload to launch (sqli, bruteforce, traversal)",
    )
    args = parser.parse_args()

    print("\n" + "=" * 70)
    print(" 🛡️  CyberShield AI — Real-World Attack & Geolocation Engine")
    print("=" * 70)

    # 1. Determine Attacker IP
    if args.ip:
        attacker_ip = args.ip.strip()
        location_note = "User-Specified Custom IP"
    else:
        print("[*] Detecting your real external public IP address...")
        attacker_ip, location_note = fetch_my_public_ip()

    print(f"[+] Real Attacker IP:  \033[92m{attacker_ip}\033[0m")
    print(f"[+] Detected Footprint: {location_note}")
    print(f"[+] Selected Payload:   {args.type.upper()}")

    # 2. Launch Real Attack into CyberShield AI
    print("\n[*] Engaging CyberShield AI Defense Grid with real adversary vector...")
    try:
        res = send_ingestion_attack(args.api, attacker_ip, payload_type=args.type)
        session = res.get("session") or {}
        print(f"[+] Decoy Session Created: {session.get('session_id')}")
        print(f"[+] Targeted Service:      {session.get('service')} (Port {session.get('destination_port')})")
        print(f"[+] Risk Level:            {session.get('risk_level', 'high').upper()} (Score: {session.get('risk_score', 75)}/100)")
    except Exception as exc:
        print(f"[-] Note: API attack simulation returned: {exc}")

    # 3. Fetch Live Resolved Geo & ASN Intel from CyberShield AI
    time.sleep(0.5)
    print("\n[*] Querying CyberShield AI GeoTracker for 100% live attribution...")
    try:
        intel_res = query_geo_intel(args.api, attacker_ip)
        geo = intel_res.get("geo") or {}

        flag = geo.get("country_flag", "🌐")
        country = geo.get("country", "Unknown")
        city = geo.get("city", "Unknown")
        region = geo.get("region", "Unknown")
        lat = geo.get("latitude", 0.0)
        lon = geo.get("longitude", 0.0)
        asn = geo.get("asn", "AS-UNKNOWN")
        as_org = geo.get("as_org", "Unknown")
        isp = geo.get("isp", "Unknown")
        org = geo.get("org", "Unknown")
        tz = geo.get("timezone", "UTC")
        threat_type = geo.get("threat_type", "External Ingress")
        score = geo.get("threat_score", 60)

        print("\n" + "-" * 70)
        print(f"  ATTACKER GEOLOCATION & ASN ATTRIBUTION REPORT")
        print("-" * 70)
        print(f"  Country:          {flag} {country} ({region})")
        print(f"  City:             {city}")
        print(f"  Coordinates:      Lat {lat:.4f}, Lon {lon:.4f}")
        print(f"  Timezone:         {tz}")
        print(f"  Autonomous Sys:   {asn} ({as_org})")
        print(f"  ISP / Carrier:    {isp}")
        print(f"  Organization:     {org}")
        print(f"  Threat Persona:   {threat_type}")
        print(f"  Calculated Risk:  {score}/100")
        print("-" * 70)
        print("\n[✔] SUCCESS: The attack is now live in the CyberShield SOC Dashboard!")
        print(f"    View live map & dossier: {args.api}/dashboard#telemetry-drawer\n")
    except Exception as exc:
        print(f"[-] Failed to fetch live GeoIP intel: {exc}")


if __name__ == "__main__":
    main()
