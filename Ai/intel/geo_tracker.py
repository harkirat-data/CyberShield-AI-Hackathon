"""Geolocation and ASN Intelligence Engine for CyberShield AI.

Provides resilient IP address attribution:
- Country name and Unicode national flag emoji (e.g. 🇩🇪, 🇺🇸, 🇨🇳)
- City and Region / State
- Geographic Coordinates (Latitude, Longitude) for map visualization
- Autonomous System Number (ASN, e.g. AS15169 Google LLC, AS208323 Tor)
- ISP and Network Organization
- Private/Bogon/Loopback network detection
- Thread-safe in-memory caching to eliminate redundant lookups
"""

from __future__ import annotations

import ipaddress
import json
import logging
import re
import threading
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("cybershield.intel.geo")

# Mapping of known country codes to Flag Emoji
def country_code_to_flag(code: Optional[str]) -> str:
    """Convert ISO 3166-1 alpha-2 country code to Unicode flag emoji."""
    if not code or len(code) != 2:
        return "🌐"
    code = code.upper()
    try:
        # Regional Indicator Symbols: 'A' -> 0x1F1E6
        return chr(ord(code[0]) + 127397) + chr(ord(code[1]) + 127397)
    except Exception:
        return "🌐"


@dataclass
class GeoIntel:
    ip: str
    country: str = "Unknown"
    country_code: str = "XX"
    country_flag: str = "🌐"
    region: str = "Unknown"
    city: str = "Unknown"
    postal: str = ""
    latitude: float = 0.0
    longitude: float = 0.0
    asn: str = "AS-UNKNOWN"
    as_org: str = "Unknown Organization"
    isp: str = "Unknown ISP"
    org: str = "Unknown Org"
    timezone: str = "UTC"
    is_private: bool = False
    threat_type: str = "Standard Ingress"
    threat_score: int = 20

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# Pre-populated realistic threat intelligence for common demo/testing IPs
KNOWN_THREAT_ACTORS: Dict[str, Dict[str, Any]] = {
    "185.220.101.5": {
        "country": "Germany",
        "country_code": "DE",
        "city": "Frankfurt am Main",
        "region": "Hesse",
        "latitude": 50.1109,
        "longitude": 8.6821,
        "asn": "AS208323",
        "as_org": "Zwiebelfreunde e.V.",
        "isp": "Zwiebelfreunde e.V.",
        "org": "Tor Exit Node Cluster",
        "threat_type": "Tor Exit Node / Anonymizer",
        "threat_score": 92,
    },
    "194.26.29.112": {
        "country": "Russia",
        "country_code": "RU",
        "city": "Moscow",
        "region": "Moscow Federal City",
        "latitude": 55.7558,
        "longitude": 37.6173,
        "asn": "AS58222",
        "as_org": "Serverel Hosting Ltd",
        "isp": "Serverel Hosting Ltd",
        "org": "Bulletproof VPS Network",
        "threat_type": "Known Automated Scanner / Exploit Script",
        "threat_score": 88,
    },
    "218.92.0.198": {
        "country": "China",
        "country_code": "CN",
        "city": "Lianyungang",
        "region": "Jiangsu",
        "latitude": 34.5997,
        "longitude": 119.1594,
        "asn": "AS4134",
        "as_org": "CHINANET-BACKBONE",
        "isp": "China Telecom",
        "org": "China Telecom Jiangsu",
        "threat_type": "SSH Brute-Force Botnet",
        "threat_score": 85,
    },
    "177.54.144.12": {
        "country": "Brazil",
        "country_code": "BR",
        "city": "São Paulo",
        "region": "São Paulo",
        "latitude": -23.5505,
        "longitude": -46.6333,
        "asn": "AS28573",
        "as_org": "CLARO S.A.",
        "isp": "Net Servicos de Comunicacao S.A.",
        "org": "Residential Proxy Cluster",
        "threat_type": "Credential Stuffing Proxy",
        "threat_score": 75,
    },
    "198.51.100.2": {
        "country": "United States",
        "country_code": "US",
        "city": "Ashburn",
        "region": "Virginia",
        "latitude": 39.0438,
        "longitude": -77.4874,
        "asn": "AS14618",
        "as_org": "Amazon.com, Inc.",
        "isp": "Amazon Technologies Inc.",
        "org": "AWS EC2 Cloud Infrastructure",
        "threat_type": "Cloud Instance Recon Scanner",
        "threat_score": 65,
    },
    "45.33.32.156": {
        "country": "United States",
        "country_code": "US",
        "city": "Fremont",
        "region": "California",
        "latitude": 37.5485,
        "longitude": -121.9886,
        "asn": "AS63949",
        "as_org": "Linode, LLC",
        "isp": "Akamai Technologies, Inc.",
        "org": "Linode Autonomous Cloud",
        "threat_type": "Automated Port Probe / Web Crawler",
        "threat_score": 70,
    },
    "103.251.167.20": {
        "country": "India",
        "country_code": "IN",
        "city": "Mumbai",
        "region": "Maharashtra",
        "latitude": 19.0760,
        "longitude": 72.8777,
        "asn": "AS55836",
        "as_org": "Reliance Jio Infocomm Limited",
        "isp": "Jio Broadband Services",
        "org": "Commercial Gateway",
        "threat_type": "External Reconnaissance",
        "threat_score": 55,
    },
}


class GeoTracker:
    """Thread-safe Geolocation & ASN resolver with LRU caching."""

    def __init__(self, max_cache: int = 2000):
        self._cache: Dict[str, GeoIntel] = {}
        self._lock = threading.RLock()
        self._max_cache = max_cache

        # Pre-seed known threat actors into cache
        for ip, data in KNOWN_THREAT_ACTORS.items():
            flag = country_code_to_flag(data.get("country_code", "XX"))
            self._cache[ip] = GeoIntel(
                ip=ip,
                country=data.get("country", "Unknown"),
                country_code=data.get("country_code", "XX"),
                country_flag=flag,
                region=data.get("region", "Unknown"),
                city=data.get("city", "Unknown"),
                latitude=data.get("latitude", 0.0),
                longitude=data.get("longitude", 0.0),
                asn=data.get("asn", "AS-UNKNOWN"),
                as_org=data.get("as_org", "Unknown"),
                isp=data.get("isp", "Unknown"),
                org=data.get("org", "Unknown"),
                threat_type=data.get("threat_type", "External Ingress"),
                threat_score=data.get("threat_score", 50),
                is_private=False,
            )

    @staticmethod
    def is_private_ip(ip_str: str) -> bool:
        """Check if an IP is loopback, RFC1918 private, link-local, or reserved."""
        cleaned = ip_str.strip()
        if cleaned in {"127.0.0.1", "localhost", "::1", "0.0.0.0", "unknown"}:
            return True
        try:
            ip_obj = ipaddress.ip_address(cleaned)
            return (
                ip_obj.is_private
                or ip_obj.is_loopback
                or ip_obj.is_link_local
                or ip_obj.is_reserved
                or ip_obj.is_multicast
            )
        except ValueError:
            return True

    def lookup(self, ip_str: str) -> GeoIntel:
        """Look up geolocation and ASN for an IP address."""
        cleaned = (ip_str or "").strip()
        if not cleaned or cleaned == "0.0.0.0":
            return GeoIntel(
                ip="0.0.0.0",
                country="Localhost / Internal",
                country_code="LAN",
                country_flag="🛡️",
                city="Local Sandbox",
                region="Internal Lab",
                asn="AS-PRIVATE",
                as_org="RFC1918 Private Network",
                isp="Local Interface",
                org="CyberShield Lab",
                is_private=True,
                threat_type="Internal / Host Loopback",
                threat_score=10,
            )

        with self._lock:
            if cleaned in self._cache:
                return self._cache[cleaned]

        # Check if it's a private / RFC1918 address
        if self.is_private_ip(cleaned):
            intel = GeoIntel(
                ip=cleaned,
                country="Internal Network",
                country_code="LAN",
                country_flag="🛡️",
                city="Local Subnet / Lab",
                region="RFC1918 Private Range",
                latitude=28.6139,
                longitude=77.2090,
                asn="AS-PRIVATE",
                as_org="Private Enterprise Subnet",
                isp="Local Network Interface",
                org="CyberShield SOC Testbed",
                timezone="Local",
                is_private=True,
                threat_type="Internal Subnet / Lab Ingress",
                threat_score=25,
            )
            with self._lock:
                if len(self._cache) >= self._max_cache:
                    self._cache.pop(next(iter(self._cache)))
                self._cache[cleaned] = intel
            return intel

        # Public IP lookup
        intel = self._fetch_public_geo(cleaned)
        with self._lock:
            if len(self._cache) >= self._max_cache:
                self._cache.pop(next(iter(self._cache)))
            self._cache[cleaned] = intel
        return intel

    def _fetch_public_geo(self, ip: str) -> GeoIntel:
        """Fetch geolocation and ASN from public APIs with timeout and fallback."""
        # Primary API: ip-api.com (fast, no key required)
        try:
            url = f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,query"
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "CyberShield-AI-Threat-Intel/1.0"},
            )
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                if resp.status == 200:
                    data = json.loads(resp.read().decode("utf-8"))
                    if data.get("status") == "success":
                        cc = data.get("countryCode", "XX")
                        flag = country_code_to_flag(cc)
                        as_field = data.get("as", "")
                        # Split "AS15169 Google LLC" into ASN and Org
                        asn_match = re.match(r"^(AS\d+)\s*(.*)$", as_field, re.IGNORECASE)
                        asn_num = asn_match.group(1) if asn_match else as_field or "AS-UNKNOWN"
                        as_name = asn_match.group(2) if asn_match else data.get("org") or data.get("isp") or "Unknown"

                        return GeoIntel(
                            ip=ip,
                            country=data.get("country", "Unknown"),
                            country_code=cc,
                            country_flag=flag,
                            region=data.get("regionName", "Unknown"),
                            city=data.get("city", "Unknown"),
                            postal=data.get("zip", ""),
                            latitude=float(data.get("lat") or 0.0),
                            longitude=float(data.get("lon") or 0.0),
                            asn=asn_num,
                            as_org=as_name,
                            isp=data.get("isp", "Unknown ISP"),
                            org=data.get("org", "Unknown Org"),
                            timezone=data.get("timezone", "UTC"),
                            is_private=False,
                            threat_type="External Public Ingress",
                            threat_score=60,
                        )
        except Exception as exc:
            logger.debug("Primary geo lookup failed for %s: %s", ip, exc)

        # Secondary API: ipwhois.app
        try:
            url = f"https://ipwhois.app/json/{ip}"
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "CyberShield-AI-Threat-Intel/1.0"},
            )
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                if resp.status == 200:
                    data = json.loads(resp.read().decode("utf-8"))
                    if data.get("success") is not False:
                        cc = data.get("country_code", "XX")
                        flag = country_code_to_flag(cc)
                        return GeoIntel(
                            ip=ip,
                            country=data.get("country", "Unknown"),
                            country_code=cc,
                            country_flag=flag,
                            region=data.get("region", "Unknown"),
                            city=data.get("city", "Unknown"),
                            latitude=float(data.get("latitude") or 0.0),
                            longitude=float(data.get("longitude") or 0.0),
                            asn=data.get("asn", "AS-UNKNOWN"),
                            as_org=data.get("org", "Unknown"),
                            isp=data.get("isp", "Unknown ISP"),
                            org=data.get("org", "Unknown Org"),
                            timezone=data.get("timezone", "UTC"),
                            is_private=False,
                            threat_type="External Public Ingress",
                            threat_score=60,
                        )
        except Exception as exc:
            logger.debug("Secondary geo lookup failed for %s: %s", ip, exc)

        # Fallback offline default
        return GeoIntel(
            ip=ip,
            country="External Host",
            country_code="UN",
            country_flag="🌐",
            city="Remote Ingress",
            region="Remote Network",
            latitude=0.0,
            longitude=0.0,
            asn="AS-UNKNOWN",
            as_org="Unattributed ASN",
            isp="External Network",
            org="External Network",
            is_private=False,
            threat_type="External Public Ingress",
            threat_score=50,
        )

    def enrich_session(self, session: Dict[str, Any]) -> Dict[str, Any]:
        """Attach geo intelligence to a session dictionary."""
        src_ip = session.get("source_ip") or session.get("source_address") or "127.0.0.1"
        geo = self.lookup(src_ip)
        enriched = dict(session)
        enriched["geo"] = geo.to_dict()
        return enriched

    def get_tracked_attackers(
        self, sessions: List[Dict[str, Any]], canaries: Optional[List[Dict[str, Any]]] = None
    ) -> List[Dict[str, Any]]:
        """Aggregate unique adversary IPs across sessions and canary tokens with full Geo + ASN attribution."""
        ip_map: Dict[str, Dict[str, Any]] = {}

        for sess in sessions:
            ip = sess.get("source_ip") or sess.get("source_address")
            if not ip or ip.strip().lower() in {"testclient", "test", "0.0.0.0", "unknown"}:
                continue
            geo = self.lookup(ip)
            port = sess.get("destination_port")
            proto = sess.get("service") or sess.get("protocol") or "unknown"

            if ip not in ip_map:
                ip_map[ip] = {
                    "ip": ip,
                    "geo": geo.to_dict(),
                    "session_count": 0,
                    "actions_count": 0,
                    "probed_ports": [],
                    "probed_services": [],
                    "latest_activity": sess.get("started_at"),
                    "max_risk_score": 0,
                    "contained": False,
                    "canary_triggered": False,
                }

            entry = ip_map[ip]
            entry["session_count"] += 1
            entry["actions_count"] += sess.get("interactions") or 0
            sess_time = sess.get("started_at")
            if sess_time:
                curr_latest = entry.get("latest_activity")
                if not curr_latest or sess_time > curr_latest:
                    entry["latest_activity"] = sess_time
            if port and port not in entry["probed_ports"]:
                entry["probed_ports"].append(port)
            if proto and proto not in entry["probed_services"]:
                entry["probed_services"].append(proto)
            if (sess.get("risk_score") or 0) > entry["max_risk_score"]:
                entry["max_risk_score"] = sess.get("risk_score") or 0
            if sess.get("contained"):
                entry["contained"] = True

        # Also incorporate canary triggers
        if canaries:
            for can in canaries:
                ip = can.get("last_source_ip")
                if not ip or ip not in ip_map:
                    if ip:
                        geo = self.lookup(ip)
                        ip_map[ip] = {
                            "ip": ip,
                            "geo": geo.to_dict(),
                            "session_count": 0,
                            "actions_count": 1,
                            "probed_ports": [80],
                            "probed_services": ["canary_token"],
                            "latest_activity": can.get("last_triggered_at"),
                            "max_risk_score": 95,
                            "contained": False,
                            "canary_triggered": True,
                        }
                else:
                    ip_map[ip]["canary_triggered"] = True
                    ip_map[ip]["max_risk_score"] = max(ip_map[ip]["max_risk_score"], 95)
                    can_time = can.get("last_triggered_at")
                    if can_time:
                        curr_latest = ip_map[ip].get("latest_activity")
                        if not curr_latest or can_time > curr_latest:
                            ip_map[ip]["latest_activity"] = can_time

        # Sort by latest_activity descending (most recent attacks first), then max_risk_score
        attackers = list(ip_map.values())
        attackers.sort(
            key=lambda a: (a.get("latest_activity") or "", a.get("max_risk_score") or 0),
            reverse=True,
        )
        return attackers


# Singleton instance
_global_geo_tracker: Optional[GeoTracker] = None
_tracker_lock = threading.Lock()


def get_geo_tracker() -> GeoTracker:
    global _global_geo_tracker
    if _global_geo_tracker is None:
        with _tracker_lock:
            if _global_geo_tracker is None:
                _global_geo_tracker = GeoTracker()
    return _global_geo_tracker
