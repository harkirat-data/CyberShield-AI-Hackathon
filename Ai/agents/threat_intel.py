"""
threat_intel.py - Check IPs/domains/hashes against threat intelligence sources

For the hackathon: local blocklist + simple heuristics.
Production: plug in AbuseIPDB, VirusTotal, AlienVault OTX.
"""
import ipaddress
from typing import Optional
from schema import Event, ThreatIntel


# Local blocklist (for demo - replace with real feed in production)
KNOWN_BAD_IPS = {
    "192.0.2.45",        # TEST-NET-1, often used in examples
    "198.51.100.42",     # TEST-NET-2
    "203.0.113.77",      # TEST-NET-3
    "185.220.101.0/24",  # Known Tor exit range
}

KNOWN_SUSPICIOUS_USERS = {
    "admin", "root", "test", "guest", "oracle", "postgres",
    "ubuntu", "ec2-user", "administrator",
}


def _ip_in_blocklist(ip: str) -> bool:
    """Check if IP is in any CIDR in blocklist."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for entry in KNOWN_BAD_IPS:
        try:
            if "/" in entry:
                if addr in ipaddress.ip_network(entry, strict=False):
                    return True
            else:
                if str(addr) == entry:
                    return True
        except ValueError:
            continue
    return False


def check(event: Event) -> ThreatIntel:
    """Run threat intel on an event. Always returns a result."""
    result = ThreatIntel()
    ip = event.actor.get("source_ip")
    user = (event.actor.get("user") or "").lower()

    if ip:
        if _ip_in_blocklist(ip):
            result.ip_reputation = "malicious"
            result.is_malicious = True
            result.abuse_score = 95
            result.sources.append("local_blocklist")
            result.notes += f"IP {ip} matches known-malicious blocklist. "
        else:
            # Simple heuristic: private IPs are likely internal
            try:
                addr = ipaddress.ip_address(ip)
                if addr.is_private:
                    result.ip_reputation = "internal"
                else:
                    result.ip_reputation = "unknown"
            except ValueError:
                result.ip_reputation = "invalid"

    if user in KNOWN_SUSPICIOUS_USERS and event.event_type in (
        "AUTH_FAILURE", "LOGON_FAILURE", "USER_CREATED", "DECOY_AUTH_ATTEMPT"
    ):
        result.notes += f"Target user '{user}' is commonly attacked. "
        result.related_iocs.append(f"user:{user}")

    # Service-level indicators
    if event.event_type == "MIMIKATZ_DETECTED":
        result.is_malicious = True
        result.campaigns.append("credential_theft")
        result.notes += "Mimikatz signature detected - high-confidence credential theft."

    if event.event_type == "ENCODED_POWERSHELL":
        result.notes += "Encoded PowerShell - common defense evasion technique. "
        result.related_iocs.append("tactic:defense_evasion")

    if event.event_type == "SUSPICIOUS_SERVICE":
        result.notes += "Service installed from suspicious path - possible persistence. "
        result.related_iocs.append("tactic:persistence")

    return result


if __name__ == "__main__":
    e = Event(
        event_id="t1", timestamp="", host="h1", source="linux_auth",
        event_type="AUTH_FAILURE", severity="high",
        actor={"source_ip": "198.51.100.42", "user": "admin"}
    )
    print(check(e).to_dict())
