"""
mitre_mapper.py - Simple rule-based MITRE mapping with optional RAG merge support.
"""
from typing import Dict, List

from schema import Event, MitreMapping


EVENT_MAPPINGS: Dict[str, Dict[str, List[str] | float | str]] = {
    "PORT_SCAN": {
        "techniques": ["T1046"],
        "tactics": ["Discovery"],
        "confidence": 0.96,
        "rationale": "Connections across multiple decoy ports indicate network service discovery.",
    },
    "HONEYPOT_SESSION_STARTED": {
        "techniques": ["T1046"],
        "tactics": ["Discovery"],
        "confidence": 0.55,
        "rationale": "A connection to a decoy service is a discovery signal until stronger intent is observed.",
    },
    "DECOY_AUTH_ATTEMPT": {
        "techniques": ["T1110"],
        "tactics": ["Credential Access"],
        "confidence": 0.92,
        "rationale": "Authentication against a deliberately non-production decoy is unauthorized credential access activity.",
    },
    "SYSTEM_DISCOVERY": {
        "techniques": ["T1082"],
        "tactics": ["Discovery"],
        "confidence": 0.9,
        "rationale": "Commands enumerate operating system, host, processes, or network configuration.",
    },
    "CREDENTIAL_DISCOVERY": {
        "techniques": ["T1552"],
        "tactics": ["Credential Access"],
        "confidence": 0.94,
        "rationale": "The interaction searches for unsecured credentials, private keys, or password stores.",
    },
    "PAYLOAD_TRANSFER": {
        "techniques": ["T1105"],
        "tactics": ["Command and Control"],
        "confidence": 0.94,
        "rationale": "The interaction attempts to transfer a tool or payload into the decoy.",
    },
    "PERSISTENCE_ATTEMPT": {
        "techniques": ["T1053", "T1098"],
        "tactics": ["Persistence", "Privilege Escalation"],
        "confidence": 0.9,
        "rationale": "The command attempts scheduled execution or account-based persistence.",
    },
    "PRIVILEGE_ESCALATION": {
        "techniques": ["T1548"],
        "tactics": ["Privilege Escalation", "Defense Evasion"],
        "confidence": 0.86,
        "rationale": "The command attempts to elevate the current decoy identity.",
    },
    "DATABASE_DISCOVERY": {
        "techniques": ["T1083", "T1213"],
        "tactics": ["Discovery", "Collection"],
        "confidence": 0.84,
        "rationale": "Queries enumerate a database or attempt to collect records from an information repository.",
    },
    "HTTP_REQUEST": {
        "techniques": ["T1190"],
        "tactics": ["Initial Access"],
        "confidence": 0.4,
        "rationale": "A request to a decoy public-facing application is retained as a possible exploitation precursor.",
    },
    "AUTH_FAILURE": {
        "techniques": ["T1110"],
        "tactics": ["Credential Access"],
        "confidence": 0.82,
        "rationale": "Repeated authentication failures commonly indicate brute force or password guessing.",
    },
    "LOGON_FAILURE": {
        "techniques": ["T1110"],
        "tactics": ["Credential Access"],
        "confidence": 0.82,
        "rationale": "Repeated logon failures commonly indicate brute force or password guessing.",
    },
    "AUTH_SUCCESS": {
        "techniques": ["T1078"],
        "tactics": ["Defense Evasion", "Persistence", "Privilege Escalation", "Initial Access"],
        "confidence": 0.45,
        "rationale": "Successful authentication can indicate valid account use when correlated with suspicious activity.",
    },
    "USER_CREATED": {
        "techniques": ["T1136"],
        "tactics": ["Persistence"],
        "confidence": 0.85,
        "rationale": "Unexpected account creation aligns with Create Account behavior.",
    },
    "MIMIKATZ_DETECTED": {
        "techniques": ["T1003"],
        "tactics": ["Credential Access"],
        "confidence": 0.98,
        "rationale": "Mimikatz strongly indicates OS credential dumping activity.",
    },
    "ENCODED_POWERSHELL": {
        "techniques": ["T1059.001", "T1027"],
        "tactics": ["Execution", "Defense Evasion"],
        "confidence": 0.9,
        "rationale": "Encoded PowerShell maps to PowerShell execution and obfuscated files or information.",
    },
    "SUSPICIOUS_SERVICE": {
        "techniques": ["T1543.003"],
        "tactics": ["Persistence", "Privilege Escalation"],
        "confidence": 0.9,
        "rationale": "Suspicious service creation aligns with Windows Service persistence.",
    },
    "SERVICE_INSTALLED": {
        "techniques": ["T1543.003"],
        "tactics": ["Persistence", "Privilege Escalation"],
        "confidence": 0.82,
        "rationale": "Service installation may indicate Windows Service persistence.",
    },
    "EVENT_LOG_CLEARED": {
        "techniques": ["T1070.001"],
        "tactics": ["Defense Evasion"],
        "confidence": 0.94,
        "rationale": "Clearing event logs maps directly to indicator removal on host.",
    },
    "AUDIT_LOG_CLEARED": {
        "techniques": ["T1070.001"],
        "tactics": ["Defense Evasion"],
        "confidence": 0.94,
        "rationale": "Clearing audit logs maps directly to indicator removal on host.",
    },
}


def map_event(event: Event) -> MitreMapping:
    mapping = EVENT_MAPPINGS.get(event.event_type, {})
    return MitreMapping(
        techniques=list(mapping.get("techniques", [])),
        tactics=list(mapping.get("tactics", [])),
        confidence=float(mapping.get("confidence", 0.2)),
        source="rules",
        rationale=str(mapping.get("rationale", f"No direct mapping rule for {event.event_type}.")),
    )


def merge_with_rag(base: MitreMapping, rag_techniques: List[str]) -> MitreMapping:
    if not rag_techniques:
        return base

    merged_techniques = list(dict.fromkeys([*base.techniques, *rag_techniques]))
    source = "hybrid" if base.techniques else "rag"
    rationale = base.rationale
    if rag_techniques:
        rationale = f"{rationale} RAG added: {', '.join(rag_techniques)}".strip()

    return MitreMapping(
        techniques=merged_techniques,
        tactics=base.tactics,
        confidence=max(base.confidence, 0.7 if rag_techniques else base.confidence),
        source=source,
        rationale=rationale,
    )
