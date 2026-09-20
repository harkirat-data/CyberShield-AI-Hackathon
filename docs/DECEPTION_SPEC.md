# VALENS Autonomous Deception Mesh Specification

## Overview

VALENS provides an autonomous cyber deception and SOC platform designed to lure, isolate, and forensic-fingerprint adversaries before they can compromise authentic production workloads. This document details the technical specification of the deception mesh, telemetry structures, and containment mechanisms.

---

## 1. Decoy Architecture & Port Mappings

The deception grid consists of lightweight, high-fidelity listeners emulating authentic production infrastructure services:

| Service Emulated | Protocol | Default Port | Decoy Persona | Defense Strategy |
| :--- | :---: | :---: | :--- | :--- |
| **MySQL Database** | TCP | `3306` | Corporate User / Billing DB | Synthetic Schema, Fake Bcrypt Hashes, Exfiltration Poisoning |
| **Redis Cache** | TCP | `6379` | Unprotected In-Memory Session Store | Poisoned Session Tokens, Key Space Notifications |
| **SSH Server** | TCP | `2222` | Edge Linux Gateway (OpenSSH 8.9) | Slow Byte-by-Byte Tarpit, Credential Harvester |
| **HTTP Admin Portal** | HTTP/S | `8050` / `8080` | Internal Management Console | Fake Session Cookies, CSRF Honeytokens, Canary Login Form |

---

## 2. Honeytoken Deployment Lifecycle

Honeytokens are digital tripwires embedded across production systems that possess zero legitimate operational purpose:

1. **AWS S3 Canary Credentials**: High-interaction IAM access keys seeded in configuration mocks that trigger instant CloudTrail / SOC alerts upon any `GetObject` or `ListBucket` call.
2. **Database Canary Records**: Synthetic user records (`admin_canary`, `finance_audit`) seeded with distinct honeypot email domains.
3. **Git Honeytokens**: Fictitious API tokens embedded in repository test fixtures to detect repository crawling bots immediately.

---

## 3. Telemetry Event Schema

All decoy events are standardized into CEF / JSON format:

```json
{
  "event_id": "evt-deception-984210",
  "timestamp": "2026-09-20T11:24:15.000Z",
  "source_ip": "198.51.100.42",
  "source_port": 54210,
  "destination_port": 3306,
  "decoy_type": "mysql_honeypot",
  "threat_level": "CRITICAL",
  "mitre_technique": "T1078.001 - Valid Accounts: Default Accounts",
  "payload_snippet": "SELECT user, password_hash FROM users WHERE admin=1",
  "auto_containment": {
    "action": "WAF_DROP_IP",
    "status": "EXECUTED",
    "quarantine_id": "qnt-4412"
  }
}
```

---

## 4. Threat Attribution & Autonomous Containment

When an unauthorized connection touches a decoy:
1. **Forensic Fingerprinting**: Capture TCP handshake fingerprint (SYN packet size, window size, TTL, user-agent).
2. **Payload Analysis**: Automated correlation against MITRE ATT&CK tactics and Sigma rule signatures.
3. **Automated Containment**: Immediate IP quarantine across edge reverse proxies (Envoy / WAF) and GitHub PR generation for permanent code patching.
