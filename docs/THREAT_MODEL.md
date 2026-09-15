# VALENS Threat Model & Attack Surface Matrix

## Overview

This threat model outlines the STRIDE categorization and defensive mitigation architecture utilized by VALENS to safeguard infrastructure from external automated scanners, credential stuffers, and sophisticated lateral movement.

---

## 1. Adversary Personas & Objectives

| Persona | Motivation | Primary Vectors | Deception Countermeasure |
| :--- | :--- | :--- | :--- |
| **Opportunistic Scanner / Botnet** | Mass discovery, unpatched CVEs, default passwords | Shodan scans, mass SSH/MySQL port probes | Lightweight honeypot traps, infinite SSH tarpit |
| **Credential Harvester** | Account takeover, credential reuse | Inbound brute-force, web login dictionary attacks | Canary user records, fake bcrypt exfiltration poisoning |
| **Advanced Persistent Threat (APT)** | Espionage, persistence, lateral movement | Cloud token theft, S3 bucket enumeration | AWS IAM Canary keys, fake S3 bucket tripwires |
| **Ransomware Operator** | Data encryption, extortion | SMB share enumeration, database dumping | SMB canary shares, instant host network auto-isolation |

---

## 2. STRIDE Threat Analysis

| Threat Category | Target Component | Attack Vector | VALENS Mitigation |
| :--- | :--- | :--- | :--- |
| **Spoofing** | Edge WAF / Listeners | IP address spoofing, forged headers | Cryptographic client fingerprinting & TCP window analysis |
| **Tampering** | Decoy Configuration | Modifying honeypot parameters | Immutable runtime environment with signed hashes |
| **Repudiation** | Telemetry Audit Logs | Deleting or altering access logs | Append-only CEF event logging & remote syslog streaming |
| **Information Disclosure** | Database Honeypot | Exfiltrating database tables | Synthetic deceptive data tables with tracked honeytokens |
| **Denial of Service** | Core Production Apps | Flooding connection pools | Isolating attack traffic to low-overhead sandboxed decoys |
| **Elevation of Privilege** | Container Runtime | Sandbox escape from decoy container | Non-root container execution, strict seccomp profiles |

---

## 3. Incident Severity Escalation Model

- **SEV-1 (Critical)**: Canary token tripwire triggered or root credential access attempted on decoy. Instant WAF edge drop + PagerDuty / SMS dispatch.
- **SEV-2 (High)**: SQL injection or rapid brute-force burst (> 10 attempts/min). Edge firewall quarantine rule created automatically.
- **SEV-3 (Medium)**: Reconnaissance scan on decoy ports (2222, 6379, 3306). Logged for threat intelligence correlation.
- **SEV-4 (Low)**: Single port probe or discarded malformed packet.
