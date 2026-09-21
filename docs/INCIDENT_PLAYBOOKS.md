# VALENS Autonomous Incident Response Playbooks

## Overview

VALENS automates defense workflows to transform adversary intrusion attempts into actionable mitigation. This guide outlines standard operating playbooks implemented by the autonomous SOC engine.

---

### Playbook 1: SQL Injection Decoy Trap & Poisoning

- **Objective**: Intercept SQL injection probes, prevent database exposure, and feed deceptive telemetry.
- **Triggers**: Inbound HTTP/API parameter matching SQL syntax keywords targeting honey-endpoints.
- **Automated Workflow**:
  1. Return `200 OK` with synthetic schema containing poisoned password hashes and honey-canary records.
  2. Log attacker originating IP, TLS cipher fingerprint, and raw payload.
  3. Dispatch automated WAF edge rule blocking the offending IP after 3 attempts.
  4. Formulate GitHub PR recommendation patching the SQL vulnerability in application code.

---

### Playbook 2: SSH Brute-Force Tarpit & Credential Harvesting

- **Objective**: Exhaust automated botnet tools and harvest adversary wordlists.
- **Triggers**: TCP connection on port `2222` with rapid authentication queries.
- **Automated Workflow**:
  1. Switch socket handler into delayed-transmission mode (1 byte every 8 seconds).
  2. Capture username and password dictionaries in memory for threat intelligence enrichment.
  3. Query MaxMind / IPInfo GeoIP database to resolve autonomous system number (ASN) and country of origin.
  4. Correlate against global Wazuh / AbuseIPDB reputation feeds.

---

### Playbook 3: Ransomware Canary SMB Share Isolation

- **Objective**: Prevent lateral ransomware encryption across local network shares.
- **Triggers**: File modification or encryption attempt on canary dummy shares (e.g. `\\valens-share\canary_budget.xlsx`).
- **Automated Workflow**:
  1. Trigger immediate host network adapter disconnection via agent socket.
  2. Take forensic snapshot of running process tree.
  3. Notify SecOps on-call team via high-priority webhook (Slack / PagerDuty / Email).

---

### Playbook 4: Automated Edge WAF Quarantine & PR Hotfix

- **Objective**: Permanently remediate attack surface with zero manual analyst fatigue.
- **Triggers**: Multiple MITRE ATT&CK technique correlations confirmed by Gemini AI SOC reasoning.
- **Automated Workflow**:
  1. Synchronize IP blocklist rule with edge reverse proxy.
  2. Clone target repository, apply verified security fix, and run automated unit tests.
  3. Open pull request with detailed explanation, diff, and audit trail for developer review.
