# VALENS Canary Tokens Deployment & Rotation Guide

## Overview

Canary tokens (honeytokens) provide high-signal, zero-false-positive intrusion alerts. Because authentic business processes never interact with canary assets, any access attempt indicates adversary reconnaissance or lateral movement.

---

## 1. Honeytoken Types Supported

### A. AWS IAM Honey-Credentials
- **Deployment**: Seeded in fictitious `.aws/credentials` or `config.json` mock files on developer workstations and staging servers.
- **Tripwire**: Any API invocation (e.g. `sts:GetCallerIdentity`, `s3:ListBuckets`) fires an immediate SOC webhook with the adversary's originating IP and user-agent.

### B. Database Honey-Records
- **Deployment**: Injected into user or transaction tables with high-value usernames (`superadmin_backup`, `finance_canary`).
- **Tripwire**: Any `SELECT` query touching the canary hash generates an exfiltration poisoning alert and feeds fake bcrypt hashes.

### C. Webhook HTTP Tripwires
- **Deployment**: Embedded as deceptive callback URLs in API responses or HTML comments (`/api/internal/debug-webhook?token=canary-8812`).
- **Tripwire**: Inbound HTTP GET or POST triggers instant IP quarantine.

---

## 2. Automated Rotation Lifecycle

1. **Generation**: Cryptographically random 32-character tokens generated on decoy boot.
2. **Distribution**: Seeded into decoy services, synthetic environment variables, and git fixtures.
3. **Audit**: Monitored via the VALENS centralized event loop.
4. **Rotation**: Automatically retired and refreshed every 30 days or immediately following an adversary engagement.
