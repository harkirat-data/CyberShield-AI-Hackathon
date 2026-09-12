# Playbook: Brute Force Authentication Response

## Scope

Use this playbook when repeated authentication failures suggest password spraying or brute force activity against SSH, RDP, VPN, or web login flows.

## Immediate actions

1. Identify the source IP, usernames targeted, and the affected authentication surface
2. Block, tarp it, or rate-limit the source IP if it is external and clearly malicious
3. Review whether any targeted account successfully authenticated after the failures
4. Force password reset and revoke tokens for accounts that show suspicious success
5. Preserve relevant logs from the host, identity provider, firewall, and VPN gateway

## Short-term containment

- Enable or tighten account lockout and throttling controls
- Require MFA on the affected service
- Restrict administrative access to trusted networks or VPN-only paths
- Hunt for the source IP and usernames across other hosts

## Long-term hardening

- Enforce password hygiene and remove shared admin accounts
- Add geographic and ASN-based alerting for authentication anomalies
- Build detections for failure bursts followed by success
- Validate SIEM parsing for SSH, RDP, and identity provider logs

## Evidence checklist

- Source IP and ASN
- Target usernames
- Failure count and time window
- Any successful logons after failures
- Post-authentication commands or lateral movement indicators
