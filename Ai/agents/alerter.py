"""
alerter.py - Modular security alerting layer for CyberShield AI.

Dispatches security alerts to Slack, Discord, and Email (SMTP) when high-risk
or critical security incidents are detected.
"""

from __future__ import annotations

import json
import logging
import os
import smtplib
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any, Dict, List, Optional

logger = logging.getLogger("cybershield.alerter")


SEVERITY_RANKS: Dict[str, int] = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


@dataclass
class SecurityAlert:
    """Normalized security alert structure shared across all notification channels."""

    event_id: str
    timestamp: str
    severity: str
    risk_score: int
    source_ip: str
    host: str
    service: str
    event_type: str
    intent: str
    mitre_techniques: List[str] = field(default_factory=list)
    mitre_tactics: List[str] = field(default_factory=list)
    ai_summary: str = ""
    recommended_remediation: List[str] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_investigation(cls, inv: Any) -> SecurityAlert:
        """Create a normalized SecurityAlert from an AI Investigation object."""
        event = inv.event
        actor = getattr(event, "actor", {}) or {}
        target = getattr(event, "target", {}) or {}
        event_details = getattr(event, "details", {}) or {}

        source_ip = actor.get("source_ip") or actor.get("user") or "unknown"
        service = target.get("service") or getattr(event, "source", "unknown")
        host = getattr(event, "host", "unknown") or target.get("host", "unknown")

        mitre = getattr(inv, "mitre", None)
        mitre_techs = getattr(mitre, "techniques", []) if mitre else []
        mitre_tactics = getattr(mitre, "tactics", []) if mitre else []

        # Extract AI explanation or fallback to deterministic rationale
        llm = getattr(inv, "llm_analysis", None) or {}
        ai_summary = ""
        if isinstance(llm, dict):
            ai_summary = (
                llm.get("summary")
                or llm.get("explanation")
                or llm.get("analysis")
                or ""
            )

        if not ai_summary:
            risk_rationale = getattr(getattr(inv, "risk", None), "rationale", "")
            if risk_rationale:
                ai_summary = risk_rationale
            else:
                ai_summary = f"Detected {event.event_type} on {host} from {source_ip}."

        # Extract remediation recommendations
        remediation_obj = getattr(inv, "final_remediation", {}) or {}
        recommended: List[str] = []
        if isinstance(remediation_obj, dict):
            immediate = remediation_obj.get("immediate", [])
            short_term = remediation_obj.get("short_term", [])
            if isinstance(immediate, list):
                recommended.extend(immediate)
            if isinstance(short_term, list):
                recommended.extend(short_term)
        elif isinstance(remediation_obj, list):
            recommended.extend(remediation_obj)

        intent = ""
        if mitre_tactics:
            intent = ", ".join(mitre_tactics)
        elif event_details.get("intent"):
            intent = str(event_details["intent"])
        else:
            intent = "Security Anomaly"

        risk_score = getattr(getattr(inv, "risk", None), "score", 0)
        severity = getattr(inv, "final_severity", "") or getattr(
            getattr(inv, "risk", None), "level", "info"
        )

        return cls(
            event_id=getattr(event, "event_id", "unknown"),
            timestamp=getattr(event, "timestamp", ""),
            severity=severity,
            risk_score=int(risk_score),
            source_ip=str(source_ip),
            host=str(host),
            service=str(service),
            event_type=getattr(event, "event_type", "SECURITY_INCIDENT"),
            intent=intent,
            mitre_techniques=list(mitre_techs),
            mitre_tactics=list(mitre_tactics),
            ai_summary=ai_summary,
            recommended_remediation=recommended,
            details=event_details,
        )


class SlackAlerter:
    """Dispatches security alerts to Slack using Incoming Webhooks."""

    def __init__(self, webhook_url: Optional[str] = None, timeout_seconds: float = 5.0):
        self._webhook_url = webhook_url
        self.timeout = timeout_seconds

    @property
    def webhook_url(self) -> str:
        if self._webhook_url is not None:
            return self._webhook_url
        return os.environ.get("SLACK_WEBHOOK_URL", "").strip()

    @property
    def is_configured(self) -> bool:
        return bool(self.webhook_url)

    def build_payload(self, alert: SecurityAlert) -> Dict[str, Any]:
        """Build a concise Slack message payload."""
        sev = alert.severity.upper()
        severity_emojis = {
            "CRITICAL": ":rotating_light:",
            "HIGH": ":warning:",
            "MEDIUM": ":large_orange_circle:",
            "LOW": ":large_blue_circle:",
            "INFO": ":information_source:",
        }
        emoji = severity_emojis.get(sev, ":warning:")

        techs_str = ", ".join(alert.mitre_techniques) if alert.mitre_techniques else "N/A"
        tactics_str = ", ".join(alert.mitre_tactics) if alert.mitre_tactics else "N/A"
        remediation_str = (
            "\n".join(f"• {r}" for r in alert.recommended_remediation[:4])
            if alert.recommended_remediation
            else "Review host logs and isolate if necessary."
        )

        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"{emoji} [CyberShield AI] {sev} Security Incident Detected",
                    "emoji": True,
                },
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Event Type:*\n`{alert.event_type}`"},
                    {"type": "mrkdwn", "text": f"*Risk Score:*\n`{alert.risk_score}/100` ({sev})"},
                    {"type": "mrkdwn", "text": f"*Source IP:*\n`{alert.source_ip}`"},
                    {"type": "mrkdwn", "text": f"*Host / Service:*\n`{alert.host}` / `{alert.service}`"},
                    {"type": "mrkdwn", "text": f"*MITRE Techniques:*\n`{techs_str}`"},
                    {"type": "mrkdwn", "text": f"*Tactic / Intent:*\n`{tactics_str}`"},
                ],
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*AI Analysis:*\n{alert.ai_summary or 'No additional analysis provided.'}",
                },
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Recommended Remediation:*\n{remediation_str}",
                },
            },
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": f"Event ID: `{alert.event_id}` | Time: `{alert.timestamp}`",
                    }
                ],
            },
        ]

        return {"blocks": blocks, "text": f"[{sev}] CyberShield AI Incident: {alert.event_type} (Score: {alert.risk_score})"}

    def send(self, alert: SecurityAlert) -> bool:
        """Send the alert to Slack. Returns True on success, False otherwise."""
        if not self.is_configured:
            logger.debug("[slack] Webhook not configured; skipping.")
            return False

        payload = self.build_payload(alert)
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            self.webhook_url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                status = resp.getcode()
                if status in (200, 204):
                    logger.info("[slack] Alert sent successfully for event %s", alert.event_id)
                    return True
                logger.warning("[slack] Unexpected status %d sending alert for %s", status, alert.event_id)
                return False
        except Exception as exc:
            logger.error("[slack] Failed to deliver alert for %s: %s", alert.event_id, exc)
            return False


class DiscordAlerter:
    """Dispatches security alerts to Discord using Webhook Embeds."""

    def __init__(self, webhook_url: Optional[str] = None, timeout_seconds: float = 5.0):
        self._webhook_url = webhook_url
        self.timeout = timeout_seconds

    @property
    def webhook_url(self) -> str:
        if self._webhook_url is not None:
            return self._webhook_url
        return os.environ.get("DISCORD_WEBHOOK_URL", "").strip()

    @property
    def is_configured(self) -> bool:
        return bool(self.webhook_url)

    def build_payload(self, alert: SecurityAlert) -> Dict[str, Any]:
        """Build Discord embed payload."""
        sev = alert.severity.upper()
        # Discord embed color codes in decimal
        color_map = {
            "CRITICAL": 0xDC2626,  # Red
            "HIGH": 0xEA580C,      # Orange
            "MEDIUM": 0xEAB308,    # Yellow
            "LOW": 0x3B82F6,       # Blue
            "INFO": 0x64748B,      # Slate Gray
        }
        color = color_map.get(sev, 0xDC2626)

        techs_str = ", ".join(alert.mitre_techniques) if alert.mitre_techniques else "None"
        remediation_str = (
            "\n".join(f"• {r}" for r in alert.recommended_remediation[:4])
            if alert.recommended_remediation
            else "Monitor host activity."
        )

        embed = {
            "title": f"🚨 [CyberShield AI] {sev} Incident Detected",
            "description": alert.ai_summary or "Suspicious activity requiring SOC attention.",
            "color": color,
            "fields": [
                {"name": "Event Type", "value": f"`{alert.event_type}`", "inline": True},
                {"name": "Risk Score", "value": f"`{alert.risk_score}/100`", "inline": True},
                {"name": "Severity", "value": f"`{sev}`", "inline": True},
                {"name": "Source IP", "value": f"`{alert.source_ip}`", "inline": True},
                {"name": "Host", "value": f"`{alert.host}`", "inline": True},
                {"name": "Service", "value": f"`{alert.service}`", "inline": True},
                {"name": "MITRE ATT&CK", "value": f"`{techs_str}`", "inline": False},
                {"name": "Recommended Remediation", "value": remediation_str, "inline": False},
            ],
            "footer": {
                "text": f"Event ID: {alert.event_id} | CyberShield AI SOC Engine",
            },
        }

        return {
            "content": f"**[CyberShield AI Alert]** {sev} Incident on `{alert.host}`",
            "embeds": [embed],
        }

    def send(self, alert: SecurityAlert) -> bool:
        """Send the alert to Discord. Returns True on success, False otherwise."""
        if not self.is_configured:
            logger.debug("[discord] Webhook not configured; skipping.")
            return False

        payload = self.build_payload(alert)
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            self.webhook_url,
            data=data,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "CyberShield-Alerter/1.0",
            },
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                status = resp.getcode()
                if status in (200, 204):
                    logger.info("[discord] Alert sent successfully for event %s", alert.event_id)
                    return True
                logger.warning("[discord] Unexpected status %d sending alert for %s", status, alert.event_id)
                return False
        except Exception as exc:
            logger.error("[discord] Failed to deliver alert for %s: %s", alert.event_id, exc)
            return False


class EmailAlerter:
    """Dispatches security alerts via SMTP email."""

    def __init__(
        self,
        smtp_host: Optional[str] = None,
        smtp_port: Optional[int] = None,
        smtp_user: Optional[str] = None,
        smtp_password: Optional[str] = None,
        smtp_use_tls: Optional[bool] = None,
        alert_to: Optional[str] = None,
        alert_from: Optional[str] = None,
        timeout_seconds: float = 10.0,
    ):
        self._host = smtp_host
        self._port = smtp_port
        self._user = smtp_user
        self._password = smtp_password
        self._use_tls = smtp_use_tls
        self._alert_to = alert_to
        self._alert_from = alert_from
        self.timeout = timeout_seconds
        self._recipients: Optional[List[Dict[str, Any]]] = None
        if alert_to:
            self._recipients = [
                {"email": addr.strip(), "enabled": True}
                for addr in alert_to.split(",")
                if addr.strip()
            ]

    def _parse_recipients_from_env(self) -> List[Dict[str, Any]]:
        raw = os.environ.get("ALERT_EMAIL_TO", "").strip()
        if not raw:
            return []
        return [{"email": addr.strip(), "enabled": True} for addr in raw.split(",") if addr.strip()]

    def get_recipients(self) -> List[Dict[str, Any]]:
        """Returns list of all recipient dictionaries: [{'email': '...', 'enabled': bool}, ...]"""
        if self._recipients is None:
            self._recipients = self._parse_recipients_from_env()
        return [dict(r) for r in self._recipients]

    def get_active_recipients(self) -> List[str]:
        """Returns list of currently enabled recipient email strings."""
        return [r["email"] for r in self.get_recipients() if r.get("enabled", True)]

    def set_recipients(self, recipients: Union[List[Dict[str, Any]], List[str], str]) -> List[Dict[str, Any]]:
        """Set the entire recipient distribution list with enabled flags."""
        parsed: List[Dict[str, Any]] = []
        if isinstance(recipients, str):
            for addr in recipients.split(","):
                a = addr.strip()
                if a:
                    parsed.append({"email": a, "enabled": True})
        elif isinstance(recipients, list):
            for item in recipients:
                if isinstance(item, str):
                    a = item.strip()
                    if a:
                        parsed.append({"email": a, "enabled": True})
                elif isinstance(item, dict) and "email" in item:
                    a = str(item["email"]).strip()
                    if a:
                        parsed.append({"email": a, "enabled": bool(item.get("enabled", True))})
        self._recipients = parsed
        self._alert_to = ",".join(self.get_active_recipients())
        return self.get_recipients()

    def add_recipient(self, email: str, enabled: bool = True) -> bool:
        """Add a recipient if not already present, or update enabled state."""
        clean = email.strip()
        if not clean or "@" not in clean:
            return False
        recipients = self.get_recipients()
        for r in recipients:
            if r["email"].lower() == clean.lower():
                r["enabled"] = enabled
                self._recipients = recipients
                self._alert_to = ",".join(self.get_active_recipients())
                return True
        recipients.append({"email": clean, "enabled": enabled})
        self._recipients = recipients
        self._alert_to = ",".join(self.get_active_recipients())
        return True

    def remove_recipient(self, email: str) -> bool:
        """Remove a recipient from the list."""
        clean = email.strip().lower()
        recipients = [r for r in self.get_recipients() if r["email"].lower() != clean]
        self._recipients = recipients
        self._alert_to = ",".join(self.get_active_recipients())
        return True

    def toggle_recipient(self, email: str, enabled: Optional[bool] = None) -> bool:
        """Toggle or set enabled state for a specific recipient."""
        clean = email.strip().lower()
        recipients = self.get_recipients()
        res = False
        found = False
        for r in recipients:
            if r["email"].lower() == clean:
                if enabled is None:
                    r["enabled"] = not r.get("enabled", True)
                else:
                    r["enabled"] = bool(enabled)
                res = r["enabled"]
                found = True
                break
        if not found:
            new_state = True if enabled is None else bool(enabled)
            recipients.append({"email": email.strip(), "enabled": new_state})
            res = new_state
        self._recipients = recipients
        self._alert_to = ",".join(self.get_active_recipients())
        return res

    @property
    def host(self) -> str:
        return self._host if self._host is not None else os.environ.get("SMTP_HOST", "").strip()

    @property
    def port(self) -> int:
        if self._port is not None:
            return self._port
        try:
            return int(os.environ.get("SMTP_PORT", "587"))
        except (ValueError, TypeError):
            return 587

    @property
    def user(self) -> str:
        return self._user if self._user is not None else os.environ.get("SMTP_USERNAME", "").strip()

    @property
    def password(self) -> str:
        return self._password if self._password is not None else os.environ.get("SMTP_PASSWORD", "").strip()

    @property
    def use_tls(self) -> bool:
        if self._use_tls is not None:
            return self._use_tls
        return os.environ.get("SMTP_USE_TLS", "true").lower() in ("true", "1", "yes")

    @property
    def to_email(self) -> str:
        active = self.get_active_recipients()
        if active:
            return ", ".join(active)
        if self._alert_to is not None:
            return self._alert_to
        return os.environ.get("ALERT_EMAIL_TO", "").strip()

    @property
    def from_email(self) -> str:
        if self._alert_from is not None:
            return self._alert_from
        return os.environ.get("ALERT_EMAIL_FROM", "").strip() or self.user or "alerts@cybershield.ai"

    @property
    def is_configured(self) -> bool:
        return bool(self.host and (self.get_recipients() or os.environ.get("ALERT_EMAIL_TO", "").strip()))

    def build_message(self, alert: SecurityAlert) -> tuple[str, str, str]:
        """
        Builds (subject, text_body, html_body).
        """
        sev = alert.severity.upper()
        subject = f"[CyberShield][{sev}] Security Incident Detected: {alert.event_type}"

        # Severity visual tokens
        sev_color_map = {
            "CRITICAL": {"bg": "#ef4444", "text": "#ffffff"},
            "HIGH":     {"bg": "#f97316", "text": "#ffffff"},
            "MEDIUM":   {"bg": "#f59e0b", "text": "#ffffff"},
            "LOW":      {"bg": "#3b82f6", "text": "#ffffff"},
            "INFO":     {"bg": "#64748b", "text": "#ffffff"},
        }
        sev_style = sev_color_map.get(sev, {"bg": "#ef4444", "text": "#ffffff"})

        techs_str = ", ".join(alert.mitre_techniques) if alert.mitre_techniques else "None"
        tactics_str = ", ".join(alert.mitre_tactics) if alert.mitre_tactics else "None"

        remediation_lines = "\n".join(f"  - {r}" for r in alert.recommended_remediation) or "  - No specific actions provided"
        remediation_items = [
            f'<li style="margin-bottom: 6px; color: #14532d; font-size: 13px; line-height: 1.5;">{r}</li>'
            for r in alert.recommended_remediation
        ]
        remediation_html = "".join(remediation_items) or '<li style="margin-bottom: 6px; color: #14532d; font-size: 13px; line-height: 1.5;">Review host and network activity for anomalies.</li>'

        text_body = f"""CyberShield AI Security Incident Alert
======================================================================
Severity:       {sev}
Risk Score:     {alert.risk_score}/100
Event Type:     {alert.event_type}
Timestamp:      {alert.timestamp}
Source IP:      {alert.source_ip}
Host / Service: {alert.host} / {alert.service}
MITRE ATT&CK:   {techs_str} ({tactics_str})
Event ID:       {alert.event_id}

AI Analysis / Rationale:
----------------------------------------------------------------------
{alert.ai_summary or "No summary provided."}

Recommended Remediation:
----------------------------------------------------------------------
{remediation_lines}

======================================================================
Generated automatically by CyberShield AI Autonomous SOC Engine.
"""

        html_body = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="color-scheme" content="light">
<title>[CyberShield AI] Security Incident Alert</title>
<style>
  body {{ margin: 0; padding: 0; background-color: #f1f5f9; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; -webkit-font-smoothing: antialiased; }}
  table {{ border-collapse: collapse; }}
  .container {{ max-width: 600px; margin: 20px auto; background-color: #ffffff; border-radius: 8px; overflow: hidden; border: 1px solid #e2e8f0; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.05); }}
  .header-bar {{ height: 4px; background-color: {sev_style['bg']}; }}
  .content {{ padding: 24px; }}
  .title-row {{ margin-bottom: 16px; border-bottom: 1px solid #f1f5f9; padding-bottom: 16px; }}
  .title {{ font-size: 18px; font-weight: 700; color: #0f172a; margin: 0 0 10px 0; }}
  .badge {{ display: inline-block; padding: 4px 10px; border-radius: 4px; font-weight: 700; font-size: 11px; background-color: {sev_style['bg']}; color: #ffffff; text-transform: uppercase; letter-spacing: 0.5px; }}
  .pill {{ display: inline-block; padding: 4px 10px; border-radius: 4px; font-size: 12px; background-color: #f8fafc; color: #334155; border: 1px solid #e2e8f0; margin-left: 8px; }}
  .data-table {{ width: 100%; border-collapse: collapse; margin: 16px 0; }}
  .data-table td {{ padding: 9px 12px; border-bottom: 1px solid #f1f5f9; font-size: 13px; vertical-align: top; }}
  .label {{ font-weight: 600; color: #64748b; width: 35%; }}
  .value {{ color: #0f172a; font-weight: 500; }}
  .chip {{ background-color: #f8fafc; color: #0f172a; padding: 2px 7px; border-radius: 4px; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size: 12px; border: 1px solid #e2e8f0; font-weight: 600; }}
  .section-label {{ font-size: 13px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; margin-top: 20px; margin-bottom: 8px; }}
  .analysis-box {{ background-color: #f0f9ff; border: 1px solid #bae6fd; border-left: 4px solid #0284c7; border-radius: 6px; padding: 14px 16px; color: #0c4a6e; font-size: 13px; line-height: 1.6; word-break: break-word; }}
  .remediation-box {{ background-color: #f0fdf4; border: 1px solid #bbf7d0; border-left: 4px solid #16a34a; border-radius: 6px; padding: 14px 16px; color: #14532d; font-size: 13px; line-height: 1.6; }}
  .footer {{ padding: 16px 24px; background-color: #f8fafc; border-top: 1px solid #f1f5f9; text-align: center; font-size: 11px; color: #64748b; line-height: 1.5; }}
</style>
</head>
<body style="margin: 0; padding: 20px; background-color: #f1f5f9; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; -webkit-font-smoothing: antialiased;">
<table width="100%" cellpadding="0" cellspacing="0" border="0" style="background-color: #f1f5f9; width: 100%;">
  <tr>
    <td align="center">
      <div class="container" style="max-width: 600px; margin: 0 auto; background-color: #ffffff; border-radius: 8px; overflow: hidden; border: 1px solid #e2e8f0; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.05); text-align: left;">
        <div class="header-bar" style="height: 4px; background-color: {sev_style['bg']};"></div>
        <div class="content" style="padding: 24px;">
          <div class="title-row" style="margin-bottom: 16px; border-bottom: 1px solid #f1f5f9; padding-bottom: 16px;">
            <h2 class="title" style="font-size: 18px; font-weight: 700; color: #0f172a; margin: 0 0 10px 0;">[CyberShield AI] Security Incident Alert</h2>
            <span class="badge" style="display: inline-block; padding: 4px 10px; border-radius: 4px; font-weight: 700; font-size: 11px; background-color: {sev_style['bg']}; color: #ffffff; text-transform: uppercase; letter-spacing: 0.5px;">{sev}</span>
            <span class="pill" style="display: inline-block; padding: 4px 10px; border-radius: 4px; font-size: 12px; background-color: #f8fafc; color: #334155; border: 1px solid #e2e8f0; margin-left: 8px;">Risk Score: <strong style="color: #0f172a;">{alert.risk_score}/100</strong></span>
          </div>

          <table class="data-table" style="width: 100%; border-collapse: collapse; margin: 16px 0;">
            <tr>
              <td class="label" style="width: 35%; padding: 9px 12px; border-bottom: 1px solid #f1f5f9; font-size: 13px; font-weight: 600; color: #64748b;">Event Type</td>
              <td class="value" style="padding: 9px 12px; border-bottom: 1px solid #f1f5f9; font-size: 13px; color: #0f172a;"><code class="chip" style="background-color: #f8fafc; color: #0f172a; padding: 2px 7px; border-radius: 4px; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size: 12px; border: 1px solid #e2e8f0; font-weight: 600;">{alert.event_type}</code></td>
            </tr>
            <tr>
              <td class="label" style="width: 35%; padding: 9px 12px; border-bottom: 1px solid #f1f5f9; font-size: 13px; font-weight: 600; color: #64748b;">Timestamp</td>
              <td class="value" style="padding: 9px 12px; border-bottom: 1px solid #f1f5f9; font-size: 13px; color: #0f172a; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;">{alert.timestamp}</td>
            </tr>
            <tr>
              <td class="label" style="width: 35%; padding: 9px 12px; border-bottom: 1px solid #f1f5f9; font-size: 13px; font-weight: 600; color: #64748b;">Source IP</td>
              <td class="value" style="padding: 9px 12px; border-bottom: 1px solid #f1f5f9; font-size: 13px; color: #0f172a;"><code class="chip" style="background-color: #f8fafc; color: #0f172a; padding: 2px 7px; border-radius: 4px; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size: 12px; border: 1px solid #e2e8f0; font-weight: 600;">{alert.source_ip}</code></td>
            </tr>
            <tr>
              <td class="label" style="width: 35%; padding: 9px 12px; border-bottom: 1px solid #f1f5f9; font-size: 13px; font-weight: 600; color: #64748b;">Host / Service</td>
              <td class="value" style="padding: 9px 12px; border-bottom: 1px solid #f1f5f9; font-size: 13px; color: #0f172a;"><code class="chip" style="background-color: #f8fafc; color: #0f172a; padding: 2px 7px; border-radius: 4px; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size: 12px; border: 1px solid #e2e8f0;">{alert.host}</code> / <code class="chip" style="background-color: #f8fafc; color: #0f172a; padding: 2px 7px; border-radius: 4px; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size: 12px; border: 1px solid #e2e8f0;">{alert.service}</code></td>
            </tr>
            <tr>
              <td class="label" style="width: 35%; padding: 9px 12px; border-bottom: 1px solid #f1f5f9; font-size: 13px; font-weight: 600; color: #64748b;">MITRE ATT&amp;CK</td>
              <td class="value" style="padding: 9px 12px; border-bottom: 1px solid #f1f5f9; font-size: 13px; color: #0f172a;"><code class="chip" style="background-color: #f8fafc; color: #0f172a; padding: 2px 7px; border-radius: 4px; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size: 12px; border: 1px solid #e2e8f0;">{techs_str}</code></td>
            </tr>
            <tr>
              <td class="label" style="width: 35%; padding: 9px 12px; border-bottom: 1px solid #f1f5f9; font-size: 13px; font-weight: 600; color: #64748b;">Event ID</td>
              <td class="value" style="padding: 9px 12px; border-bottom: 1px solid #f1f5f9; font-size: 13px; color: #0f172a;"><code class="chip" style="background-color: #f8fafc; color: #0f172a; padding: 2px 7px; border-radius: 4px; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size: 12px; border: 1px solid #e2e8f0;">{alert.event_id}</code></td>
            </tr>
          </table>

          <div class="section-label" style="font-size: 13px; font-weight: 700; color: #0284c7; text-transform: uppercase; letter-spacing: 0.5px; margin-top: 20px; margin-bottom: 8px;">AI Analysis &amp; Rationale</div>
          <div class="analysis-box" style="background-color: #f0f9ff; border: 1px solid #bae6fd; border-left: 4px solid #0284c7; border-radius: 6px; padding: 14px 16px; color: #0c4a6e; font-size: 13px; line-height: 1.6; word-break: break-word;">{alert.ai_summary or "Suspicious activity detected."}</div>

          <div class="section-label" style="font-size: 13px; font-weight: 700; color: #16a34a; text-transform: uppercase; letter-spacing: 0.5px; margin-top: 20px; margin-bottom: 8px;">Recommended Remediation</div>
          <div class="remediation-box" style="background-color: #f0fdf4; border: 1px solid #bbf7d0; border-left: 4px solid #16a34a; border-radius: 6px; padding: 14px 16px; color: #14532d; font-size: 13px; line-height: 1.6;">
            <ul style="margin: 0; padding-left: 20px; color: #14532d;">{remediation_html}</ul>
          </div>
        </div>

        <div class="footer" style="padding: 16px 24px; background-color: #f8fafc; border-top: 1px solid #f1f5f9; text-align: center; font-size: 11px; color: #64748b; line-height: 1.5;">
          CyberShield AI Autonomous SOC &bull; Automated Telemetry Notification<br>
          <span style="color: #94a3b8;">Generated automatically from real-time endpoint and network sensor analysis.</span>
        </div>
      </div>
    </td>
  </tr>
</table>
</body>
</html>"""

        return subject, text_body, html_body

    def send(self, alert: SecurityAlert, override_recipients: Optional[List[str]] = None) -> bool:
        """Send email alert via SMTP. Returns True on success, False otherwise."""
        if not self.is_configured:
            logger.debug("[email] SMTP not configured; skipping.")
            return False

        recipients = [
            addr.strip()
            for addr in (override_recipients if override_recipients is not None else self.get_active_recipients())
            if addr.strip()
        ]
        if not recipients:
            logger.warning("[email] No active recipients configured; skipping alert %s", alert.event_id)
            return False

        subject, text_body, html_body = self.build_message(alert)

        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = self.from_email
        msg["To"] = ", ".join(recipients)
        msg.attach(MIMEText(text_body, "plain", "utf-8"))
        msg.attach(MIMEText(html_body, "html", "utf-8"))

        try:
            with smtplib.SMTP(self.host, self.port, timeout=self.timeout) as server:
                server.ehlo()
                if self.use_tls:
                    server.starttls()
                    server.ehlo()
                if self.user and self.password:
                    server.login(self.user, self.password)
                server.sendmail(self.from_email, recipients, msg.as_string())
            logger.info("[email] Alert sent successfully for event %s to %s", alert.event_id, ", ".join(recipients))
            return True
        except Exception as exc:
            logger.error("[email] Failed to send alert email for %s: %s", alert.event_id, exc)
            return False


class AlertManager:
    """
    Central Alert Manager coordinating Slack, Discord, and Email alerts.

    Applies threshold filtering (risk score / severity) and deduplication.
    Dispatches alerts in non-blocking background threads by default.
    """

    def __init__(
        self,
        slack: Optional[SlackAlerter] = None,
        discord: Optional[DiscordAlerter] = None,
        email: Optional[EmailAlerter] = None,
        min_risk_score: Optional[int] = None,
        min_severity: Optional[str] = None,
        dedup_window_seconds: Optional[int] = None,
    ):
        self.slack = slack if slack is not None else SlackAlerter()
        self.discord = discord if discord is not None else DiscordAlerter()
        self.email = email if email is not None else EmailAlerter()

        # Configurable alert threshold
        if min_risk_score is not None:
            self.min_risk_score = min_risk_score
        else:
            try:
                self.min_risk_score = int(os.environ.get("ALERT_MIN_RISK_SCORE", "80"))
            except ValueError:
                self.min_risk_score = 80

        if min_severity is not None:
            self.min_severity = min_severity.lower()
        else:
            self.min_severity = os.environ.get("ALERT_MIN_SEVERITY", "high").lower()

        if dedup_window_seconds is not None:
            self.dedup_window = dedup_window_seconds
        else:
            try:
                self.dedup_window = int(os.environ.get("ALERT_DEDUP_WINDOW", "300"))
            except ValueError:
                self.dedup_window = 300

        # Channel enabled state (can be configured via env or toggled at runtime)
        self.channel_enabled: Dict[str, bool] = {
            "slack": os.environ.get("SLACK_ENABLED", "true").lower() in ("true", "1", "yes"),
            "discord": os.environ.get("DISCORD_ENABLED", "true").lower() in ("true", "1", "yes"),
            "email": os.environ.get("EMAIL_ENABLED", "true").lower() in ("true", "1", "yes"),
        }

        # In-memory deduplication cache: {key: timestamp}
        self._cache: Dict[str, float] = {}
        self._history: List[Dict[str, Any]] = []
        self._lock = threading.Lock()

    def toggle_channel(self, channel: str, enabled: Optional[bool] = None) -> bool:
        """Toggle or set enabled state for an alert channel at runtime."""
        ch = channel.lower()
        if ch not in self.channel_enabled:
            raise ValueError(f"Unknown channel '{channel}'; valid channels are: {list(self.channel_enabled.keys())}")
        if enabled is None:
            self.channel_enabled[ch] = not self.channel_enabled[ch]
        else:
            self.channel_enabled[ch] = bool(enabled)
        return self.channel_enabled[ch]

    def _dedup_key(self, alert: SecurityAlert) -> str:
        """Create a deduplication key."""
        if alert.event_id and alert.event_id != "unknown":
            return f"id:{alert.event_id}"
        return f"sig:{alert.event_type}:{alert.source_ip}:{alert.host}"

    def should_alert(self, alert: SecurityAlert, record: bool = False) -> bool:
        """
        Evaluate if alert meets severity/risk thresholds and is not a duplicate.
        If record=True, records this event in the deduplication cache if accepted.
        """
        sev_rank = SEVERITY_RANKS.get(alert.severity.lower(), 0)
        min_sev_rank = SEVERITY_RANKS.get(self.min_severity.lower(), 3)  # default 'high' = 3

        # Match policy if risk_score >= threshold OR severity rank meets minimum
        score_meets = alert.risk_score >= self.min_risk_score
        severity_meets = sev_rank >= min_sev_rank

        if not (score_meets or severity_meets):
            logger.debug(
                "[alerter] Skipping alert for %s (score=%d < %d and sev=%s < %s)",
                alert.event_id,
                alert.risk_score,
                self.min_risk_score,
                alert.severity,
                self.min_severity,
            )
            return False

        # Deduplication check
        key = self._dedup_key(alert)
        now = time.time()
        with self._lock:
            # Clean expired cache entries occasionally
            expired = [k for k, ts in self._cache.items() if now - ts > self.dedup_window]
            for k in expired:
                del self._cache[k]

            if key in self._cache:
                logger.info("[alerter] Suppressing duplicate alert for key '%s'", key)
                return False

            if record:
                self._cache[key] = now

        return True

    def _dispatch_all(self, alert: SecurityAlert, email_recipients: Optional[List[str]] = None) -> Dict[str, bool]:
        """Directly invokes all configured and enabled alerters and records to history."""
        slack_sent = False
        if self.channel_enabled.get("slack", True):
            slack_sent = self.slack.send(alert)

        discord_sent = False
        if self.channel_enabled.get("discord", True):
            discord_sent = self.discord.send(alert)

        email_sent = False
        if self.channel_enabled.get("email", True):
            if email_recipients is not None:
                email_sent = self.email.send(alert, override_recipients=email_recipients)
            else:
                email_sent = self.email.send(alert)

        results = {
            "slack": slack_sent,
            "discord": discord_sent,
            "email": email_sent,
        }
        with self._lock:
            self._history.insert(0, {
                "event_id": alert.event_id,
                "timestamp": alert.timestamp,
                "event_type": alert.event_type,
                "severity": alert.severity,
                "risk_score": alert.risk_score,
                "source_ip": alert.source_ip,
                "host": alert.host,
                "service": alert.service,
                "ai_summary": alert.ai_summary,
                "results": results,
            })
            if len(self._history) > 50:
                self._history = self._history[:50]
        return results

    def get_status(self) -> Dict[str, Any]:
        """Return status of all alert channels, policy settings, and recent history."""
        slack_active = self.slack.is_configured and self.channel_enabled.get("slack", True)
        discord_active = self.discord.is_configured and self.channel_enabled.get("discord", True)
        email_active = self.email.is_configured and self.channel_enabled.get("email", True)
        active_count = sum([1 if slack_active else 0, 1 if discord_active else 0, 1 if email_active else 0])
        with self._lock:
            history = list(self._history)

        return {
            "active_channels_count": active_count,
            "channels": {
                "slack": {
                    "configured": self.slack.is_configured,
                    "enabled": self.channel_enabled.get("slack", True),
                    "active": slack_active,
                    "name": "Slack",
                },
                "discord": {
                    "configured": self.discord.is_configured,
                    "enabled": self.channel_enabled.get("discord", True),
                    "active": discord_active,
                    "name": "Discord",
                },
                "email": {
                    "configured": self.email.is_configured,
                    "enabled": self.channel_enabled.get("email", True),
                    "active": email_active,
                    "name": "Email (SMTP)",
                    "host": self.email.host if self.email.is_configured else "",
                    "to": self.email.to_email if self.email.is_configured else "",
                    "recipients": self.email.get_recipients(),
                    "active_recipients": self.email.get_active_recipients(),
                    "active_recipients_count": len(self.email.get_active_recipients()),
                },
            },
            "policy": {
                "min_risk_score": self.min_risk_score,
                "min_severity": self.min_severity,
                "dedup_window_seconds": self.dedup_window,
            },
            "history": history,
        }

    def send_alert(
        self,
        alert: SecurityAlert,
        sync: bool = False,
        email_recipients: Optional[List[str]] = None,
    ) -> Optional[Dict[str, bool]]:
        """
        Main entrypoint for sending an alert.
        If sync=True, executes synchronously (primarily for unit tests and CLI).
        If sync=False (default), spawns execution in a background daemon thread
        so calling routes and honeypots are never delayed.
        """
        if not self.should_alert(alert, record=True):
            return None

        if sync:
            return self._dispatch_all(alert, email_recipients=email_recipients)

        worker = threading.Thread(
            target=self._dispatch_all,
            args=(alert, email_recipients),
            daemon=True,
            name=f"alert-dispatch-{alert.event_id[:8]}",
        )
        worker.start()
        return None

    def process_investigation(self, inv: Any, sync: bool = False) -> Optional[Dict[str, bool]]:
        """
        Inspect an AI Investigation object and dispatch security alerts if thresholds are met.
        Safe against any unexpected investigation exceptions.
        """
        try:
            alert = SecurityAlert.from_investigation(inv)
            return self.send_alert(alert, sync=sync)
        except Exception as exc:
            logger.error("[alerter] Unexpected error processing investigation: %s", exc)
            return None

    def process_security_alert(self, alert: SecurityAlert, sync: bool = False) -> Optional[Dict[str, bool]]:
        """Process an existing SecurityAlert object directly."""
        try:
            return self.send_alert(alert, sync=sync)
        except Exception as exc:
            logger.error("[alerter] Unexpected error processing security alert: %s", exc)
            return None


# Global singleton instance
_GLOBAL_ALERT_MANAGER: Optional[AlertManager] = None
_ALERT_MANAGER_LOCK = threading.Lock()


def get_alert_manager() -> AlertManager:
    """Get or initialize the global AlertManager singleton."""
    global _GLOBAL_ALERT_MANAGER
    if _GLOBAL_ALERT_MANAGER is None:
        with _ALERT_MANAGER_LOCK:
            if _GLOBAL_ALERT_MANAGER is None:
                _GLOBAL_ALERT_MANAGER = AlertManager()
    return _GLOBAL_ALERT_MANAGER


def reset_alert_manager() -> None:
    """Reset the singleton instance (used in tests)."""
    global _GLOBAL_ALERT_MANAGER
    with _ALERT_MANAGER_LOCK:
        _GLOBAL_ALERT_MANAGER = None
