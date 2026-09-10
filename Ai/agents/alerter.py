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
        self.webhook_url = webhook_url if webhook_url is not None else os.environ.get("SLACK_WEBHOOK_URL", "").strip()
        self.timeout = timeout_seconds

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
        self.webhook_url = webhook_url if webhook_url is not None else os.environ.get("DISCORD_WEBHOOK_URL", "").strip()
        self.timeout = timeout_seconds

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
        self.host = smtp_host if smtp_host is not None else os.environ.get("SMTP_HOST", "").strip()
        
        port_raw = os.environ.get("SMTP_PORT", "587") if smtp_port is None else smtp_port
        try:
            self.port = int(port_raw)
        except (ValueError, TypeError):
            self.port = 587

        self.user = smtp_user if smtp_user is not None else os.environ.get("SMTP_USERNAME", "").strip()
        self.password = smtp_password if smtp_password is not None else os.environ.get("SMTP_PASSWORD", "").strip()

        if smtp_use_tls is not None:
            self.use_tls = smtp_use_tls
        else:
            self.use_tls = os.environ.get("SMTP_USE_TLS", "true").lower() in ("true", "1", "yes")

        self.to_email = alert_to if alert_to is not None else os.environ.get("ALERT_EMAIL_TO", "").strip()
        self.from_email = (
            alert_from
            if alert_from is not None
            else (os.environ.get("ALERT_EMAIL_FROM", "").strip() or self.user or "alerts@cybershield.ai")
        )
        self.timeout = timeout_seconds

    @property
    def is_configured(self) -> bool:
        return bool(self.host and self.to_email)

    def build_message(self, alert: SecurityAlert) -> tuple[str, str, str]:
        """
        Builds (subject, text_body, html_body).
        """
        sev = alert.severity.upper()
        subject = f"[CyberShield][{sev}] Security Incident Detected: {alert.event_type}"

        techs_str = ", ".join(alert.mitre_techniques) if alert.mitre_techniques else "None"
        tactics_str = ", ".join(alert.mitre_tactics) if alert.mitre_tactics else "None"

        remediation_lines = "\n".join(f"  - {r}" for r in alert.recommended_remediation) or "  - No specific actions provided"
        remediation_html = "".join(f"<li>{r}</li>" for r in alert.recommended_remediation) or "<li>Review host activity</li>"

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
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background-color: #0f172a; color: #f8fafc; padding: 20px; }}
  .container {{ max-width: 600px; margin: auto; background-color: #1e293b; border-radius: 8px; padding: 24px; border: 1px solid #334155; }}
  .header {{ border-bottom: 2px solid #ef4444; padding-bottom: 12px; margin-bottom: 16px; }}
  .header h2 {{ margin: 0; color: #f87171; }}
  .badge {{ display: inline-block; padding: 4px 8px; border-radius: 4px; font-weight: bold; font-size: 12px; background-color: #ef4444; color: white; }}
  table {{ width: 100%; border-collapse: collapse; margin: 16px 0; }}
  td {{ padding: 8px; border-bottom: 1px solid #334155; font-size: 14px; }}
  td.label {{ font-weight: 600; color: #94a3b8; width: 35%; }}
  td.value {{ color: #f1f5f9; }}
  .section-title {{ font-size: 15px; font-weight: bold; color: #38bdf8; margin-top: 16px; margin-bottom: 8px; }}
  .box {{ background: #0f172a; padding: 12px; border-radius: 6px; border: 1px solid #334155; font-size: 13px; line-height: 1.5; }}
  ul {{ margin: 0; padding-left: 20px; }}
  .footer {{ font-size: 11px; color: #64748b; margin-top: 24px; text-align: center; }}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <h2>[CyberShield AI] Security Incident Alert</h2>
    <span class="badge">{sev}</span> &nbsp; <span>Risk Score: <strong>{alert.risk_score}/100</strong></span>
  </div>
  <table>
    <tr><td class="label">Event Type</td><td class="value"><code>{alert.event_type}</code></td></tr>
    <tr><td class="label">Timestamp</td><td class="value">{alert.timestamp}</td></tr>
    <tr><td class="label">Source IP</td><td class="value"><code>{alert.source_ip}</code></td></tr>
    <tr><td class="label">Host / Service</td><td class="value"><code>{alert.host}</code> / <code>{alert.service}</code></td></tr>
    <tr><td class="label">MITRE ATT&CK</td><td class="value"><code>{techs_str}</code></td></tr>
    <tr><td class="label">Event ID</td><td class="value"><code>{alert.event_id}</code></td></tr>
  </table>

  <div class="section-title">AI Analysis</div>
  <div class="box">{alert.ai_summary or "Suspicious activity detected."}</div>

  <div class="section-title">Recommended Remediation</div>
  <div class="box">
    <ul>{remediation_html}</ul>
  </div>

  <div class="footer">CyberShield AI Autonomous SOC &bull; Automated Telemetry Notification</div>
</div>
</body>
</html>"""

        return subject, text_body, html_body

    def send(self, alert: SecurityAlert) -> bool:
        """Send email alert via SMTP. Returns True on success, False otherwise."""
        if not self.is_configured:
            logger.debug("[email] SMTP not configured; skipping.")
            return False

        subject, text_body, html_body = self.build_message(alert)

        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = self.from_email
        msg["To"] = self.to_email
        msg.attach(MIMEText(text_body, "plain", "utf-8"))
        msg.attach(MIMEText(html_body, "html", "utf-8"))

        try:
            recipients = [addr.strip() for addr in self.to_email.split(",") if addr.strip()]
            with smtplib.SMTP(self.host, self.port, timeout=self.timeout) as server:
                server.ehlo()
                if self.use_tls:
                    server.starttls()
                    server.ehlo()
                if self.user and self.password:
                    server.login(self.user, self.password)
                server.sendmail(self.from_email, recipients, msg.as_string())
            logger.info("[email] Alert sent successfully for event %s to %s", alert.event_id, self.to_email)
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
                self.dedup_window = int(os.environ.get("ALERT_DEDUPLICATION_WINDOW_SECONDS", "300"))
            except ValueError:
                self.dedup_window = 300

        # In-memory deduplication cache: {key: timestamp}
        self._cache: Dict[str, float] = {}
        self._lock = threading.Lock()

    def _dedup_key(self, alert: SecurityAlert) -> str:
        """Create a deduplication key."""
        if alert.event_id and alert.event_id != "unknown":
            return f"id:{alert.event_id}"
        return f"sig:{alert.event_type}:{alert.source_ip}:{alert.host}"

    def should_alert(self, alert: SecurityAlert, record: bool = False) -> bool:
        """
        Evaluate alert threshold policy and deduplication.
        If record=True, updates the deduplication cache with the current timestamp.
        """
        sev_rank = SEVERITY_RANKS.get(alert.severity.lower(), 0)
        min_sev_rank = SEVERITY_RANKS.get(self.min_severity, 3)  # default 'high' = 3

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

    def _dispatch_all(self, alert: SecurityAlert) -> Dict[str, bool]:
        """Directly invokes all configured alerters."""
        results = {
            "slack": self.slack.send(alert),
            "discord": self.discord.send(alert),
            "email": self.email.send(alert),
        }
        return results

    def send_alert(self, alert: SecurityAlert, sync: bool = False) -> Optional[Dict[str, bool]]:
        """
        Main entrypoint for sending an alert.
        If sync=True, executes synchronously (primarily for unit tests and CLI).
        If sync=False (default), spawns execution in a background daemon thread
        so calling routes and honeypots are never delayed.
        """
        if not self.should_alert(alert, record=True):
            return None

        if sync:
            return self._dispatch_all(alert)

        worker = threading.Thread(
            target=self._dispatch_all,
            args=(alert,),
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
