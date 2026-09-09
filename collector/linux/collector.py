import time
import re
import json
import os
import socket
import urllib.error
import urllib.request
from collections import defaultdict
from datetime import datetime
from pathlib import Path

from risk_scoring import score_event

LOG_FILE = "/var/log/auth.log"
ALERT_LOG = Path.home() / "soc-testing" / "logs" / "alerts.jsonl"
EVENT_LOG = Path.home() / "soc-testing" / "logs" / "events.jsonl"
API_URL = os.environ.get("ARGUS_API_URL", "http://127.0.0.1:8000/api/v1/logs")
HOSTNAME = socket.gethostname()

AUTH_FAILURE_PATTERN = r"Failed password for (?:invalid user )?(\w+) from ([\d.]+)"
AUTH_SUCCESS_PATTERN = r"Accepted password for (\w+) from ([\d.]+)"
SUDO_FAILURE_PATTERN = r"sudo:.*authentication failure.*user=(\w+)"
USER_ADD_PATTERN = r"new user: name=([a-z_][a-z0-9_-]*),"
INVALID_USER_PATTERN = r"Invalid user (\w+) from ([\d.]+)"
PASSWORD_CHANGE_PATTERN = r"passwd.*?for user (\w+)"
SUDO_SESSION_PATTERN = r"sudo:\s+(\w+)\s+:.*COMMAND=(.+)"

failed_attempts_by_ip = defaultdict(list)
failed_attempts_by_user = defaultdict(list)
known_events = set()


def parse_auth_failure(line):
    match = re.search(AUTH_FAILURE_PATTERN, line)
    if not match:
        return None
    return {
        "event_type": "AUTH_FAILURE",
        "user": match.group(1),
        "source_ip": match.group(2),
        "raw": line
    }


def parse_auth_success(line):
    match = re.search(AUTH_SUCCESS_PATTERN, line)
    if not match:
        return None
    return {
        "event_type": "AUTH_SUCCESS",
        "user": match.group(1),
        "source_ip": match.group(2),
        "raw": line
    }


def parse_sudo_failure(line):
    match = re.search(SUDO_FAILURE_PATTERN, line)
    if not match:
        return None
    return {
        "event_type": "SUDO_FAILURE",
        "user": match.group(1),
        "raw": line
    }


def parse_user_creation(line):
    match = re.search(USER_ADD_PATTERN, line, re.IGNORECASE)
    if not match:
        return None
    return {
        "event_type": "USER_CREATED",
        "user": match.group(1),
        "raw": line
    }


def parse_invalid_user(line):
    match = re.search(INVALID_USER_PATTERN, line)
    if not match:
        return None
    return {
        "event_type": "INVALID_USER",
        "user": match.group(1),
        "source_ip": match.group(2),
        "raw": line
    }


def parse_password_change(line):
    match = re.search(PASSWORD_CHANGE_PATTERN, line)
    if not match:
        return None
    return {
        "event_type": "PASSWORD_CHANGE",
        "user": match.group(1),
        "raw": line
    }


def parse_sudo_session(line):
    match = re.search(SUDO_SESSION_PATTERN, line)
    if not match:
        return None
    return {
        "event_type": "PRIV_ESCALATION",
        "user": match.group(1),
        "command": match.group(2),
        "raw": line
    }


PARSERS = [
    parse_auth_failure,
    parse_auth_success,
    parse_sudo_failure,
    parse_user_creation,
    parse_invalid_user,
    parse_password_change,
    parse_sudo_session,
]


def parse_log(line):
    for parser in PARSERS:
        event = parser(line)
        if event:
            return event
    return None


def check_brute_force(event):
    alerts = []
    if event["event_type"] != "AUTH_FAILURE":
        return alerts

    now = datetime.now()
    ip = event.get("source_ip")
    user = event.get("user")

    if ip:
        recent = [t for t in failed_attempts_by_ip[ip] if (now - t).total_seconds() < 60]
        failed_attempts_by_ip[ip] = recent
        failed_attempts_by_ip[ip].append(now)
        if len(recent) >= 5:
            alerts.append({
                "alert_type": "BRUTE_FORCE_BY_IP",
                "source_ip": ip,
                "attempts": len(recent),
                "window_seconds": 60,
                "severity": "CRITICAL"
            })

    if user:
        recent = [t for t in failed_attempts_by_user[user] if (now - t).total_seconds() < 300]
        failed_attempts_by_user[user] = recent
        failed_attempts_by_user[user].append(now)
        if len(recent) >= 5:
            alerts.append({
                "alert_type": "BRUTE_FORCE_BY_USER",
                "target_user": user,
                "attempts": len(recent),
                "window_seconds": 300,
                "severity": "HIGH"
            })

    return alerts


def write_jsonl(filepath, payload):
    filepath.parent.mkdir(parents=True, exist_ok=True)
    with open(filepath, "a", encoding="utf-8") as f:
        f.write(json.dumps(payload) + "\n")


def _severity_from_risk(risk_level):
    return (risk_level or "low").lower()


def _normalize_event(event, risk_level):
    details = {}
    if event.get("command"):
        details["command"] = event["command"]
    return {
        "event_id": f"{event['event_type']}:{event.get('user', 'unknown')}:{int(time.time() * 1000)}",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "host": HOSTNAME,
        "source": "linux_auth",
        "event_type": event.get("event_type", "UNKNOWN"),
        "severity": _severity_from_risk(risk_level),
        "actor": {
            "source_ip": event.get("source_ip", ""),
            "user": event.get("user", ""),
        },
        "target": {
            "host": HOSTNAME,
            "service": "ssh",
        },
        "details": details,
        "raw": event.get("raw", ""),
    }


def post_to_api(event, risk_level, brute_force_detected=False):
    payload = {
        "event": _normalize_event(event, risk_level),
        "brute_force_detected": brute_force_detected,
    }
    request = urllib.request.Request(
        API_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            body = response.read().decode("utf-8", errors="ignore")
            print(json.dumps({"api_forwarded": True, "status": response.status, "body": body[:400]}))
    except urllib.error.URLError as exc:
        print(json.dumps({"api_forwarded": False, "error": str(exc), "url": API_URL}))


def stream_and_collect():
    print(f"[SOC] Monitoring: {LOG_FILE}")
    print(f"[SOC] Alerts:     {ALERT_LOG}")
    print(f"[SOC] Events:     {EVENT_LOG}")

    try:
        with open(LOG_FILE, "r") as f:
            f.seek(0, 2)
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.2)
                    continue

                line = line.strip()
                event = parse_log(line)
                if not event:
                    continue

                event_key = f"{event['event_type']}:{event.get('user')}:{event.get('source_ip')}:{line[:80]}"
                if event_key in known_events:
                    continue
                known_events.add(event_key)

                if len(known_events) > 5000:
                    known_events.clear()

                scored = score_event(event)
                output = {
                    "timestamp": datetime.utcnow().isoformat(),
                    "event": event,
                    "risk": {
                        "score": scored["risk_score"],
                        "level": scored["risk_level"],
                        "reasons": scored["reasons"]
                    }
                }
                write_jsonl(EVENT_LOG, output)
                print(json.dumps(output))
                post_to_api(event, scored["risk_level"], brute_force_detected=False)

                if scored["risk_level"] in ["HIGH", "MEDIUM"]:
                    alert = {
                        "timestamp": scored["scored_at"],
                        "alert_type": "RISK_THRESHOLD",
                        "risk_level": scored["risk_level"],
                        "risk_score": scored["risk_score"],
                        "reasons": scored["reasons"],
                        "event": event
                    }
                    write_jsonl(ALERT_LOG, alert)

                bf_alerts = check_brute_force(event)
                for bf in bf_alerts:
                    bf["timestamp"] = datetime.utcnow().isoformat()
                    bf["trigger_event"] = event
                    write_jsonl(ALERT_LOG, bf)
                    print(json.dumps({"alert": bf}))
                    post_to_api(event, bf.get("severity", "HIGH"), brute_force_detected=True)

    except KeyboardInterrupt:
        print("\n[SOC] Stopped by user")
    except FileNotFoundError:
        print(f"[SOC] Log file not found: {LOG_FILE}")
        print("[SOC] Run with sudo to access system logs")
    except PermissionError:
        print(f"[SOC] Permission denied: {LOG_FILE}")
        print("[SOC] Run with sudo")


if __name__ == "__main__":
    stream_and_collect()
