import time
import json
import re
import win32evtlog
import subprocess
from collections import defaultdict
from datetime import datetime
from pathlib import Path

from risk_scoring import score_event

OUTPUT_DIR = Path(r"C:\soc-logs")
ALERT_LOG = OUTPUT_DIR / "win.log" / "windows_alerts.jsonl"
EVENT_LOG = OUTPUT_DIR / "win.log" / "windows_events.jsonl"

IP_PATTERN = r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"

CRITICAL_EVENTS = {
    4624: "LOGON_SUCCESS",
    4625: "LOGON_FAILURE",
    4634: "LOGOFF",
    4647: "LOGOFF_INITIATED",
    4648: "LOGON_EXPLICIT",
    4672: "PRIV_ESCALATION",
    4720: "USER_CREATED",
    4722: "USER_ENABLED",
    4723: "PASSWORD_CHANGE",
    4724: "PASSWORD_RESET",
    4725: "USER_DISABLED",
    4726: "USER_DELETED",
    4728: "USER_ADDED_TO_GROUP",
    4732: "USER_ADDED_TO_LOCALGROUP",
    4738: "USER_ACCOUNT_CHANGED",
    4740: "ACCOUNT_LOCKOUT",
    4756: "USER_ADDED_TO_UNIVERSALGROUP",
    4697: "SERVICE_INSTALLED",
    4698: "SCHEDULED_TASK",
    4719: "AUDIT_POLICY_CHANGE",
    1102: "AUDIT_LOG_CLEARED",
    4688: "PROCESS_CREATE",
    7045: "SERVICE_INSTALLED",
    5156: "FIREWALL_ALLOWED",
    5157: "FIREWALL_BLOCKED",
    1: "SYSMON_PROCESS",
    3: "SYSMON_NETWORK",
    7: "SYSMON_IMAGE_LOAD",
    8: "SYSMON_CREATE_REMOTE_THREAD",
    10: "SYSMON_PROCESS_ACCESS",
    11: "SYSMON_FILE_CREATE",
    12: "SYSMON_REGISTRY_CREATE",
    13: "SYSMON_REGISTRY_SET",
    22: "SYSMON_DNS_QUERY",
    25: "SYSMON_TAMPERING",
    4103: "POWERSHELL_SCRIPT",
    4104: "POWERSHELL_SCRIPT_BLOCK",
}

failed_logins_by_user = defaultdict(list)
failed_logins_by_ip = defaultdict(list)
known_events = set()


def setup_logging():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


def extract_ip(text):
    if not text:
        return None
    match = re.search(IP_PATTERN, text)
    return match.group(1) if match else None


def extract_field(text, key):
    if not text:
        return None
    pattern = rf"{re.escape(key)}\s*([^\s\r\n]+)"
    match = re.search(pattern, text)
    return match.group(1) if match else None


def parse_event(log_name, ev_obj):
    event_id = ev_obj.EventID
    source = ev_obj.SourceName
    time_gen = str(ev_obj.TimeGenerated)
    computer = ev_obj.ComputerName

    try:
        msg_parts = ev_obj.StringInserts or []
        message = " | ".join(str(p) for p in msg_parts)
    except Exception:
        message = ""

    event_type = CRITICAL_EVENTS.get(event_id, f"OTHER_{event_id}")

    event = {
        "log": log_name,
        "event_id": event_id,
        "event_type": event_type,
        "source": source,
        "time": time_gen,
        "computer": computer,
        "user": None,
        "source_ip": None,
        "dest_ip": None,
        "dest_port": None,
        "process": None,
        "command": None,
        "service_name": None,
        "task_name": None,
        "message": message[:500],
    }

    if event_id in [4624, 4625, 4634, 4647, 4648, 4672, 4776]:
        event["user"] = extract_field(message, "Account Name:") or extract_field(message, "Account:")
        ip_section = message
        if "Source Network Address:" in message:
            ip_section = message.split("Source Network Address:")[-1]
            ip_section = ip_section.split("|")[0] if "|" in ip_section else ip_section
        event["source_ip"] = extract_ip(ip_section)
        if not event["source_ip"] or event["source_ip"] == "-":
            event["source_ip"] = None

    elif event_id in [4720, 4722, 4723, 4724, 4725, 4726, 4738, 4740]:
        event["user"] = extract_field(message, "Account Name:") or extract_field(message, "Subject:")

    elif event_id in [4728, 4732, 4756]:
        event["user"] = extract_field(message, "Account Name:") or extract_field(message, "Member:")

    elif event_id == 4697:
        event["user"] = extract_field(message, "Subject:")
        event["service_name"] = extract_field(message, "Service Name:")

    elif event_id == 4698:
        event["user"] = extract_field(message, "Subject:")
        task_match = re.search(r"Task Name:\s+(.+?)(?:\||$)", message)
        if task_match:
            event["task_name"] = task_match.group(1).strip()

    elif event_id == 7045:
        event["service_name"] = extract_field(message, "Service Name:")
        event["process"] = extract_field(message, "Image Path:")

    elif event_id == 1:
        proc_match = re.search(r"Image:\s+(.+?)(?:\||$)", message)
        if proc_match:
            event["process"] = proc_match.group(1).strip()
        cmd_match = re.search(r"CommandLine:\s+(.+?)(?:\||$)", message)
        if cmd_match:
            event["command"] = cmd_match.group(1).strip()[:500]

    elif event_id == 3:
        event["source_ip"] = extract_field(message, "SourceIp:")
        event["dest_ip"] = extract_field(message, "DestinationIp:")
        port_match = re.search(r"DestinationPort:\s+(\d+)", message)
        if port_match:
            event["dest_port"] = int(port_match.group(1))

    elif event_id in [4103, 4104]:
        event["user"] = extract_field(message, "User=")
        if not event["user"]:
            event["user"] = extract_field(message, "Account Name:")

    return event


def check_brute_force(event):
    alerts = []
    if event["event_type"] != "LOGON_FAILURE":
        return alerts

    now = datetime.now()
    user = event.get("user")
    ip = event.get("source_ip")

    if user:
        recent = [t for t in failed_logins_by_user[user] if (now - t).total_seconds() < 300]
        failed_logins_by_user[user] = recent
        failed_logins_by_user[user].append(now)
        if len(recent) >= 5:
            alerts.append({
                "alert_type": "BRUTE_FORCE_BY_USER",
                "target_user": user,
                "attempts": len(recent),
                "window_seconds": 300,
                "severity": "HIGH"
            })

    if ip:
        recent = [t for t in failed_logins_by_ip[ip] if (now - t).total_seconds() < 300]
        failed_logins_by_ip[ip] = recent
        failed_logins_by_ip[ip].append(now)
        if len(recent) >= 10:
            alerts.append({
                "alert_type": "BRUTE_FORCE_BY_IP",
                "source_ip": ip,
                "attempts": len(recent),
                "window_seconds": 300,
                "severity": "CRITICAL"
            })

    return alerts


def check_suspicious_patterns(event):
    alerts = []
    event_id = event.get("event_id")
    message = event.get("message", "").lower()

    if event_id == 1102:
        alerts.append({
            "alert_type": "AUDIT_LOG_CLEARED",
            "severity": "CRITICAL",
            "message": "Windows Security log was cleared"
        })

    if event.get("event_type") in ["POWERSHELL_SCRIPT", "POWERSHELL_SCRIPT_BLOCK"]:
        if "-enc" in message or "encodedcommand" in message or "frombase64string" in message:
            alerts.append({
                "alert_type": "ENCODED_POWERSHELL",
                "severity": "HIGH",
                "message": "Encoded PowerShell command detected"
            })
        if "mimikatz" in message:
            alerts.append({
                "alert_type": "MIMIKATZ_DETECTED",
                "severity": "CRITICAL",
                "message": "Mimikatz reference detected"
            })

    if event_id == 4697 or event_id == 7045:
        svc_path = event.get("process", "").lower()
        msg = event.get("message", "").lower()
        if any(p in svc_path or p in msg for p in ["\\temp\\", "\\appdata\\", "\\downloads\\", "\\public\\"]):
            alerts.append({
                "alert_type": "SUSPICIOUS_SERVICE",
                "severity": "HIGH",
                "service": event.get("service_name"),
                "message": "Service installed from suspicious location"
            })

    return alerts


def write_jsonl(filepath, payload):
    filepath.parent.mkdir(parents=True, exist_ok=True)
    with open(filepath, "a", encoding="utf-8") as f:
        f.write(json.dumps(payload) + "\n")


def poll_log(log_name, max_events=100):
    events = []
    try:
        hand = win32evtlog.OpenEventLog(None, log_name)
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        raw_events = win32evtlog.ReadEventLog(hand, flags, 0)
        for ev_obj in raw_events[:max_events]:
            try:
                events.append(parse_event(log_name, ev_obj))
            except Exception:
                pass
        win32evtlog.CloseEventLog(hand)
    except Exception:
        pass
    return events


def main():
    setup_logging()
    hostname = subprocess.check_output("hostname", shell=True, text=True).strip()
    print(f"[SOC-WIN] Host:       {hostname}")
    print(f"[SOC-WIN] Alerts:     {ALERT_LOG}")
    print(f"[SOC-WIN] Events:     {EVENT_LOG}")

    log_names = [
        "Security",
        "System",
        "Application",
        "Microsoft-Windows-PowerShell/Operational",
        "Microsoft-Windows-Sysmon/Operational",
    ]

    while True:
        try:
            for log_name in log_names:
                events = poll_log(log_name, max_events=50)

                for event in events:
                    if event["event_id"] not in CRITICAL_EVENTS:
                        continue

                    if event["event_id"] == 4624:
                        user_lower = (event.get("user") or "").lower()
                        if user_lower in ["system", "local service", "network service",
                                          "dwm-1", "dwm-2", "umfd-1", "umfd-2"]:
                            continue

                    event_key = f"{event['log']}:{event['event_id']}:{event['time']}:{event['message'][:80]}"
                    if event_key in known_events:
                        continue
                    known_events.add(event_key)

                    if len(known_events) > 10000:
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

                    sus_alerts = check_suspicious_patterns(event)
                    for sus in sus_alerts:
                        sus["timestamp"] = datetime.utcnow().isoformat()
                        sus["trigger_event"] = event
                        write_jsonl(ALERT_LOG, sus)
                        print(json.dumps({"alert": sus}))

            time.sleep(2)

        except KeyboardInterrupt:
            print("\n[SOC-WIN] Stopped by user")
            break
        except Exception as e:
            print(f"[SOC-WIN] Error: {e}")
            time.sleep(5)


if __name__ == "__main__":
    main()
