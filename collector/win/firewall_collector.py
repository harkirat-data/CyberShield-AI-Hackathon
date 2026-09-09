"""
system_collector_windows.py

Windows system/Sysmon event collector.
Reads: System, Microsoft-Windows-Windows Defender/Operational,
       Microsoft-Windows-Sysmon/Operational
Writes: C:\\soc-logs\\windows_system_events.jsonl
        C:\\soc-logs\\windows_system_alerts.jsonl

Run standalone:  python system_collector_windows.py
Run as service:  python system_collector_windows.py --service
"""

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
EVENT_LOG  = OUTPUT_DIR / "win.log"/"windows_events.jsonl"
ALERT_LOG  = OUTPUT_DIR / "win.log"/"windows_alerts.jsonl"

# Event IDs of interest at the system / endpoint level
SYSTEM_EVENTS = {
    104:  "EVENT_LOG_CLEARED",       # System log cleared
    1102: "AUDIT_LOG_CLEARED",       # Security log cleared (if it leaks into other logs)
    7034: "SERVICE_CRASHED",
    7035: "SERVICE_SENT_CONTROL",
    7036: "SERVICE_STATE_CHANGED",
    7040: "SERVICE_START_TYPE_CHANGED",
    7045: "SERVICE_INSTALLED",       # Service installed (persistence)
    1001: "WER_REPORT",
    10016: "DCOM_ERROR",
    5152: "FIREWALL_DROPPED_PACKET",
    5157: "FIREWALL_BLOCKED",
    # Sysmon
    1:    "SYSMON_PROCESS",
    3:    "SYSMON_NETWORK",
    7:    "SYSMON_IMAGE_LOAD",
    8:    "SYSMON_CREATE_REMOTE_THREAD",
    10:   "SYSMON_PROCESS_ACCESS",
    11:   "SYSMON_FILE_CREATE",
    12:   "SYSMON_REGISTRY_CREATE",
    13:   "SYSMON_REGISTRY_SET",
    22:   "SYSMON_DNS_QUERY",
    25:   "SYSMON_TAMPERING",
    # Defender
    1116: "DEFENDER_MALWARE_DETECTED",
    1117: "DEFENDER_ACTION_TAKEN",
    1118: "DEFENDER_SERVICE_FAILED",
    # PowerShell (already in auth collector but include here for completeness)
    4103: "POWERSHELL_SCRIPT",
    4104: "POWERSHELL_SCRIPT_BLOCK",
}

IP_PATTERN = r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"

LOGS_TO_POLL = [
    "System",
    "Microsoft-Windows-Sysmon/Operational",
    "Microsoft-Windows-Windows Defender/Operational",
    "Microsoft-Windows-PowerShell/Operational",
]

known_events = set()
suspicious_ips = defaultdict(lambda: {"events": 0, "ts": []})
known_services = set()


def setup_logging():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


def extract_ip(text):
    if not text:
        return None
    m = re.search(IP_PATTERN, text)
    return m.group(1) if m else None


def extract_field(text, key):
    if not text:
        return None
    m = re.search(rf"{re.escape(key)}\s*([^\s\r\n|]+)", text)
    return m.group(1).strip() if m else None


def parse_event(log_name, ev_obj):
    event_id = ev_obj.EventID
    source   = ev_obj.SourceName
    time_gen = str(ev_obj.TimeGenerated)
    computer = ev_obj.ComputerName

    try:
        msg_parts = ev_obj.StringInserts or []
        message = " | ".join(str(p) for p in msg_parts)
    except Exception:
        message = ""

    event_type = SYSTEM_EVENTS.get(event_id, f"OTHER_{event_id}")

    event = {
        "log":         log_name,
        "event_id":    event_id,
        "event_type":  event_type,
        "source":      source,
        "time":        time_gen,
        "computer":    computer,
        "user":        None,
        "source_ip":   None,
        "dest_ip":     None,
        "dest_port":   None,
        "process":     None,
        "command":     None,
        "service_name": None,
        "task_name":   None,
        "raw_command": None,
        "message":     message[:600],
    }

    # Sysmon Event ID 1 - Process Create
    if event_id == 1:
        m = re.search(r"Image:\s+(.+?)(?:\||$)", message)
        if m:
            event["process"] = m.group(1).strip()
        m = re.search(r"CommandLine:\s+(.+?)(?:\||$)", message)
        if m:
            event["command"] = m.group(1).strip()[:500]
        m = re.search(r"User:\s+(.+?)(?:\||$)", message)
        if m:
            event["user"] = m.group(1).strip()
        m = re.search(r"ParentImage:\s+(.+?)(?:\||$)", message)
        if m:
            event["parent_process"] = m.group(1).strip()

    # Sysmon Event ID 3 - Network Connection
    elif event_id == 3:
        event["source_ip"] = extract_field(message, "SourceIp:")
        event["dest_ip"]   = extract_field(message, "DestinationIp:")
        port_match = re.search(r"DestinationPort:\s+(\d+)", message)
        if port_match:
            event["dest_port"] = int(port_match.group(1))
        m = re.search(r"Image:\s+(.+?)(?:\||$)", message)
        if m:
            event["process"] = m.group(1).strip()

    # Sysmon Event ID 22 - DNS Query
    elif event_id == 22:
        m = re.search(r"QueryName:\s+(.+?)(?:\||$)", message)
        if m:
            event["query_name"] = m.group(1).strip()
        m = re.search(r"Image:\s+(.+?)(?:\||$)", message)
        if m:
            event["process"] = m.group(1).strip()

    # Sysmon Event ID 11/12/13 - File/Registry
    elif event_id in (11, 12, 13):
        m = re.search(r"TargetObject:\s+(.+?)(?:\||$)", message)
        if m:
            event["target_object"] = m.group(1).strip()
        m = re.search(r"Image:\s+(.+?)(?:\||$)", message)
        if m:
            event["process"] = m.group(1).strip()

    # Service installed (7045)
    elif event_id == 7045:
        event["service_name"] = extract_field(message, "Service Name:")
        event["process"]      = extract_field(message, "Image Path:")

    # Service state changed (7036)
    elif event_id == 7036:
        m = re.search(r"Service Name:\s+(.+?)\s+entered the\s+(.+?)\s+state", message)
        if m:
            event["service_name"] = m.group(1).strip()
            event["service_state"] = m.group(2).strip()

    # Scheduled task created (4698) - often appears in Security log too
    elif event_id == 4698:
        m = re.search(r"Task Name:\s+(.+?)(?:\||$)", message)
        if m:
            event["task_name"] = m.group(1).strip()
        event["user"] = extract_field(message, "Subject:")

    # PowerShell script
    elif event_id in (4103, 4104):
        event["user"] = extract_field(message, "User=") or extract_field(message, "Account Name:")
        # Extract the actual script block if present
        m = re.search(r"ScriptBlockText:\s+(.+?)(?:\|\s*ScriptBlockId|$)", message, re.DOTALL)
        if m:
            event["raw_command"] = m.group(1).strip()[:1000]
        m = re.search(r"Path:\s+(.+?)(?:\||$)", message)
        if m:
            event["process"] = m.group(1).strip()

    # Defender malware
    elif event_id in (1116, 1117, 1118):
        m = re.search(r"Threat Name:\s+(.+?)(?:\||$)", message)
        if m:
            event["threat_name"] = m.group(1).strip()
        m = re.search(r"Path:\s+(.+?)(?:\||$)", message)
        if m:
            event["process"] = m.group(1).strip()

    # Firewall
    elif event_id in (5152, 5157):
        event["source_ip"] = extract_field(message, "Source Address:")
        event["dest_ip"]   = extract_field(message, "Dest Address:")
        port_match = re.search(r"Dest Port:\s+(\d+)", message)
        if port_match:
            event["dest_port"] = int(port_match.group(1))

    return event


def check_suspicious_patterns(event):
    alerts = []
    eid = event.get("event_id")
    msg = (event.get("message") or "").lower()

    # Audit log cleared - critical, attacker covering tracks
    if eid in (104, 1102):
        alerts.append({
            "alert_type": "EVENT_LOG_CLEARED",
            "severity":   "CRITICAL",
            "log":        event.get("log"),
            "message":    f"Log {event.get('log')} was cleared"
        })

    # PowerShell encoded command
    if event.get("event_type") in ("POWERSHELL_SCRIPT", "POWERSHELL_SCRIPT_BLOCK"):
        if "-enc" in msg or "encodedcommand" in msg or "frombase64string" in msg:
            alerts.append({
                "alert_type": "ENCODED_POWERSHELL",
                "severity":   "HIGH",
                "user":       event.get("user"),
                "message":    "Encoded PowerShell command detected"
            })
        for keyword in ("mimikatz", "invoke-mimikatz", "sekurlsa", "lsadump"):
            if keyword in msg:
                alerts.append({
                    "alert_type": "MIMIKATZ_DETECTED",
                    "severity":   "CRITICAL",
                    "user":       event.get("user"),
                    "message":    f"Credential dumping tool reference: {keyword}"
                })
                break

    # Service installed from suspicious location
    if eid == 7045:
        svc_path = (event.get("process") or "").lower()
        svc_name = event.get("service_name", "")
        bad_paths = ("\\temp\\", "\\appdata\\", "\\downloads\\", "\\public\\",
                     "\\programdata\\", "%appdata%")
        if any(p in svc_path for p in bad_paths):
            alerts.append({
                "alert_type": "SUSPICIOUS_SERVICE",
                "severity":   "HIGH",
                "service":    svc_name,
                "path":       event.get("process"),
                "message":    "Service installed from suspicious location"
            })

    # Sysmon tampering
    if eid == 25:
        alerts.append({
            "alert_type": "SYSMON_TAMPERING",
            "severity":   "CRITICAL",
            "message":    "Sysmon service or configuration tampering detected"
        })

    # Defender detected malware
    if eid == 1116:
        alerts.append({
            "alert_type": "MALWARE_DETECTED",
            "severity":   "HIGH",
            "threat":     event.get("threat_name"),
            "path":       event.get("process"),
            "message":    "Windows Defender detected malware"
        })

    # Sysmon: Office spawning a child process (classic macro attack)
    if eid == 1:
        parent = (event.get("parent_process") or "").lower()
        child  = (event.get("process") or "").lower()
        office_parents = ("winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe")
        suspicious_children = ("cmd.exe", "powershell.exe", "wscript.exe",
                              "cscript.exe", "mshta.exe", "rundll32.exe")
        if any(p in parent for p in office_parents):
            if any(c in child for c in suspicious_children):
                alerts.append({
                    "alert_type": "OFFICE_SPAWN_SUSPICIOUS",
                    "severity":   "HIGH",
                    "parent":     event.get("parent_process"),
                    "child":      event.get("process"),
                    "message":    "Office application spawned suspicious child process"
                })

    return alerts


def detect_outbound_beacon(event):
    """Alert on repeated connections from same process to same dest."""
    if event.get("event_type") != "SYSMON_NETWORK":
        return None
    if not event.get("dest_ip") or not event.get("process"):
        return None

    key = (event["process"], event["dest_ip"], event.get("dest_port"))
    state = suspicious_ips[key]
    state["events"] += 1
    state["ts"].append(datetime.now())
    state["ts"] = [t for t in state["ts"] if (datetime.now() - t).total_seconds() < 60]

    if len(state["ts"]) >= 20:
        return {
            "alert_type":  "POSSIBLE_BEACON",
            "severity":    "HIGH",
            "process":     event["process"],
            "dest_ip":     event["dest_ip"],
            "dest_port":   event.get("dest_port"),
            "connections": len(state["ts"]),
            "message":     "Repeated outbound connections from same process - possible C2 beacon"
        }
    return None


def write_jsonl(filepath, payload):
    filepath.parent.mkdir(parents=True, exist_ok=True)
    with open(filepath, "a", encoding="utf-8") as f:
        f.write(json.dumps(payload) + "\n")


def poll_log(log_name, max_events=100):
    events = []
    try:
        hand = win32evtlog.OpenEventLog(None, log_name)
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        raw = win32evtlog.ReadEventLog(hand, flags, 0)
        for ev_obj in raw[:max_events]:
            try:
                events.append(parse_event(log_name, ev_obj))
            except Exception:
                pass
        win32evtlog.CloseEventLog(hand)
    except Exception as e:
        print(f"[SOC-WIN-SYS] Cannot read {log_name}: {e}")
    return events


def main():
    setup_logging()
    hostname = subprocess.check_output("hostname", shell=True, text=True).strip()
    print(f"[SOC-WIN-SYS] Host:   {hostname}")
    print(f"[SOC-WIN-SYS] Events: {EVENT_LOG}")
    print(f"[SOC-WIN-SYS] Alerts: {ALERT_LOG}")

    while True:
        try:
            for log_name in LOGS_TO_POLL:
                events = poll_log(log_name, max_events=50)

                for event in events:
                    if event["event_id"] not in SYSTEM_EVENTS:
                        continue

                    key = f"{event['log']}:{event['event_id']}:{event['time']}:{event['message'][:80]}"
                    if key in known_events:
                        continue
                    known_events.add(key)

                    if len(known_events) > 10000:
                        known_events.clear()

                    scored = score_event(event)
                    output = {
                        "timestamp": datetime.utcnow().isoformat(),
                        "event":     event,
                        "risk": {
                            "score":   scored["risk_score"],
                            "level":   scored["risk_level"],
                            "reasons": scored["reasons"]
                        }
                    }
                    write_jsonl(EVENT_LOG, output)
                    print(json.dumps(output))

                    if scored["risk_level"] in ("HIGH", "MEDIUM"):
                        write_jsonl(ALERT_LOG, {
                            "timestamp":   scored.get("scored_at", datetime.utcnow().isoformat()),
                            "alert_type":  "RISK_THRESHOLD",
                            "risk_level":  scored["risk_level"],
                            "risk_score":  scored["risk_score"],
                            "reasons":     scored["reasons"],
                            "event":       event
                        })

                    for sus in check_suspicious_patterns(event):
                        sus["timestamp"]     = datetime.utcnow().isoformat()
                        sus["trigger_event"] = event
                        write_jsonl(ALERT_LOG, sus)
                        print(json.dumps({"alert": sus}))

                    beacon = detect_outbound_beacon(event)
                    if beacon:
                        beacon["timestamp"]     = datetime.utcnow().isoformat()
                        beacon["trigger_event"] = event
                        write_jsonl(ALERT_LOG, beacon)
                        print(json.dumps({"alert": beacon}))

            time.sleep(2)

        except KeyboardInterrupt:
            print("\n[SOC-WIN-SYS] Stopped by user")
            break
        except Exception as e:
            print(f"[SOC-WIN-SYS] Error: {e}")
            time.sleep(5)


if __name__ == "__main__":
    main()
