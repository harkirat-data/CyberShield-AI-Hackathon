"""
system_firewall_collector.py

Multi-source log collector for system and firewall events.
Tails (whichever exist):
  - /var/log/syslog     (Debian/Ubuntu)
  - /var/log/messages   (RHEL/CentOS)
  - /var/log/kern.log   (kernel + iptables)
  - /var/log/ufw.log    (Ubuntu Firewall)

Requires root/sudo to read /var/log/*

Run:
  sudo python3 system_firewall_collector.py
"""

import time
import re
import json
import os
import socket
import queue
import threading
import urllib.error
import urllib.request
from collections import defaultdict
from datetime import datetime
from pathlib import Path

# Reuse your existing risk scorer
try:
    from risk_scoring import score_event
except ImportError:
    print("[SOC] risk_scoring.py not found - using default scoring")
    def score_event(event):
        return {
            "risk_score": 10,
            "risk_level": "LOW",
            "reasons": ["default scoring (risk_scoring.py not loaded)"],
            "scored_at": datetime.utcnow().isoformat()
        }


# === Output paths (shared with auth collector) ===
ALERT_LOG = Path.home()/ "logs" / "alerts.jsonl"
EVENT_LOG = Path.home()/ "logs" / "events.jsonl"
API_URL = os.environ.get("ARGUS_API_URL", "http://127.0.0.1:8000/api/v1/logs")
HOSTNAME = socket.gethostname()


# === Patterns ===

# UFW / iptables kernel log:
#   ... kernel: [UFW BLOCK] IN=eth0 OUT= MAC=... SRC=1.2.3.4 DST=5.6.7.8
#         ... PROTO=TCP SPT=12345 DPT=22
# Plain iptables (no brackets):
#   ... kernel: IN=eth0 OUT= SRC=1.2.3.4 DST=5.6.7.8 ... PROTO=TCP SPT=1234 DPT=80
IPTABLES_PATTERN = re.compile(
    r"(?:\[(?P<action>[^\]]+)\]\s+)?"
    r"IN=(?P<in>\S+)\s+"
    r"(?:OUT=(?P<out>\S+)\s+)?"
    r"(?:MAC=[^\s]+\s+)?"
    r"SRC=(?P<src>[\d.]+)\s+"
    r"DST=(?P<dst>[\d.]+)\s+"
    r".*?PROTO=(?P<proto>\w+)"
    r"(?:\s+SPT=(?P<spt>\d+))?"
    r"(?:\s+DPT=(?P<dpt>\d+))?"
)

# systemd service event:
#   ... systemd[1]: sshd.service: Deactivated successfully.
SERVICE_PATTERN = re.compile(
    r"systemd\[\d+\]:\s+(?P<svc>[\w\-\.\@]+\.service):\s+(?P<msg>.+)"
)

# OOM killer:
#   ... Out of memory: Killed process 1234 (apache) total-vm:...
OOM_PATTERN = re.compile(
    r"Out of memory:\s+Killed process \d+ \((?P<proc>[\w\-]+)\)"
)

# Cron execution:
#   ... CRON[1234]: (root) CMD (/usr/bin/command args)
CRON_PATTERN = re.compile(
    r"CRON\[\d+\]:\s+\((?P<user>\w+)\)\s+CMD\s+\((?P<cmd>.+?)\)"
)


# === Ports often probed by scanners / attackers ===
SUSPICIOUS_PORTS = {
    21:    "FTP",
    23:    "Telnet",
    135:   "MS-RPC",
    139:   "NetBIOS",
    445:   "SMB",
    1433:  "MSSQL",
    3306:  "MySQL",
    3389:  "RDP",
    4444:  "Metasploit-default",
    5555:  "ADB",
    5900:  "VNC",
    6379:  "Redis",
    9200:  "Elasticsearch",
    27017: "MongoDB",
}


# === Parsers (return dict or None) ===

def parse_iptables(line):
    m = IPTABLES_PATTERN.search(line)
    if not m:
        return None
    g = m.groupdict()
    dpt = int(g["dpt"]) if g["dpt"] else None

    # Normalize action
    action_raw = (g["action"] or "").upper()
    if not action_raw:
        action = "LOG"
    elif "BLOCK" in action_raw or "DROP" in action_raw or "REJECT" in action_raw:
        action = "BLOCK"
    elif "ALLOW" in action_raw or "ACCEPT" in action_raw:
        action = "ALLOW"
    else:
        action = action_raw

    return {
        "event_type":     "FIREWALL_EVENT",
        "action":         action,
        "in_interface":   g["in"],
        "out_interface":  g["out"] or "",
        "source_ip":      g["src"],
        "dest_ip":        g["dst"],
        "protocol":       g["proto"],
        "source_port":    int(g["spt"]) if g["spt"] else None,
        "dest_port":      dpt,
        "suspicious_port": SUSPICIOUS_PORTS.get(dpt) if dpt else None,
        "raw":            line
    }


def parse_service_change(line):
    m = SERVICE_PATTERN.search(line)
    if not m:
        return None
    return {
        "event_type": "SERVICE_CHANGE",
        "service":    m.group("svc"),
        "message":    m.group("msg"),
        "raw":        line
    }


def parse_oom(line):
    m = OOM_PATTERN.search(line)
    if not m:
        return None
    return {
        "event_type": "OOM_KILL",
        "process":    m.group("proc"),
        "raw":        line
    }


def parse_cron(line):
    m = CRON_PATTERN.search(line)
    if not m:
        return None
    return {
        "event_type": "CRON_EXEC",
        "user":       m.group("user"),
        "command":    m.group("cmd"),
        "raw":        line
    }


# Map log file -> parsers to try (in order)
SOURCE_PARSERS = {
    "/var/log/syslog":   [parse_iptables, parse_service_change, parse_oom, parse_cron],
    "/var/log/messages": [parse_iptables, parse_service_change, parse_oom, parse_cron],
    "/var/log/kern.log": [parse_iptables],
    "/var/log/ufw.log":  [parse_iptables],
}


# === Detection state ===

port_scan_state = defaultdict(lambda: {"ports": set(), "ts": []})
known_events = set()


def detect_port_scan(event):
    """Alert on 10+ unique destination ports blocked from same IP in 60s."""
    if event.get("event_type") != "FIREWALL_EVENT":
        return None
    if event.get("action") != "BLOCK":
        return None

    ip = event.get("source_ip")
    dpt = event.get("dest_port")
    if not ip or not dpt:
        return None

    now = datetime.now()
    state = port_scan_state[ip]

    # Keep only last 60s
    fresh = [(t, p) for t, p in zip(state["ts"], state["ports"])
             if (now - t).total_seconds() < 60]
    state["ts"]    = [t for t, p in fresh]
    state["ports"] = {p for t, p in fresh}

    state["ts"].append(now)
    state["ports"].add(dpt)

    if len(state["ports"]) >= 10:
        alert = {
            "alert_type":       "PORT_SCAN",
            "source_ip":        ip,
            "unique_ports":     len(state["ports"]),
            "blocked_attempts": len(state["ts"]),
            "window_seconds":   60,
            "severity":         "HIGH"
        }
        state["ts"].clear()
        state["ports"].clear()
        return alert
    return None


def detect_suspicious_port(event):
    """Alert when firewall blocks traffic to a known risky port."""
    if event.get("event_type") != "FIREWALL_EVENT":
        return None
    if event.get("action") != "BLOCK":
        return None
    name = event.get("suspicious_port")
    if not name:
        return None
    return {
        "alert_type": "SUSPICIOUS_PORT_PROBE",
        "source_ip":  event.get("source_ip"),
        "dest_port":  event.get("dest_port"),
        "service":    name,
        "severity":   "MEDIUM"
    }


def detect_service_change(event):
    """Alert when a critical service is stopped/deactivated."""
    if event.get("event_type") != "SERVICE_CHANGE":
        return None
    critical = {"sshd.service", "sudo.service", "systemd-logind.service", "polkit.service"}
    svc = event.get("service", "")
    if svc not in critical:
        return None
    msg = event.get("message", "")
    if "Deactivated" not in msg and "Stopped" not in msg and "failed" not in msg.lower():
        return None
    return {
        "alert_type": "CRITICAL_SERVICE_STOPPED",
        "service":    svc,
        "message":    msg,
        "severity":   "HIGH"
    }


# === Output ===

def write_jsonl(filepath, payload):
    filepath.parent.mkdir(parents=True, exist_ok=True)
    with open(filepath, "a", encoding="utf-8") as f:
        f.write(json.dumps(payload) + "\n")


def _severity_from_risk(risk_level):
    return (risk_level or "low").lower()


def _normalize_event(event, risk_level):
    details = {
        "action": event.get("action", ""),
        "protocol": event.get("protocol", ""),
        "source_port": event.get("source_port"),
        "dest_port": event.get("dest_port"),
        "service": event.get("suspicious_port", ""),
        "service_name": event.get("service", ""),
        "message": event.get("message", ""),
        "command": event.get("command", ""),
        "process": event.get("process", ""),
    }
    details = {key: value for key, value in details.items() if value not in ("", None)}
    return {
        "event_id": f"{event['event_type']}:{event.get('source_ip', 'unknown')}:{int(time.time() * 1000)}",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "host": HOSTNAME,
        "source": "linux_system",
        "event_type": event.get("event_type", "UNKNOWN"),
        "severity": _severity_from_risk(risk_level),
        "actor": {
            "source_ip": event.get("source_ip", ""),
            "user": event.get("user", ""),
        },
        "target": {
            "host": HOSTNAME,
            "service": event.get("service", ""),
        },
        "details": details,
        "raw": event.get("raw", ""),
    }


def post_to_api(event, risk_level):
    payload = {
        "event": _normalize_event(event, risk_level),
        "brute_force_detected": False,
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


# === File tailer (runs in its own thread) ===

class FileTailer(threading.Thread):
    def __init__(self, path, parsers, out_queue):
        super().__init__(daemon=True)
        self.path     = path
        self.parsers  = parsers
        self.out_queue = out_queue
        self._stop    = threading.Event()

    def stop(self):
        self._stop.set()

    def run(self):
        try:
            f = open(self.path, "r")
            try:
                inode = Path(self.path).stat().st_ino
                f.seek(0, 2)  # only new lines
                print(f"[SOC] Tailing {self.path}")
                while not self._stop.is_set():
                    line = f.readline()
                    if not line:
                        time.sleep(0.2)
                        # Detect log rotation (inode change)
                        try:
                            if Path(self.path).stat().st_ino != inode:
                                print(f"[SOC] {self.path} rotated, reopening")
                                break
                        except FileNotFoundError:
                            break
                        continue
                    line = line.strip()
                    for parser in self.parsers:
                        event = parser(line)
                        if event:
                            event["_source"] = self.path
                            self.out_queue.put(event)
                            break
            finally:
                f.close()
        except PermissionError:
            print(f"[SOC] Permission denied on {self.path} (need sudo)")
        except FileNotFoundError:
            print(f"[SOC] File not found: {self.path}")
        except Exception as e:
            print(f"[SOC] Tailer error on {self.path}: {e}")


# === Main ===

def find_available_sources():
    found = []
    for path, parsers in SOURCE_PARSERS.items():
        p = Path(path)
        if p.exists() and p.is_file():
            try:
                with open(path, "r"):
                    pass
                found.append((path, parsers))
            except PermissionError:
                print(f"[SOC] {path} exists but not readable (need sudo)")
        else:
            print(f"[SOC] Skipping {path} (not present)")
    return found


def process_event(event):
    # Dedup
    key = (
        event.get("event_type"),
        event.get("source_ip"),
        event.get("dest_port"),
        event.get("user"),
        event.get("service"),
        event.get("raw", "")[:200]
    )
    if key in known_events:
        return
    known_events.add(key)
    if len(known_events) > 5000:
        known_events.clear()

    # Score
    try:
        scored = score_event(event)
    except Exception as e:
        scored = {
            "risk_score": 10,
            "risk_level": "LOW",
            "reasons":    [f"scoring_error: {e}"],
            "scored_at":  datetime.utcnow().isoformat()
        }

    source = event.pop("_source", "unknown")
    output = {
        "timestamp":   datetime.utcnow().isoformat(),
        "source_file": source,
        "event":       event,
        "risk": {
            "score":   scored["risk_score"],
            "level":   scored["risk_level"],
            "reasons": scored["reasons"]
        }
    }
    write_jsonl(EVENT_LOG, output)
    print(json.dumps(output))
    post_to_api(event, scored["risk_level"])

    # Risk-threshold alert
    if scored["risk_level"] in ("HIGH", "MEDIUM"):
        write_jsonl(ALERT_LOG, {
            "timestamp":   scored.get("scored_at", datetime.utcnow().isoformat()),
            "alert_type":  "RISK_THRESHOLD",
            "risk_level":  scored["risk_level"],
            "risk_score":  scored["risk_score"],
            "reasons":     scored["reasons"],
            "event":       event
        })

    # Specific detections
    for detector in (detect_port_scan, detect_suspicious_port, detect_service_change):
        a = detector(event)
        if a:
            a["timestamp"]     = datetime.utcnow().isoformat()
            a["trigger_event"] = event
            write_jsonl(ALERT_LOG, a)
            print(json.dumps({"alert": a}))


def main():
    print(f"[SOC] System & Firewall Collector starting...")
    print(f"[SOC] Alerts: {ALERT_LOG}")
    print(f"[SOC] Events: {EVENT_LOG}")

    sources = find_available_sources()
    if not sources:
        print("[SOC] No readable log sources found. Run with sudo.")
        return

    q = queue.Queue()
    tailers = []
    for path, parsers in sources:
        t = FileTailer(path, parsers, q)
        t.start()
        tailers.append(t)

    print(f"[SOC] Monitoring {len(sources)} source(s). Ctrl+C to stop.\n")

    try:
        while True:
            try:
                event = q.get(timeout=1)
            except queue.Empty:
                continue
            process_event(event)
    except KeyboardInterrupt:
        print("\n[SOC] Shutting down...")
        for t in tailers:
            t.stop()


if __name__ == "__main__":
    main()
