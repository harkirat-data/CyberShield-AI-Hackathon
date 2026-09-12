from datetime import datetime


SCORE_LOGON_SUCCESS = 10
SCORE_LOGON_FAILURE = 25
SCORE_ACCOUNT_LOCKOUT = 60
SCORE_PRIV_ESCALATION = 70
SCORE_USER_CREATED = 50
SCORE_USER_DELETED = 30
SCORE_USER_ADDED_TO_GROUP = 45
SCORE_SERVICE_INSTALLED = 55
SCORE_SCHEDULED_TASK = 35
SCORE_PROCESS_SUSPICIOUS = 50
SCORE_FIREWALL_CHANGE = 40
SCORE_AUDIT_POLICY_CHANGE = 60
SCORE_AUDIT_LOG_CLEARED = 100
SCORE_SYSMON_PROCESS = 20
SCORE_SYSMON_NETWORK = 25
SCORE_SYSMON_DNS = 30
SCORE_SYSMON_FILE = 25
SCORE_SYSMON_REGISTRY = 35
SCORE_SYSMON_TAMPERING = 60
SCORE_POWERSHELL_SCRIPT = 35

SCORE_USER_ADMIN = 40
SCORE_USER_SYSTEM = 30
SCORE_USER_SERVICE = 15

SCORE_PRIVATE_IP = 5
SCORE_PUBLIC_IP = 25
SCORE_PUBLIC_IP_SENSITIVE = 40

THRESHOLD_HIGH = 70
THRESHOLD_MEDIUM = 40

HIGH_RISK_USERS = ["administrator", "admin", "root", "sa", "sysadmin", "default", "guest"]
SERVICE_USERS = ["system", "local service", "network service", "iusr", "iis_user"]

SENSITIVE_EVENT_TYPES = ["USER_CREATED", "USER_ADDED_TO_GROUP", "SERVICE_INSTALLED",
                         "SCHEDULED_TASK", "POWERSHELL_SCRIPT", "PRIV_ESCALATION"]


def is_private_ip(ip):
    if not ip:
        return False
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        first = int(parts[0])
        second = int(parts[1])
    except ValueError:
        return False
    if first == 127:
        return True
    if first == 10:
        return True
    if first == 172 and 16 <= second <= 31:
        return True
    if first == 192 and second == 168:
        return True
    return False


def is_high_risk_user(user):
    if not user:
        return False
    return user.lower() in [u.lower() for u in HIGH_RISK_USERS]


def is_service_user(user):
    if not user:
        return False
    return user.lower() in [u.lower() for u in SERVICE_USERS]


def is_off_hours():
    hour = datetime.now().hour
    return hour < 6 or hour > 22


def is_weekend():
    return datetime.now().weekday() >= 5


def score_event(event):
    base_score = 0
    reasons = []

    event_type = event.get("event_type", "UNKNOWN")
    user = event.get("user", "")
    source_ip = event.get("source_ip", "")
    event_id = event.get("event_id", 0)

    type_scores = {
        "LOGON_SUCCESS": SCORE_LOGON_SUCCESS,
        "LOGON_FAILURE": SCORE_LOGON_FAILURE,
        "ACCOUNT_LOCKOUT": SCORE_ACCOUNT_LOCKOUT,
        "PRIV_ESCALATION": SCORE_PRIV_ESCALATION,
        "USER_CREATED": SCORE_USER_CREATED,
        "USER_DELETED": SCORE_USER_DELETED,
        "USER_ADDED_TO_GROUP": SCORE_USER_ADDED_TO_GROUP,
        "SERVICE_INSTALLED": SCORE_SERVICE_INSTALLED,
        "SCHEDULED_TASK": SCORE_SCHEDULED_TASK,
        "PROCESS_SUSPICIOUS": SCORE_PROCESS_SUSPICIOUS,
        "FIREWALL_CHANGE": SCORE_FIREWALL_CHANGE,
        "AUDIT_POLICY_CHANGE": SCORE_AUDIT_POLICY_CHANGE,
        "AUDIT_LOG_CLEARED": SCORE_AUDIT_LOG_CLEARED,
        "SYSMON_PROCESS": SCORE_SYSMON_PROCESS,
        "SYSMON_NETWORK": SCORE_SYSMON_NETWORK,
        "SYSMON_DNS": SCORE_SYSMON_DNS,
        "SYSMON_FILE": SCORE_SYSMON_FILE,
        "SYSMON_REGISTRY": SCORE_SYSMON_REGISTRY,
        "SYSMON_TAMPERING": SCORE_SYSMON_TAMPERING,
        "POWERSHELL_SCRIPT": SCORE_POWERSHELL_SCRIPT,
    }
    
    

    if event_type in type_scores:
        base_score += type_scores[event_type]
        reasons.append(f"{event_type} (Event ID {event_id})")

    if is_high_risk_user(user):
        base_score += SCORE_USER_ADMIN
        reasons.append(f"Privileged user: {user}")
    elif is_service_user(user):
        base_score += SCORE_USER_SERVICE
        reasons.append(f"Service account: {user}")

    if source_ip:
        if is_private_ip(source_ip):
            base_score += SCORE_PRIVATE_IP
            if event_type in ["LOGON_FAILURE", "PRIV_ESCALATION", "USER_ADDED_TO_GROUP"]:
                reasons.append(f"Internal IP: {source_ip}")
        else:
            base_score += SCORE_PUBLIC_IP
            reasons.append(f"Public IP: {source_ip}")
            if event_type in SENSITIVE_EVENT_TYPES:
                base_score += 15
                reasons.append("Public IP + sensitive event")

    if is_off_hours() and event_type in [
        "LOGON_SUCCESS", "PRIV_ESCALATION", "USER_CREATED",
        "SCHEDULED_TASK", "POWERSHELL_SCRIPT", "SERVICE_INSTALLED"
    ]:
        base_score += 10
        reasons.append(f"Off-hours activity ({datetime.now().hour}:00)")

    if is_weekend() and event_type in ["LOGON_SUCCESS", "USER_CREATED", "SERVICE_INSTALLED"]:
        base_score += 5
        reasons.append("Weekend activity")

    if event_id == 1102:
        base_score += 50
        reasons.append("Security log cleared")

    if event.get("command"):
        cmd = event["command"].lower()
        if "-enc" in cmd or "encodedcommand" in cmd or "frombase64string" in cmd:
            base_score += 30
            reasons.append("Encoded PowerShell command")
        if "mimikatz" in cmd or "invoke-mimikatz" in cmd:
            base_score += 80
            reasons.append("Mimikatz reference")

    if event.get("process"):
        proc = event["process"].lower()
        if any(p in proc for p in ["\\temp\\", "\\appdata\\", "\\downloads\\", "\\public\\"]):
            base_score += 25
            reasons.append("Suspicious process location")

    if event.get("dest_port"):
        port = event["dest_port"]
        if port in [4444, 5555, 6666, 31337, 1337]:
            base_score += 50
            reasons.append(f"Known backdoor port: {port}")

    if len(reasons) >= 3:
        base_score += 5
        reasons.append("Multiple suspicious indicators")

    base_score = min(base_score, 100)

    if base_score >= THRESHOLD_HIGH:
        level = "HIGH"
    elif base_score >= THRESHOLD_MEDIUM:
        level = "MEDIUM"
    else:
        level = "LOW"

    return {
        "risk_score": base_score,
        "risk_level": level,
        "reasons": reasons,
        "scored_at": datetime.utcnow().isoformat(),
        "event": event
    }
