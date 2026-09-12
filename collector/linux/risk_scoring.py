from datetime import datetime


SCORE_AUTH_FAILURE = 30
SCORE_AUTH_SUCCESS = 15
SCORE_INVALID_USER = 25
SCORE_SUDO_FAILURE = 40
SCORE_PRIV_ESCALATION = 50
SCORE_USER_CREATED = 50
SCORE_USER_DELETED = 30
SCORE_PASSWORD_CHANGE = 20

SCORE_USER_ROOT = 50
SCORE_USER_ADMIN = 35
SCORE_USER_SERVICE = 15

SCORE_PRIVATE_IP = 5
SCORE_LOCALHOST_IP = 0
SCORE_PUBLIC_IP = 20
SCORE_KNOWN_BAD_IP = 50

THRESHOLD_HIGH = 70
THRESHOLD_MEDIUM = 40

HIGH_RISK_USERS = ["root", "admin", "administrator", "sysadmin", "sa"]
SERVICE_USERS = ["www-data", "nginx", "apache", "mysql", "postgres", "redis",
                 "nobody", "daemon", "ftp", "mail"]

KNOWN_BAD_IP_PREFIXES = ["185.", "45.", "91.", "194."]

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

    if event_type == "FIREWALL_EVENT":
        if event.get("suspicious_port"):
            return {
                "risk_score": 60,
                "risk_level": "MEDIUM",
                "reasons": [f"probe of {event['suspicious_port']}"] ,
                "scored_at": datetime.utcnow().isoformat(),
                "event": event,
            }
        if event.get("action") == "BLOCK":
            return {
                "risk_score": 20,
                "risk_level": "LOW",
                "reasons": ["firewall block"],
                "scored_at": datetime.utcnow().isoformat(),
                "event": event,
            }

    if event_type == "OOM_KILL":
        return {
            "risk_score": 70,
            "risk_level": "HIGH",
            "reasons": ["OOM kill"],
            "scored_at": datetime.utcnow().isoformat(),
            "event": event,
        }

    if event_type == "CRON_EXEC" and user == "root":
        return {
            "risk_score": 30,
            "risk_level": "LOW",
            "reasons": ["root cron"],
            "scored_at": datetime.utcnow().isoformat(),
            "event": event,
        }

    if event_type == "AUTH_FAILURE":
        base_score += SCORE_AUTH_FAILURE
        reasons.append("Authentication failure")
    elif event_type == "AUTH_SUCCESS":
        base_score += SCORE_AUTH_SUCCESS
        reasons.append("Successful authentication")
    elif event_type == "INVALID_USER":
        base_score += SCORE_INVALID_USER
        reasons.append("Login with non-existent user")
    elif event_type == "SUDO_FAILURE":
        base_score += SCORE_SUDO_FAILURE
        reasons.append("Sudo authentication failure")
    elif event_type == "PRIV_ESCALATION":
        base_score += SCORE_PRIV_ESCALATION
        reasons.append("Privilege escalation attempt")
    elif event_type == "USER_CREATED":
        base_score += SCORE_USER_CREATED
        reasons.append("New user account created")
    elif event_type == "USER_DELETED":
        base_score += SCORE_USER_DELETED
        reasons.append("User account deleted")
    elif event_type == "PASSWORD_CHANGE":
        base_score += SCORE_PASSWORD_CHANGE
        reasons.append("Password change attempt")

    if user.lower() == "root":
        base_score += SCORE_USER_ROOT
        reasons.append("Targeting root user")
    elif is_high_risk_user(user):
        base_score += SCORE_USER_ADMIN
        reasons.append(f"Targeting admin user ({user})")
    elif is_service_user(user):
        base_score += SCORE_USER_SERVICE
        reasons.append(f"Service account ({user})")

    if source_ip:
        if source_ip.startswith("127."):
            base_score += SCORE_LOCALHOST_IP
        elif is_private_ip(source_ip):
            base_score += SCORE_PRIVATE_IP
            reasons.append(f"Internal IP ({source_ip})")
        else:
            base_score += SCORE_PUBLIC_IP
            reasons.append(f"Public IP ({source_ip})")

        for bad_prefix in KNOWN_BAD_IP_PREFIXES:
            if source_ip.startswith(bad_prefix):
                base_score += SCORE_KNOWN_BAD_IP
                reasons.append("Known malicious IP range")
                break

    if is_off_hours() and event_type in [
        "AUTH_SUCCESS", "USER_CREATED", "PRIV_ESCALATION",
        "SUDO_FAILURE", "PASSWORD_CHANGE"
    ]:
        base_score += 10
        reasons.append(f"Off-hours activity ({datetime.now().hour}:00)")

    if is_weekend() and event_type in ["AUTH_SUCCESS", "USER_CREATED"]:
        base_score += 5
        reasons.append("Weekend activity")

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
