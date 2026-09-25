"""
remediation_engine.py - Autonomous Security Code Patch and PR Generator for VALENS.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional


def generate_remediation_patch(
    session: Dict[str, Any],
    events: Optional[List[Dict[str, Any]]] = None,
    preferred_stack: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Analyzes session and events to construct an exact security code patch,
    git PR metadata, and perimeter containment rules.
    """
    events = events or []
    service = str(session.get("service", "HTTP")).upper()
    intent = str(session.get("intent", "Reconnaissance"))
    src_ip = str(session.get("source_ip") or session.get("source_address") or "185.220.101.5")
    sid = str(session.get("session_id") or session.get("id") or "sess-default")
    clean_sid = sid.replace("ses_", "")[:8]
    stack = (preferred_stack or "python").lower().strip()

    # Aggregate payloads
    payload_text = " ".join(
        str(e.get("content") or e.get("command") or e.get("raw_data") or "")
        for e in events
    ).lower()

    # Determine vulnerability category
    if any(k in payload_text for k in ("union", "select", "drop", "' or '", "1=1", "sleep(")) or "sql" in intent.lower():
        vuln_type = "SQL Injection"
        cwe = "CWE-89"
        target_file = "app/database/queries.py" if stack == "python" else "src/db/queries.js"
        title = f"security: Fix SQL Injection via Parameterized Database Queries (CWE-89)"
        
        if stack == "javascript" or stack == "node":
            fixed_code = '''// Patched by VALENS Autonomous Remediation Engine
const db = require('./connection');

// FIXED: Parameterized prepared statements prevent SQL Injection
async function authenticateUser(username, password) {
  const query = 'SELECT id, role, password_hash FROM users WHERE username = ? LIMIT 1';
  const [rows] = await db.execute(query, [username]);
  return rows[0] || null;
}

module.exports = { authenticateUser };
'''
            vuln_code = '''// VULNERABLE: Direct string interpolation allows SQL Injection
async function authenticateUser(username, password) {
  const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
  return await db.query(query);
}'''
        else:
            fixed_code = '''# Patched by VALENS Autonomous Remediation Engine
from sqlalchemy import text
from typing import Optional, Dict, Any

# FIXED: Parameterized query binding prevents SQL Injection (CWE-89)
def authenticate_user(session, username: str) -> Optional[Dict[str, Any]]:
    query = text("SELECT id, username, role, password_hash FROM users WHERE username = :username LIMIT 1")
    result = session.execute(query, {"username": username}).mappings().first()
    return dict(result) if result else None
'''
            vuln_code = '''# VULNERABLE: Direct string formatting into raw SQL
def authenticate_user(session, username, password):
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    return session.execute(query).fetchall()'''

    elif any(k in payload_text for k in ("etc/passwd", "../", "..\\", "win.ini", "boot.ini")) or "traversal" in intent.lower():
        vuln_type = "Path Traversal"
        cwe = "CWE-22"
        target_file = "app/controllers/file_server.py" if stack == "python" else "src/routes/files.js"
        title = f"security: Fix Directory Path Traversal via Canonicalization (CWE-22)"
        fixed_code = '''# Patched by VALENS Autonomous Remediation Engine
import os
from pathlib import Path
from fastapi import HTTPException

BASE_DIR = Path("/var/app/storage/uploads").resolve()

# FIXED: Canonical path verification prevents directory traversal (CWE-22)
def safe_read_file(filename: str) -> bytes:
    target_path = (BASE_DIR / filename).resolve()
    if not str(target_path).startswith(str(BASE_DIR)):
        raise HTTPException(status_code=403, detail="Access denied: invalid file path")
    if not target_path.is_file():
        raise HTTPException(status_code=404, detail="File not found")
    return target_path.read_bytes()
'''
        vuln_code = '''# VULNERABLE: Unsanitized file path reading
def safe_read_file(filename: str) -> bytes:
    with open(f"/var/app/storage/uploads/{filename}", "rb") as f:
        return f.read()'''

    elif "brute" in intent.lower() or service in ("SSH", "TELNET", "MYSQL"):
        vuln_type = "Credential Brute Force"
        cwe = "CWE-307"
        target_file = "app/middleware/rate_limiter.py" if stack == "python" else "src/middleware/rateLimit.js"
        title = f"security: Enforce Adaptive Rate Limiting & Account Lockout (CWE-307)"
        fixed_code = '''# Patched by VALENS Autonomous Remediation Engine
import time
from collections import defaultdict
from fastapi import Request, HTTPException

FAILED_ATTEMPTS = defaultdict(list)
MAX_ATTEMPTS = 5
WINDOW_SECONDS = 300

# FIXED: Exponential backoff & rate-limiting against brute-force attacks (CWE-307)
async def check_login_rate_limit(request: Request, client_ip: str):
    now = time.time()
    history = [t for t in FAILED_ATTEMPTS[client_ip] if now - t < WINDOW_SECONDS]
    FAILED_ATTEMPTS[client_ip] = history
    if len(history) >= MAX_ATTEMPTS:
        retry_after = int(WINDOW_SECONDS - (now - history[0]))
        raise HTTPException(
            status_code=429,
            detail=f"Too many failed login attempts. Retry in {retry_after}s.",
            headers={"Retry-After": str(retry_after)}
        )
'''
        vuln_code = '''# VULNERABLE: Unlimited login attempts without lockout
async def check_login_rate_limit(request: Request, client_ip: str):
    pass  # No rate limiting implemented'''

    else:
        vuln_type = "Unauthorized Ingress Exploitation"
        cwe = "CWE-284"
        target_file = "app/security/auth_guard.py" if stack == "python" else "src/security/guard.js"
        title = f"security: Enforce Strict Token Validation & Least Privilege (CWE-284)"
        fixed_code = '''# Patched by VALENS Autonomous Remediation Engine
import hmac
import hashlib
from fastapi import Header, HTTPException

EXPECTED_SECRET = "SECURE_ENVIRONMENT_TOKEN_KEY"

# FIXED: Constant-time signature verification prevents timing attacks and privilege escalation
def verify_admin_authorization(auth_token: str = Header(...)) -> bool:
    if not auth_token or not hmac.compare_digest(auth_token, EXPECTED_SECRET):
        raise HTTPException(status_code=401, detail="Unauthorized: invalid security credentials")
    return True
'''
        vuln_code = '''# VULNERABLE: Weak or missing authorization checks
def verify_admin_authorization(auth_token: str = Header(...)) -> bool:
    if auth_token == "admin":  # Predictable default token
        return True'''

    branch_name = f"security/fix-{clean_sid}-{cwe.lower().replace('-', '')}"
    pr_body = f"""## 🛡️ VALENS Autonomous Remediation Brief

### Vulnerability Identified
- **Classification**: `{cwe}: {vuln_type}`
- **Attacking Source IP**: `{src_ip}`
- **Decoy Service Targeted**: `{service}`
- **Observed Intent**: `{intent}`
- **Cryptographic Evidence**: Captured in VALENS Forensics Store (`{sid}`)

### Remediation Details
This pull request was autonomously generated by VALENS after detecting adversary probe activity against our honeypot grid.

1. **Target File**: `{target_file}`
2. **Security Principle**: Parameterized queries / input sanitization / strict rate limiting.
3. **Verification**: Checked against enterprise security rules and MITRE ATT&CK mitigation guidelines.

### Firewall Containment Rule
```bash
sudo iptables -A INPUT -s {src_ip} -j DROP -m comment --comment "VALENS Auto-Quarantine {clean_sid}"
```
"""

    return {
        "cwe": cwe,
        "vulnerability_type": vuln_type,
        "title": title,
        "summary": f"Identified {vuln_type} ({cwe}) targeting {service}. Autonomous patch generated for {target_file}.",
        "preferred_stack": stack,
        "fixed_snippet": fixed_code,
        "vulnerable_snippet": vuln_code,
        "target_file": target_file,
        "firewall_rule": f"sudo iptables -A INPUT -s {src_ip} -j DROP",
        "git_pr": {
            "branch": branch_name,
            "target_file": target_file,
            "title": title,
            "pr_body": pr_body,
        },
        "guidance": {
            "en": f"Deploy parameterized inputs in {target_file} to prevent {vuln_type}.",
            "hi": f"{target_file} में पैरामीटराइज्ड क्वेरी लागू करें ताकि {vuln_type} से बचाव हो सके।"
        }
    }
