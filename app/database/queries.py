# Patched by CyberShield AI Autonomous Remediation Engine
from sqlalchemy import text
from typing import Optional, Dict, Any

# FIXED: Parameterized query binding prevents SQL Injection (CWE-89)
def authenticate_user(session, username: str) -> Optional[Dict[str, Any]]:
    query = text("SELECT id, username, role, password_hash FROM users WHERE username = :username LIMIT 1")
    result = session.execute(query, {"username": username}).mappings().first()
    return dict(result) if result else None
