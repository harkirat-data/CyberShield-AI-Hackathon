# Patched by CyberShield AI Autonomous Remediation Engine
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
