#!/bin/bash
# Simulate suspicious activity for testing

echo "[*] Generating test events in /var/log/auth.log..."

# Try 6 failed logins (triggers brute force)
for i in {1..6}; do
    logger -p auth.warning "Failed password for root from 203.0.113.42 port 1234 ssh2"
    sleep 0.5
done

# Successful login from public IP
logger -p auth.info "Accepted password for admin from 203.0.113.99 port 5678 ssh2"

# Invalid user
logger -p auth.warning "Invalid user oracle from 198.51.100.7 port 9999 ssh2"

# Sudo failure
logger -p auth.err "sudo: pam_unix(sudo:auth): authentication failure; logname=analyst uid=1000 tty=/dev/pts/0 user=analyst"

# User creation
logger -p auth.info "useradd[1234]: new user: name=hacker, UID=0, GID=0, home=/home/hacker, shell=/bin/bash"

echo "[*] Done. Check your collector output."
