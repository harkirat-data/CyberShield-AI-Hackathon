# Linux SSH Authentication Reference

## Common files

- `/var/log/auth.log` on Debian and Ubuntu systems
- `/var/log/secure` on RHEL, CentOS, Rocky, and AlmaLinux systems
- `journalctl -u ssh` or `journalctl -u sshd` for systemd-based hosts

## High-signal brute force indicators

- Many `Failed password` events from a single source IP in a short period
- Attempts against common usernames such as `root`, `admin`, `oracle`, or `ubuntu`
- A later `Accepted password` from the same IP after many failures
- Authentication attempts from geographies or networks not associated with the user

## Example suspicious log lines

```text
Failed password for invalid user admin from 203.0.113.50 port 53422 ssh2
Failed password for root from 203.0.113.50 port 53438 ssh2
Accepted password for root from 203.0.113.50 port 53455 ssh2
```

## Suggested triage

1. Count failures by source IP and username over the last 15 minutes
2. Check whether the same source later authenticated successfully
3. Review `sudo` activity and new session creation after any success
4. Block or rate-limit the source if the host is internet exposed
5. Confirm MFA, password rotation, and account lockout settings

## Useful commands

```bash
grep "Failed password" /var/log/auth.log | tail -n 50
grep "Accepted password" /var/log/auth.log | tail -n 20
journalctl -u sshd --since "15 minutes ago"
```
