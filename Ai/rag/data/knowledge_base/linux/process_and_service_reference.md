# Linux Process and Service Investigation Reference

## Suspicious process indicators

- Unexpected shells spawned by web services such as `www-data`, `nginx`, or `apache`
- Encoded or heavily obfuscated bash, python, curl, or wget commands
- Processes launching from `/tmp`, `/dev/shm`, or a user home directory with execute permissions
- Network utilities running immediately after authentication success

## Suspicious service indicators

- New `systemd` service unit files written under `/etc/systemd/system`
- Services that execute scripts from temporary or user-writable paths
- Services created shortly after privilege escalation events

## Useful commands

```bash
systemctl list-unit-files --type=service
systemctl status <service-name>
ps auxf
ss -plant
find /etc/systemd/system -type f -mtime -7
```

## MITRE alignment

- `T1059` Command and Scripting Interpreter
- `T1543.002` Systemd Service
- `T1055` Process Injection when unusual parent-child process trees appear
