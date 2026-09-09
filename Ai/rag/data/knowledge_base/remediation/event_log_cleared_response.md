# Playbook: Event Log Cleared

## Scope

Use this playbook when Windows audit or event logs are cleared unexpectedly.

## Immediate actions

1. Treat the activity as potential defense evasion
2. Identify the account and process responsible for clearing the log
3. Retrieve forwarded logs from SIEM, collectors, or backup channels
4. Review nearby events for suspicious logons, process launches, or service installs
5. Isolate the host if additional attacker behavior is present

## Short-term containment

- Restrict permissions for log management utilities
- Hunt for `wevtutil cl`, PowerShell log clearing, or alternate admin tooling
- Review whether the same user or host cleared logs elsewhere

## Long-term hardening

- Forward logs to centralized immutable storage
- Alert on event IDs `1102` and related log tampering signals
- Limit local admin usage and protect audit policy changes

## Evidence checklist

- User and logon session
- Command line or utility used
- Time log clearing occurred
- Preceding suspicious events
- Availability of remote or forwarded copies
