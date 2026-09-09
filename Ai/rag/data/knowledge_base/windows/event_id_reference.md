# Windows Event Reference

## Useful Security Event IDs

- `4624` Successful logon
- `4625` Failed logon
- `4648` Logon attempted with explicit credentials
- `4672` Special privileges assigned to new logon
- `4688` New process created
- `4720` User account created
- `4728` User added to security-enabled global group
- `7045` Service installed
- `1102` Audit log cleared

## High-signal correlations

- Many `4625` failures followed by a `4624` success from the same host or IP
- `4688` showing `powershell.exe` with `-enc` or base64-like blobs
- `7045` immediately followed by network connections or child processes
- `4720` or `4728` outside approved change windows
- `1102` after process creation or suspicious admin activity

## Example triage path

1. Pull all events for the host and account around the suspicious timestamp
2. Check whether privileged tokens (`4672`) were granted
3. Review parent-child chains for the process in `4688`
4. Inspect service install path, signer, and start mode for `7045`
5. Confirm whether accounts created or modified were authorized
