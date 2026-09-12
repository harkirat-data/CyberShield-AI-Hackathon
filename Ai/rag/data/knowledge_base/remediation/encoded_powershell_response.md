# Playbook: Encoded PowerShell Response

## Scope

Use this playbook when PowerShell is launched with encoded commands or obfuscated content.

## Immediate actions

1. Capture the full command line and parent process
2. Isolate the host if the script appears malicious or has network/download behavior
3. Decode the payload in a safe analysis environment
4. Collect PowerShell operational logs, script block logs, and process creation events
5. Search for the same command or hash across other endpoints

## Short-term containment

- Block known malicious domains or IPs contacted by the script
- Disable or restrict the affected account if misuse is confirmed
- Review scheduled tasks, startup folders, services, and WMI persistence

## Long-term hardening

- Enable PowerShell script block logging and transcription where feasible
- Enforce constrained language mode or application control for admin tooling
- Tune detections for `-enc`, `DownloadString`, and AMSI bypass patterns

## Evidence checklist

- Full encoded command
- Decoded script content
- Parent process lineage
- User context and privilege level
- Network destinations and downloaded artifacts
