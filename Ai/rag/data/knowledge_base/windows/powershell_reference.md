# PowerShell Investigation Reference

## Suspicious PowerShell behaviors

- Use of `-enc`, `-encodedcommand`, or compressed base64 blobs
- Download cradles using `IEX`, `Invoke-WebRequest`, `Net.WebClient`, or `DownloadString`
- Disabling logging, AMSI bypass logic, or hidden window execution
- Spawning from Office processes, scripting hosts, or web-facing applications

## Data to collect

- Full command line
- Parent process and parent command line
- User context and integrity level
- Script block logging if available
- Network destinations contacted immediately after launch

## Common MITRE mappings

- `T1059.001` PowerShell
- `T1027` Obfuscated Files or Information
- `T1105` Ingress Tool Transfer
- `T1562.001` Impair Defenses
