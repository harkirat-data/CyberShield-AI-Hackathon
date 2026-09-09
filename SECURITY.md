# Security Policy

ARGUS is defensive lab software and should be treated as an exposed security
sensor, not as a hardened production service.

## Reporting

Report vulnerabilities privately to the repository owner. Include affected
version, reproducible steps, impact, and a minimal proof of concept. Do not include
real API keys, passwords, personal information, or third-party attack traffic.

## Deployment expectations

- Use only on systems and networks you are authorized to monitor.
- Isolate the runtime from production workloads and credentials.
- Block outbound traffic except explicitly required provider access.
- Keep the dashboard on a management-only interface.
- Review all firewall and port-forwarding rules before applying them.
- Rotate a Gemini key immediately if it is exposed in logs or commits.

## Out of scope

Reports caused solely by intentionally exposed fictional services, self-signed
lab certificates, or the absence of real authentication on decoy ports are not
security defects. Escapes from the no-execution boundary, secret leakage, unsafe
dashboard access, and telemetry corruption are in scope.

