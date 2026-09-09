# Security Model

ARGUS assumes every network byte and every model response is untrusted.

## Enforced application controls

- No `subprocess`, shell execution, `eval`, or `exec` path exists for attacker input.
- Input sizes, event previews, interaction counts, sessions, and timeouts are bounded.
- Passwords are represented by length and SHA-256; raw passwords are not retained.
- Authorization, cookie, proxy authorization, and API-key headers are redacted.
- HTTP bodies receive field-level secret redaction plus size and SHA-256 metadata.
- Gemini has no tools and receives a fictional system context.
- Model output is length-limited and protocol-normalized before transmission.
- Runtime source blocking changes only ARGUS process state.

## Controls required from the operator

Application safeguards do not replace infrastructure isolation. A real deployment
must provide:

- A disposable host, VM, container, or isolated VLAN
- Default-deny egress filtering
- No mounted production secrets or host-control sockets
- A management-only dashboard interface
- Firewall/NAT rules scoped to intended decoy traffic
- Log retention, access control, monitoring, and incident handling

## Known limitations

- SSH is a banner/client-fingerprint sensor, not a full SSH cryptographic server.
- Gemini output is probabilistic and can be inconsistent despite prompt controls.
- Runtime blocking is not durable and does not update the operating-system firewall.
- SQLite is suitable for a lab or single node, not a high-volume distributed sensor grid.
- The self-signed HTTPS certificate is for deception testing, not trusted production TLS.

## Data handling

Honeypot telemetry can contain personal data, network identifiers, or attacker
content. Apply local law, authorization, retention, and disclosure requirements.
Never publish raw captured data or API keys in an issue or commit.

