# Contributing

Changes should preserve ARGUS's primary invariant: attacker-controlled input is
observed and simulated, never executed.

## Development

```powershell
uv sync
uv run pytest tests -q
python -m compileall -q Ai honeypot tests
```

Keep protocol parsers bounded, redact sensitive fields before persistence, and
include regression tests for changes to parsing, telemetry, response framing, or
containment. Model prompts must maintain the fictional-data and no-tool boundary.

## Commit guidance

Use focused conventional-style messages such as `feat:`, `fix:`, `docs:`,
`test:`, `refactor:`, and `chore:`. Never commit `.env`, runtime databases,
generated certificates, API keys, or captured third-party traffic.

## Pull requests

Describe the behavior change, threat model impact, verification performed, and
any configuration or deployment migration. UI changes should include a screenshot
and protocol changes should include a sample sanitized transcript.

