# Architecture

ARGUS separates untrusted network traffic from analysis and operator control.
The network runtime accepts bytes, converts them into bounded telemetry, and
returns only simulated data. No received command or query is executed.

## Components

### Deception runtime

`honeypot/runtime.py` owns five asynchronous TCP listeners. Each connection gets
a session ID and protocol-specific handler. The handlers implement only enough
protocol behavior to support scanner identification and controlled interaction.

### Gemini deception engine

`honeypot/deception.py` builds a constrained service-persona prompt, preserves a
small session history, requests text from Gemini, normalizes the response, and
adds configurable timing jitter. The engine has no tool access.

### Telemetry store

`honeypot/store.py` persists sessions, events, and SOC investigations in SQLite.
WAL mode permits the dashboard to read while listeners continue writing.

### SOC bridge

`honeypot/soc_bridge.py` sends important events through the existing correlation,
threat-intelligence, risk, and MITRE mapping agents. The resulting investigation
is linked back to the originating session.

### API and dashboard

`Ai/backend/api_server.py` exposes lifecycle, query, containment, and export
endpoints. Static assets in `dashboard/` render the operational console and poll
for updates every three seconds.

## Event flow

```text
TCP accept
  → create session
  → record connection event
  → detect multi-port scan
  → parse bounded protocol input
  → redact secrets and hash payload
  → classify intent
  → run deterministic SOC analysis
  → ask Gemini for fictional output
  → normalize protocol response
  → apply response jitter
  → send bytes and record outbound evidence
```

## Failure behavior

- Listener failure degrades one service without stopping the remaining services.
- Gemini failure records a redacted reason and uses the deterministic persona.
- Malformed protocol input is bounded, recorded when useful, and disconnected.
- Dashboard/API failure does not authorize execution or broaden network access.

## Trust boundaries

Untrusted attacker bytes end at protocol parsing and prompt construction. The
Gemini response is untrusted as well, so HTTP output is normalized before it is
framed. Operator-only actions are exposed through the dashboard API, which should
remain bound to a trusted interface.

