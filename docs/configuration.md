# Configuration Reference

Copy `.env.example` to `.env`. Explicit process environment variables override
values loaded from the file.

## Gemini

| Variable | Default | Description |
|---|---|---|
| `GEMINI_API_KEY` | unset | Google Gemini API key; required for generated output |
| `GEMINI_MODEL` | `gemini-2.5-flash` | Model name supplied to the Gemini API |
| `HONEYPOT_USE_GEMINI` | `true` | Enable or disable Gemini deception |
| `HONEYPOT_AI_TIMEOUT` | `12` | Maximum seconds allowed for one model request |
| `HONEYPOT_MIN_RESPONSE_DELAY` | `1.25` | Minimum post-generation delay in seconds |
| `HONEYPOT_MAX_RESPONSE_DELAY` | `2.75` | Maximum post-generation delay in seconds |

The maximum delay is automatically raised to the minimum when misordered. Both
delay values are clamped to zero or greater.

## Listener settings

| Variable | Default |
|---|---:|
| `HONEYPOT_BIND_HOST` | `127.0.0.1` |
| `HONEYPOT_AUTOSTART` | `false` |
| `HONEYPOT_SSH_PORT` | `2222` |
| `HONEYPOT_TELNET_PORT` | `2323` |
| `HONEYPOT_HTTP_PORT` | `8088` |
| `HONEYPOT_HTTPS_PORT` | `8443` |
| `HONEYPOT_MYSQL_PORT` | `33060` |

Use `0.0.0.0` only inside an isolated lab or decoy environment. Keep the Uvicorn
dashboard bind separate; `--host 127.0.0.1` prevents publishing the operator UI.

## Storage

| Variable | Default | Description |
|---|---|---|
| `HONEYPOT_DB_PATH` | `logs/argus_honeypot.db` | SQLite telemetry database |
| `HONEYPOT_CERT_DIR` | `logs/certs` | Generated HTTPS key and certificate directory |

## Safety limits

| Variable | Default | Description |
|---|---:|---|
| `HONEYPOT_READ_TIMEOUT` | `90` | Seconds allowed for an individual read |
| `HONEYPOT_SESSION_TIMEOUT` | `1800` | Maximum session duration |
| `HONEYPOT_MAX_SESSIONS_PER_IP` | `8` | Concurrent sessions permitted per source |
| `HONEYPOT_MAX_INTERACTIONS` | `64` | Commands/queries permitted per session |
| `HONEYPOT_MAX_INPUT_BYTES` | `16384` | Maximum bounded input unit |
| `HONEYPOT_MAX_EVENT_PREVIEW` | `4096` | Maximum stored preview characters |
| `HONEYPOT_MAX_AI_OUTPUT` | `2000` | Maximum returned model-output characters |

## Existing SOC settings

`CLOUDAMQP_URL`, `REDIS_URL`, and the existing RAG settings continue to apply to
the original ARGUS pipeline. The honeypot and dashboard remain usable when those
optional services are unavailable.

