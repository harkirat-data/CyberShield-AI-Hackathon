# Troubleshooting and Operations

## No WSL sessions appear

Check runtime status:

```powershell
(Invoke-RestMethod http://127.0.0.1:8000/api/v1/honeypot/status) |
    ConvertTo-Json -Depth 6
```

For default WSL NAT testing, `bind_host` must be `0.0.0.0` or the Windows-side
WSL adapter address. Restart Uvicorn after changing `.env`. Confirm the target in
WSL with `ip route show | grep default`, then use `nc -vz TARGET PORT`.

If traffic is still filtered, review Windows Firewall. Any temporary rule should
be limited to the five decoy ports and the WSL source address, then removed after
the demonstration.

## Gemini says Ready but does not become Live

Send a dynamic request; `/` and `POST /login` are intentionally static:

```bash
curl "http://$TARGET:8088/api/diagnostic-$(date +%s)"
```

Inspect the `gemini` object from the status endpoint. `last_error` is redacted and
usually identifies invalid keys, unavailable models, quota, network errors, or
timeouts. Verify that the key is in `D:\CyberSheild\.env`, not `.env.example` or
only the Ubuntu environment.

## Gemini generates nested HTTP headers

The runtime normalizer strips accidental model-generated status lines and headers
before applying its own framing. Restart a non-reloading Uvicorn process after
updating. Dynamic API-like paths should normally return JSON.

## A listener shows failed

Another process or a Windows reserved-port rule may own the port. Override the
specific `HONEYPOT_*_PORT` value, restart, and confirm the configured port in the
dashboard. Avoid terminating unrelated services merely to claim a preferred port.

## Dashboard does not refresh

The browser polls every three seconds. Hard-refresh the page, confirm `/health`
and `/api/v1/honeypot/metrics`, and check the browser console for API errors. A
selected **Live only** filter hides already-completed sessions.

## Resetting demonstration data

Stop ARGUS before moving or removing `logs/argus_honeypot.db`. Treat collected
telemetry as evidence: export anything required before cleanup. Do not remove the
entire project or logs directory with a recursive wildcard.

