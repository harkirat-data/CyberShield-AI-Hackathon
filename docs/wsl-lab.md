# Ubuntu WSL Lab Guide

This guide keeps the operator dashboard on Windows and uses Ubuntu WSL as the
authorized traffic source.

## Windows side

Configure `.env`:

```dotenv
HONEYPOT_BIND_HOST=0.0.0.0
HONEYPOT_AUTOSTART=true
HONEYPOT_USE_GEMINI=true
```

Start the API with its dashboard restricted to Windows loopback:

```powershell
cd D:\CyberSheild
uv run uvicorn Ai.backend.api_server:app --host 127.0.0.1 --port 8000 --reload
```

## Ubuntu side

```bash
sudo apt update
sudo apt install -y nmap netcat-openbsd curl openssh-client default-mysql-client
TARGET=$(ip route show | awk '/default/ {print $3; exit}')
```

Confirm reachability:

```bash
for port in 2222 2323 8088 8443 33060; do
  nc -zvw2 "$TARGET" "$port"
done
```

Run `scripts/demo-attacks-wsl.sh "$TARGET"` or follow `docs/demo-attacks.md`.

## Mirrored networking

When WSL mirrored networking is enabled, `127.0.0.1` may work bidirectionally.
The default-route address remains the most explicit target for NAT mode.

## Cleanup

Stop the API with `Ctrl+C`. Remove any temporary firewall rule created for the
lab. Restore `HONEYPOT_BIND_HOST=127.0.0.1` before the next local-only run.

