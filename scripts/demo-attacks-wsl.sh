#!/usr/bin/env bash
set -euo pipefail

target="${1:-}"
if [[ -z "$target" ]]; then
  echo "Usage: $0 <private Windows host IP>" >&2
  exit 2
fi

if [[ ! "$target" =~ ^127\. ]] &&
   [[ ! "$target" =~ ^10\. ]] &&
   [[ ! "$target" =~ ^192\.168\. ]] &&
   [[ ! "$target" =~ ^172\.(1[6-9]|2[0-9]|3[01])\. ]]; then
  echo "Refusing non-private target: $target" >&2
  exit 3
fi

for tool in curl nc; do
  command -v "$tool" >/dev/null || {
    echo "Missing required tool: $tool" >&2
    exit 4
  }
done

echo "[1/6] Connecting to all five decoy ports"
for port in 2222 2323 8088 8443 33060; do
  nc -zvw2 "$target" "$port" || true
done

echo "[2/6] Enumerating fictional HTTP resources"
for path in admin backup .env api/config private/ledger; do
  curl -sS --max-time 15 -o /dev/null -w "%{http_code} $path\n" \
    "http://$target:8088/$path" || true
done

echo "[3/6] Sending a credential attempt"
curl -sS --max-time 15 -X POST "http://$target:8088/login" \
  --data 'username=admin&password=demonstration-only' || true
echo

echo "[4/6] Sending database-discovery-shaped input"
curl -sS --max-time 20 -X POST "http://$target:8088/api/search" \
  --data "q=' UNION SELECT username,password FROM users--" || true
echo

echo "[5/6] Running a bounded fake shell sequence"
printf '%s\n' root demonstration-only whoami hostname 'uname -a' 'ls -la' \
  'find / -name "*.pem"' 'sudo -l' 'crontab -l' exit |
  nc -w 35 "$target" 2323 || true

echo "[6/6] Requesting a dynamic HTTPS resource"
curl -ksS --max-time 20 "https://$target:8443/api/internal/accounts" || true
echo
echo "Demo complete. Review http://127.0.0.1:8000/dashboard on Windows."

