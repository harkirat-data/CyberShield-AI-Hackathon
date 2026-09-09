param(
    [string]$BaseUrl = "http://127.0.0.1:8000"
)

$ErrorActionPreference = "Stop"

Write-Host "ARGUS health" -ForegroundColor Cyan
Invoke-RestMethod -Uri "$BaseUrl/health" | ConvertTo-Json -Depth 6

Write-Host "`nDeception grid" -ForegroundColor Cyan
$status = Invoke-RestMethod -Uri "$BaseUrl/api/v1/honeypot/status"
$status | ConvertTo-Json -Depth 8

Write-Host "`nTelemetry metrics" -ForegroundColor Cyan
Invoke-RestMethod -Uri "$BaseUrl/api/v1/honeypot/metrics" |
    ConvertTo-Json -Depth 6

if (-not $status.running) {
    Write-Warning "The deception grid is stopped. Start it from the dashboard or control API."
}

if (-not $status.gemini.configured) {
    Write-Warning "Gemini is not configured in the server process."
} elseif ($status.gemini.healthy -eq $false) {
    Write-Warning "Gemini used fallback: $($status.gemini.last_error)"
}
