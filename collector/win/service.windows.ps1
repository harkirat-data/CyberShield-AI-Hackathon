# install_service_windows.ps1
# Installs CyberShield AI Windows collectors as services.
# Run as Administrator: .\install_service_windows.ps1

#Requires -RunAsAdministrator

$ErrorActionPreference = "Stop"

$InstallDir = "C:\soc\collectors"
$LogDir     = "C:\soc\logs"
$PythonExe  = (Get-Command python.exe).Source

Write-Host "[CyberShield AI] Installing Windows collectors..." -ForegroundColor Cyan

# 1. Create directories
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
New-Item -ItemType Directory -Force -Path $LogDir     | Out-Null

# 2. Copy collector files
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

$files = @("auth_collector.py", "system_collector_windows.py", "risk_scoring.py")
foreach ($file in $files) {
    $source = Join-Path $ScriptDir $file
    if (Test-Path $source) {
        Copy-Item $source $InstallDir -Force
        Write-Host "[CyberShield AI] Copied $file" -ForegroundColor Green
    } else {
        Write-Host "[CyberShield AI] WARNING: $file not found in $ScriptDir" -ForegroundColor Yellow
    }
}

# 3. Install Python dependencies
Write-Host "[CyberShield AI] Installing Python dependencies..." -ForegroundColor Cyan
& $PythonExe -m pip install --quiet pywin32 watchdog

# 4. Download NSSM (service manager) if not present
$NssmPath = "$env:SystemRoot\System32\nssm.exe"
if (-not (Test-Path $NssmPath)) {
    Write-Host "[CyberShield AI] Downloading NSSM..." -ForegroundColor Cyan
    $NssmUrl = "https://nssm.cc/release/nssm-2.24.zip"
    $NssmZip = "$env:TEMP\nssm.zip"
    $NssmExtractDir = "$env:TEMP\nssm"

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $NssmUrl -OutFile $NssmZip -UseBasicParsing

    Expand-Archive -Path $NssmZip -DestinationPath $NssmExtractDir -Force
    $NssmExe = Get-ChildItem -Path $NssmExtractDir -Recurse -Filter "nssm.exe" |
               Where-Object { $_.DirectoryName -match "win64" } | Select-Object -First 1
    Copy-Item $NssmExe.FullName $NssmPath -Force
    Write-Host "[CyberShield AI] NSSM installed" -ForegroundColor Green
}

# 5. Install auth collector service
Write-Host "[CyberShield AI] Installing cybershield-auth service..." -ForegroundColor Cyan

& $NssmPath install cybershield-auth $PythonExe "$InstallDir\auth_collector.py" | Out-Null
& $NssmPath set cybershield-auth AppDirectory $InstallDir           | Out-Null
& $NssmPath set cybershield-auth AppStdoutOutput "$LogDir\auth.out.log"   | Out-Null
& $NssmPath set cybershield-auth AppStderrOutput "$LogDir\auth.err.log"   | Out-Null
& $NssmPath set cybershield-auth AppRotateFiles 1                  | Out-Null
& $NssmPath set cybershield-auth AppRotateBytes 10485760           | Out-Null  # 10MB
& $NssmPath set cybershield-auth DisplayName "CyberShield AI Auth Collector"     | Out-Null
& $NssmPath set cybershield-auth Description "Collects Windows Security/Auth events" | Out-Null
& $NssmPath set cybershield-auth Start SERVICE_AUTO_START           | Out-Null

# 6. Install system collector service
Write-Host "[CyberShield AI] Installing cybershield-system service..." -ForegroundColor Cyan

& $NssmPath install cybershield-system $PythonExe "$InstallDir\system_collector_windows.py" | Out-Null
& $NssmPath set cybershield-system AppDirectory $InstallDir        | Out-Null
& $NssmPath set cybershield-system AppStdoutOutput "$LogDir\system.out.log" | Out-Null
& $NssmPath set cybershield-system AppStderrOutput "$LogDir\system.err.log" | Out-Null
& $NssmPath set cybershield-system AppRotateFiles 1                | Out-Null
& $NssmPath set cybershield-system AppRotateBytes 10485760         | Out-Null
& $NssmPath set cybershield-system DisplayName "CyberShield AI System Collector"  | Out-Null
& $NssmPath set cybershield-system Description "Collects Windows System/Sysmon events" | Out-Null
& $NssmPath set cybershield-system Start SERVICE_AUTO_START        | Out-Null

# 7. Configure recovery: restart on failure
& $NssmPath set cybershield-auth   AppExit Default Restart          | Out-Null
& $NssmPath set cybershield-auth   AppRestartDelay 5000             | Out-Null
& $NssmPath set cybershield-system AppExit Default Restart          | Out-Null
& $NssmPath set cybershield-system AppRestartDelay 5000             | Out-Null

# 8. Start services
Start-Service cybershield-auth
Start-Service cybershield-system

Start-Sleep -Seconds 2

Write-Host ""
Write-Host "[CyberShield AI] ========================================" -ForegroundColor Green
Write-Host "[CyberShield AI] Installation complete!" -ForegroundColor Green
Write-Host "[CyberShield AI] ========================================" -ForegroundColor Green
Write-Host ""
Write-Host "Service status:"
Get-Service cybershield-auth   | Format-Table -AutoSize
Get-Service cybershield-system | Format-Table -AutoSize
Write-Host ""
Write-Host "Useful commands:" -ForegroundColor Cyan
Write-Host "  Get-Service cybershield-auth"
Write-Host "  Get-Service cybershield-system"
Write-Host "  Restart-Service cybershield-auth"
Write-Host "  Get-Content '$LogDir\auth.out.log' -Wait"
Write-Host "  Get-Content '$LogDir\system.out.log' -Wait"
Write-Host ""
Write-Host "Uninstall:" -ForegroundColor Yellow
Write-Host "  & nssm.exe remove cybershield-auth confirm"
Write-Host "  & nssm.exe remove cybershield-system confirm"
