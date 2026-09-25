@echo off
title VALENS - Security Operations. Deception. Intelligence
cd /d "%~dp0"
echo ========================================================
echo   VALENS - Security Operations. Deception. Intelligence
echo ========================================================
echo.
echo [*] Launching Honeypot Decoy Grid and SOC Command Center...
echo [*] Dashboard will open at: http://127.0.0.1:8050/dashboard
echo.
python main.py
pause
