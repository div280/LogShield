@echo off
title LogShield SIEM Forensic Dashboard

:: Auto-elevate to Administrator for live Windows Event Log access
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [LogShield] Requesting Administrator privileges for live Windows Event Log access...
    powershell -NoProfile -Command "Start-Process cmd.exe -ArgumentList '/c \"\"%~f0\"\"' -Verb RunAs"
    exit /b
)

cd /d "%~dp0"
echo ======================================================================
echo   LogShield Real-Time Forensic Integrity SIEM Dashboard
echo   Mode: Administrator (Live Windows Security Event Stream Enabled)
echo ======================================================================
echo.
"D:\Yashu_lp\Software\Softwares_d\Anaconda\envs\logshield\python.exe" -m streamlit run dashboard/app.py
pause
