@echo off
title NEXUS - Command Center
cd /d "%~dp0"

REM Single launcher. Everything else is a button on DECK 4: OPS & AUTOMATION.
REM
REM   rolling capture      DECK 4 -> START CAPTURE (pick the context tag there)
REM   sensor              header -> NETWORK NIC CAPTURE toggle
REM   audit / weekly      DECK 4 -> RUN AUDIT / WEEKLY CYCLE
REM   scheduled tasks     DECK 4 -> INSTALL SCHEDULED TASKS
REM
REM Administrator is required for live packet capture (Npcap raw sockets) and for
REM registering scheduled tasks from the UI. Without it the dashboard still runs
REM and every read-only panel works; the capture and schedule buttons will report
REM that they need elevation rather than failing silently.
REM
REM --active-defense is deliberately NOT passed. Nothing reachable from the UI can
REM write a Windows Firewall rule. Arming that stays a command-line decision after
REM a week of clean audits.

if not exist "venv\Scripts\python.exe" (
    echo [ERROR] venv\Scripts\python.exe not found. Create the virtual environment first.
    pause
    exit /b 1
)

net session >nul 2>&1
if errorlevel 1 (
    echo [WARNING] Not running as Administrator.
    echo           Live capture and scheduled-task registration will be unavailable.
    echo           Right-click this file and choose "Run as administrator".
    echo.
)

echo =======================================================
echo   NEXUS COMMAND CENTER
echo   http://localhost:8000    -  DECK 4 has the controls
echo   Shadow mode: the firewall is never touched from here
echo =======================================================
echo.

start http://localhost:8000
.\venv\Scripts\python.exe scripts\dashboard.py --port 8000

pause
