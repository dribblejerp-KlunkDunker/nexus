@echo off
title NEXUS - First Run Setup
cd /d "%~dp0"
setlocal

REM Run this once. It creates the virtual environment and installs dependencies.
REM Safe to re-run: it reuses an existing venv and just reinstalls packages.

echo =========================================================
echo   NEXUS SETUP
echo =========================================================
echo.

where python >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python is not on PATH.
    echo         Install Python 3.10 or newer from python.org and tick
    echo         "Add python.exe to PATH" during installation.
    pause
    exit /b 1
)

for /f "tokens=2" %%v in ('python --version 2^>^&1') do set PYVER=%%v
echo Using Python %PYVER%
echo.

if not exist "venv\Scripts\python.exe" (
    echo [1/3] Creating virtual environment in venv\ ...
    python -m venv venv
    if errorlevel 1 (
        echo [ERROR] Could not create the virtual environment.
        pause
        exit /b 1
    )
) else (
    echo [1/3] Virtual environment already present, reusing it.
)

echo [2/3] Upgrading pip ...
.\venv\Scripts\python.exe -m pip install --upgrade pip --quiet

echo [3/3] Installing dependencies (torch is large, this can take a few minutes) ...
.\venv\Scripts\python.exe -m pip install -r requirements.txt
if errorlevel 1 (
    echo.
    echo [ERROR] Dependency installation failed. Read the error above.
    pause
    exit /b 1
)

echo.
echo Running diagnostics to confirm the install ...
echo.
.\venv\Scripts\python.exe scripts\verify_system.py

echo.
echo =========================================================
echo   SETUP COMPLETE
echo.
echo   If the diagnostics above mention Npcap or live capture,
echo   install Npcap from https://npcap.com  - it is what lets
echo   scapy read packets off your adapter. Everything except
echo   packet capture works without it.
echo.
echo   Next:
echo     1. CREATE_DESKTOP_SHORTCUT.bat   (makes the desktop icon)
echo     2. Launch NEXUS from that icon   (it runs as administrator)
echo     3. Deck 4 -^> INSTALL SCHEDULED TASKS
echo     4. Deck 4 -^> START CAPTURE
echo =========================================================
echo.
pause
