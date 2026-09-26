@echo off
title NEXUS - Capture Home Network Baseline
cd /d %~dp0
call venv\Scripts\activate.bat
echo ================================================================
echo        NEXUS 60-SECOND HOME NETWORK BASELINE RECORDER
echo ================================================================
echo Sniffing live ambient network traffic to calibrate neural baseline...
python scripts\capture_baseline.py --duration 60
echo.
pause
