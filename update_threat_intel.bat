@echo off
title NEXUS - Update Threat Intelligence (Abuse.ch ThreatFox / MITRE)
cd /d %~dp0
call venv\Scripts\activate.bat
echo ================================================================
echo    NEXUS THREAT INTELLIGENCE SYNCHRONIZER (ABUSE.CH / MITRE)
echo ================================================================
echo Pulling latest active C2 botnet and malware IOC feeds...
python scripts\update_threat_intel.py
echo.
pause
