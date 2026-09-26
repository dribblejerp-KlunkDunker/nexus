@echo off
title NEXUS - Regression Audit
cd /d "%~dp0"
if not exist "venv\Scripts\python.exe" exit /b 1

.\venv\Scripts\python.exe scripts\ops.py audit
set CODE=%ERRORLEVEL%

if %CODE%==0 echo AUDIT PASS
if %CODE%==1 echo AUDIT WARN - review logs\audit_report.json
if %CODE%==2 echo AUDIT FAIL - review logs\audit_report.json before leaving blocking armed

REM Scheduled runs should not block on a prompt; only pause when run by hand.
if "%1"=="" pause
exit /b %CODE%
