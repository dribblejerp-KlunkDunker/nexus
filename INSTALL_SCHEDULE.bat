@echo off
title NEXUS - Install Scheduled Tasks
cd /d "%~dp0"

REM Registers the two cadences with Windows Task Scheduler so neither depends on
REM being remembered. Run this once, as administrator.
REM
REM The audit is scheduled, not the retrain: retraining daily on an unchanged
REM corpus is churn, and repeatedly selecting against the same holdout eventually
REM promotes a champion that looks good on it by luck. The audit is what needs to
REM run often, because it catches regression you would otherwise find by having a
REM real host firewalled.

net session >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Run this as administrator.
    pause
    exit /b 1
)

echo Registering NEXUS_Audit  - daily 20:00
schtasks /Create /TN "NEXUS_Audit" /TR "\"%~dp0NEXUS_AUDIT.bat\" scheduled" /SC DAILY /ST 20:00 /RL HIGHEST /F

echo Registering NEXUS_Weekly - Sundays 21:00
schtasks /Create /TN "NEXUS_Weekly" /TR "\"%~dp0NEXUS_WEEKLY.bat\" scheduled" /SC WEEKLY /D SUN /ST 21:00 /RL HIGHEST /F

echo.
echo Installed. Verify with:  schtasks /Query /TN NEXUS_Audit
echo Remove with:             schtasks /Delete /TN NEXUS_Audit /F
echo.
echo NOT scheduled on purpose: rolling capture and the sensor. Those run in
echo visible windows via START_NEXUS.bat, because anything touching your NIC
echo should be something you can see and close.
echo.
pause
