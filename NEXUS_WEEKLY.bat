@echo off
title NEXUS - Weekly Retrain Cycle
cd /d "%~dp0"
if not exist "venv\Scripts\python.exe" exit /b 1
.\venv\Scripts\python.exe scripts\ops.py weekly --generations 150
if "%1"=="" pause
