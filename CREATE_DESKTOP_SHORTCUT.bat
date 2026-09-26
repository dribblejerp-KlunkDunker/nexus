@echo off
title NEXUS - Create Desktop Shortcut
cd /d "%~dp0"
setlocal

REM Creates "NEXUS.lnk" on your Desktop pointing at START_NEXUS.bat, with the
REM NEXUS icon, the correct working directory, and the "Run as administrator"
REM flag set so live packet capture works without you remembering to right-click.
REM
REM The elevation flag is not exposed by WScript.Shell, so the script sets it the
REM only way available: byte 0x15 of the .lnk header carries the link flags, and
REM bit 0x20 is "run as administrator". The shortcut is created normally first,
REM then that one byte is patched.

echo =========================================================
echo   NEXUS DESKTOP SHORTCUT
echo =========================================================
echo.

if not exist "START_NEXUS.bat" (
    echo [ERROR] START_NEXUS.bat not found next to this file.
    echo         Run this from inside the NEXUS folder.
    pause
    exit /b 1
)

set "PS1=%TEMP%\nexus_shortcut_%RANDOM%.ps1"

> "%PS1%" echo param([Parameter(Mandatory=$true)][string]$Root)
>> "%PS1%" echo $ErrorActionPreference = 'Stop'
>> "%PS1%" echo try {
>> "%PS1%" echo   # The caller passes the folder with a trailing dot, because a path ending
>> "%PS1%" echo   # in a backslash would escape the closing quote of the argument.
>> "%PS1%" echo   $root    = (Resolve-Path -LiteralPath $Root).Path.TrimEnd('\')
>> "%PS1%" echo   $target  = Join-Path $root 'START_NEXUS.bat'
>> "%PS1%" echo   $icon    = Join-Path $root 'NEXUS.ico'
>> "%PS1%" echo   $desktop = [Environment]::GetFolderPath('Desktop')
>> "%PS1%" echo   $link    = Join-Path $desktop 'NEXUS.lnk'
>> "%PS1%" echo.
>> "%PS1%" echo   $ws = New-Object -ComObject WScript.Shell
>> "%PS1%" echo   $sc = $ws.CreateShortcut($link)
>> "%PS1%" echo   $sc.TargetPath       = $target
>> "%PS1%" echo   $sc.WorkingDirectory = $root
>> "%PS1%" echo   $sc.Description      = 'NEXUS network sensor - shadow mode, opens the command center on localhost:8000'
>> "%PS1%" echo   $sc.WindowStyle      = 1
>> "%PS1%" echo   if (Test-Path $icon) { $sc.IconLocation = "$icon,0" }
>> "%PS1%" echo   $sc.Save()
>> "%PS1%" echo.
>> "%PS1%" echo   # Patch the run-as-administrator bit.
>> "%PS1%" echo   $bytes = [System.IO.File]::ReadAllBytes($link)
>> "%PS1%" echo   $bytes[0x15] = $bytes[0x15] -bor 0x20
>> "%PS1%" echo   [System.IO.File]::WriteAllBytes($link, $bytes)
>> "%PS1%" echo.
>> "%PS1%" echo   Write-Host ''
>> "%PS1%" echo   Write-Host '  Created:  ' -NoNewline; Write-Host $link -ForegroundColor Cyan
>> "%PS1%" echo   Write-Host '  Target:   ' -NoNewline; Write-Host $target
>> "%PS1%" echo   Write-Host '  Start in: ' -NoNewline; Write-Host $root
>> "%PS1%" echo   if ((([System.IO.File]::ReadAllBytes($link))[0x15] -band 0x20) -eq 0x20) {
>> "%PS1%" echo     Write-Host '  Elevation: run as administrator IS set' -ForegroundColor Green
>> "%PS1%" echo   } else {
>> "%PS1%" echo     Write-Host '  Elevation: could NOT be set - right-click the icon,' -ForegroundColor Yellow
>> "%PS1%" echo     Write-Host '             Properties, Advanced, tick Run as administrator' -ForegroundColor Yellow
>> "%PS1%" echo   }
>> "%PS1%" echo   exit 0
>> "%PS1%" echo } catch {
>> "%PS1%" echo   Write-Host ''
>> "%PS1%" echo   Write-Host ('  FAILED: ' + $_.Exception.Message) -ForegroundColor Red
>> "%PS1%" echo   exit 1
>> "%PS1%" echo }

powershell -NoProfile -ExecutionPolicy Bypass -File "%PS1%" -Root "%~dp0."
set "RC=%ERRORLEVEL%"
del "%PS1%" >nul 2>&1

echo.
if "%RC%"=="0" (
    echo   Double-click the NEXUS icon on your Desktop to start.
    echo   Windows will ask for permission - that is the elevation
    echo   prompt, and it is needed for packet capture.
) else (
    echo   Shortcut creation failed. You can still start NEXUS by
    echo   right-clicking START_NEXUS.bat and choosing
    echo   "Run as administrator".
)
echo.
pause
exit /b %RC%
