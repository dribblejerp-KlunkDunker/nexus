@echo off
REM ===========================================================================
REM NEXUS web asset build (offline-first command deck)
REM
REM Compiles Tailwind (once, at build time) into web/static/css/app.css.
REM After this, the dashboard loads ZERO third-party resources: fonts, CSS,
REM and JS are all served from web/static/ by dashboard.py itself.
REM
REM One-time setup:  npm install   (from the project root; dev-only)
REM Re-run whenever you change Tailwind classes or the custom HUD styles in
REM web/static/css/input.css.
REM ===========================================================================
setlocal
cd /d "%~dp0"

if not exist node_modules\tailwindcss (
  echo [NEXUS] Installing build tooling once (dev-only)...
  call npm install --no-audit --no-fund || goto :fail
)

echo [NEXUS] Compiling Tailwind -^> web/static/css/app.css ...
REM Build from web/ so the config's content globs (./index.html, ./js/app.js)
REM resolve correctly; running from the root yields an empty-utilities CSS.
pushd web
node ..\node_modules\tailwindcss\lib\cli.js -c tailwind.config.js -i static\css\input.css -o static\css\app.css --minify || (popd & goto :fail)
popd

echo [NEXUS] Done. app.css is up to date. Restart the dashboard to serve it.
exit /b 0

:fail
echo [NEXUS] Web asset build FAILED. The previously committed app.css is still in place.
exit /b 1
