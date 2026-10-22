@echo off
setlocal
cd /d "%~dp0"
where uv >nul 2>nul
if errorlevel 1 (
  echo Install uv and Node.js as described in README.md, then open this file again.
  pause
  exit /b 1
)
if not exist ".venv\Scripts\python.exe" goto setup
if not exist "frontend\dist\index.html" goto setup
goto launch
:setup
call scripts\setup.cmd
if errorlevel 1 (
  pause
  exit /b 1
)
:launch
uv run --locked python -m sentinel.launch
if errorlevel 1 pause
