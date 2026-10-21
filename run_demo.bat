@echo off
rem QRshield - one-click demo for Windows. Creates .venv on first run, installs dependencies, starts the server.
setlocal
cd /d "%~dp0"

if exist ".venv\Scripts\python.exe" goto have_venv
echo [setup] Creating virtual environment ...
where py >nul 2>nul
if errorlevel 1 goto try_python
py -3.12 -m venv .venv 2>nul
if exist ".venv\Scripts\python.exe" goto have_venv
py -3.11 -m venv .venv 2>nul
if exist ".venv\Scripts\python.exe" goto have_venv
py -3 -m venv .venv 2>nul
if exist ".venv\Scripts\python.exe" goto have_venv
:try_python
python -m venv .venv
if not exist ".venv\Scripts\python.exe" (
    echo [error] Could not create a virtual environment. Install Python 3.11 or 3.12 from python.org and re-run.
    pause
    exit /b 1
)

:have_venv
if exist ".venv\.deps_installed" goto run
echo [setup] Installing dependencies (first run only, a few minutes) ...
".venv\Scripts\python.exe" -m pip install --upgrade pip >nul
".venv\Scripts\python.exe" -m pip install -r requirements.txt
if errorlevel 1 (
    echo [error] Dependency installation failed. See the messages above.
    pause
    exit /b 1
)
echo ok> ".venv\.deps_installed"

:run
".venv\Scripts\python.exe" -m qrshield setup
set PORT=8000
netstat -ano | findstr LISTENING | findstr ":8000 " >nul 2>nul
if not errorlevel 1 set PORT=8080
echo.
echo Starting QRshield at http://127.0.0.1:%PORT%   (Ctrl+C to stop)
start "" "http://127.0.0.1:%PORT%"
".venv\Scripts\python.exe" -m qrshield serve --port %PORT%
pause
