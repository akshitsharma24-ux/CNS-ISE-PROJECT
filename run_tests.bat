@echo off
rem Run the QRshield test-suite with the project's virtual environment.
setlocal
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
    echo Run run_demo.bat once first to create the virtual environment.
    pause
    exit /b 1
)
".venv\Scripts\python.exe" -m pip install -q -r requirements-dev.txt
".venv\Scripts\python.exe" -m pytest %*
pause
