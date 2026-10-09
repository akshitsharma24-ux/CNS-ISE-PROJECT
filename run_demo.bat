@echo off
echo ========================================================
echo  Starting QRshield Quishing ^& Tamper Detection System
echo ========================================================
echo.
where py >nul 2>nul
if %errorlevel% equ 0 (
    set PY_CMD=py -3.12
) else (
    set PY_CMD=python
)

set PORT=8000
netstat -ano | findstr LISTENING | findstr :8000 >nul 2>nul
if %errorlevel% equ 0 (
    echo Port 8000 is already in use, using fallback port 8080...
    set PORT=8080
)

echo Starting FastAPI / Uvicorn Server at http://127.0.0.1:%PORT% ...
echo Press Ctrl+C to stop the server.
echo.
start http://127.0.0.1:%PORT%
%PY_CMD% -m uvicorn qrshield.app.api:app --host 127.0.0.1 --port %PORT% --reload
pause
