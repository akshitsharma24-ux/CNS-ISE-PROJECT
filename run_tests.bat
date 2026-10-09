@echo off
echo ========================================================
echo  Running QRshield 49-Test Unit ^& Red-Team Test Suite
echo ========================================================
echo.
where py >nul 2>nul
if %errorlevel% equ 0 (
    set PY_CMD=py -3.12
) else (
    set PY_CMD=python
)

%PY_CMD% -m pytest tests/ -v
pause
