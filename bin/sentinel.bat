@echo off
REM ------------------------------------------------------------------------------
REM Run Sentinel CLI
REM ------------------------------------------------------------------------------

REM --- Check parameter ---
IF "%~1"=="" (
    echo Usage: %~nx0 ^<scan-directory^>
    echo.
    echo Example:
    echo   %~nx0 C:\path\to\project
    exit /b 1
)

SET "SCAN_DIR=%~1"

REM --- Check if directory exists ---
IF NOT EXIST "%SCAN_DIR%" (
    echo Error: Scan directory does not exist: %SCAN_DIR%
    exit /b 1
)

REM --- Change working directory to project root ---
cd /d "%~dp0..\"

REM --- Run Sentinel CLI ---
python app\sentinel.py "%SCAN_DIR%" ^
    -l ^
    -g ^
    -k ^
    --heuristics-level low
    REM --forensic
    REM --no-bail-out
    REM --all-matches
    REM --exclude-dirs node_modules

pause
