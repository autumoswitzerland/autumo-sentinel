@echo off
REM ------------------------------------------------------------------------------
REM Run Sentinel CLI
REM ------------------------------------------------------------------------------

REM --- Check parameters ---
IF "%~1"=="" (
    echo Usage: %~nx0 ^<severity^> ^<scan-directory^>
    echo.
    echo Severity levels: low, medium, high
    echo Example:
    echo   %~nx0 medium C:\path\to\project
    exit /b 1
)

IF "%~2"=="" (
    echo Usage: %~nx0 ^<severity^> ^<scan-directory^>
    exit /b 1
)

SET "SEVERITY=%~1"
SET "SCAN_DIR=%~2"

REM --- Validate severity ---
IF /I NOT "%SEVERITY%"=="low" IF /I NOT "%SEVERITY%"=="medium" IF /I NOT "%SEVERITY%"=="high" (
    echo Error: Invalid severity level: %SEVERITY%
    exit /b 1
)

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
    --heuristics-level %SEVERITY%
    REM --forensic
    REM --no-bail-out
    REM --all-matches
    REM --exclude-dirs node_modules

pause
