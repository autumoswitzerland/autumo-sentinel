@echo off
REM ------------------------------------------------------------------------------
REM Run sentinel CLI
REM ------------------------------------------------------------------------------

REM --- 0. Set working directory to project root ---
cd /d "%~dp0..\"

REM --- 1. Define scan directory ---
SET "SCAN_DIR=C:\Users\Mike\Development\git\repository\autumo-toolbox"

REM --- 2. Run sentinel CLI with options ---
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
