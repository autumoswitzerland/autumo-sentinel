@echo off
REM ------------------------------------------------------------------------------
REM make.bat - Build sentinel CLI using PyInstaller (no venv, no PowerShell)
REM ------------------------------------------------------------------------------

REM --- 0. Variables and Options
SETLOCAL ENABLEEXTENSIONS
SET "VERSION=3.0.0"
SET "BIN_NAME=sentinel"
SET "DIST_DIR=dist"
SET "PACK_DIR=pack"
SET "DIST_ZIP=autumo-Sentinel-v%VERSION%"
SET "CLEAN_ONLY=false"

SET "COMMERCIAL_BUILD=false"

REM --- 1. Parse optional flags ---
:parse_args
if "%~1"=="" goto args_done
if "%~1"=="--commercial" (
    SET "COMMERCIAL_BUILD=True"
    SET "VERSION=%VERSION%c"
) else if "%~1"=="--clean" (
    SET "CLEAN_ONLY=True"
)
SHIFT
goto parse_args
:args_done

REM --- 2. Determine project root ---
SET "SCRIPT_DIR=%~dp0"
SET "PROJECT_ROOT=%SCRIPT_DIR%..\"
cd /d "%PROJECT_ROOT%"
echo Project root: %PROJECT_ROOT%

REM --- 3. Clean only mode ---
if "%CLEAN_ONLY%"=="True" (
    echo Cleaning build artifacts only...
    if exist "%DIST_DIR%" rmdir /s /q "%DIST_DIR%"
    if exist "build" rmdir /s /q "build"
    if exist "%BIN_NAME%.spec" del /q "%BIN_NAME%.spec"
    echo Clean finished.
    exit /b 0
)

REM --- 4. Detect architecture ---
for /f "tokens=2 delims==" %%a in ('wmic os get osarchitecture /value') do set ARCH=%%a
echo Detected Windows, architecture: %ARCH%

REM --- 5. Clean old builds ---
echo Cleaning old builds...
if exist "%DIST_DIR%" rmdir /s /q "%DIST_DIR%"
if exist "build" rmdir /s /q "build"
if exist "%BIN_NAME%.spec" del /q "%BIN_NAME%.spec"

REM --- 8. Generate build_info.py ---
echo Generating build_info.py...
(
    echo COMMERCIAL_BUILD=%COMMERCIAL_BUILD%
    echo VERSION="%VERSION%"
) > app\build_info.py

REM --- 7. PyInstaller build ---
echo Building sentinel CLI with PyInstaller...
where pyinstaller >nul 2>&1
if errorlevel 1 (
    echo ERROR: PyInstaller not found. Please install it first.
    exit /b 1
)

pyinstaller --name "%BIN_NAME%" --onefile app\sentinel.py
if errorlevel 1 (
    echo ERROR: PyInstaller build failed.
    exit /b 1
)

echo Build finished. Check %DIST_DIR%\%BIN_NAME%.exe

REM --- 8. Package ---
SET "DIST_ZIP_NAME=%DIST_ZIP%-windows"
SET "DIST_ZIP_PATH=%DIST_DIR%\%DIST_ZIP_NAME%.zip"
echo Creating %DIST_ZIP_PATH%...

REM --- 9. Package ---
REM Check for tar command
where tar >nul 2>&1
if errorlevel 1 (
    echo ERROR: 'tar' not found. Cannot create ZIP. Install Windows 10+ tar or use 7-Zip.
    exit /b 1
)

REM Prepare package
mkdir "%DIST_DIR%\%PACK_DIR%\rules" 2>nul

REM Copy app files
xcopy /E /I /Y config "%DIST_DIR%\%PACK_DIR%" >nul
xcopy /E /I /Y patterns "%DIST_DIR%\%PACK_DIR%" >nul
xcopy /Y rules\rules.low* "%DIST_DIR%\%PACK_DIR%\rules\" >nul
xcopy /Y rules\rule-set-policy.md "%DIST_DIR%\%PACK_DIR%\rules\" >nul
xcopy /Y README.md "%DIST_DIR%\%PACK_DIR%" >nul
copy /Y "%DIST_DIR%\%BIN_NAME%.exe" "%DIST_DIR%\%PACK_DIR%\" >nul
copy /Y LICENSE "%DIST_DIR%\%PACK_DIR%\" >nul

REM Copy commercial files if requested
if "%COMMERCIAL_BUILD%"=="True" (
    echo Including commercial files for enterprise build...
    xcopy /Y rules\rules.high* "%DIST_DIR%\%PACK_DIR%\rules\" >nul
    xcopy /Y rules\rules.medium* "%DIST_DIR%\%PACK_DIR%\rules\" >nul
    xcopy /Y rules\rules-overview* "%DIST_DIR%\%PACK_DIR%\rules\" >nul
    copy /Y LICENSE_COMMERCIAL.html "%DIST_DIR%\%PACK_DIR%\" >nul
)

REM ZIP using tar -a
cd "%DIST_DIR%\%PACK_DIR%"
tar -a -c -f ..\%DIST_ZIP_NAME%.zip *

cd ..
rmdir /s /q "%PACK_DIR%"

echo Distribution package created as "%DIST_ZIP_PATH%"
ENDLOCAL
pause
