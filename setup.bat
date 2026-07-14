@echo off
setlocal enabledelayedexpansion
title Threat Intel Hub - Setup
cd /d "%~dp0"
set "LOG=%~dp0setup-log.txt"
echo Threat Intel Hub setup - %date% %time% > "%LOG%"

echo.
echo  ===================================================
echo    THREAT INTEL HUB  -  SETUP + DIAGNOSTICS
echo  ===================================================
echo.
echo  Everything is also written to: setup-log.txt
echo.

:: ?? STEP 1: Node.js ?????????????????????????????????????????????????????????
echo  [1/4] Checking Node.js...
node --version >nul 2>&1
if errorlevel 1 (
    echo  [!] Node.js is NOT installed. Opening download page...
    echo  Node.js missing >> "%LOG%"
    start https://nodejs.org/en/download/
    goto :end
)
for /f "tokens=*" %%i in ('node --version') do set NODE_VERSION=%%i
echo  [OK] Node.js !NODE_VERSION!
echo  Node !NODE_VERSION! >> "%LOG%"

:: ?? STEP 2: Dependencies - check the actual Electron binary, not just the folder
echo.
echo  [2/4] Checking dependencies...
if not exist "node_modules\electron\dist\electron.exe" (
    echo  Electron binary missing - running npm install ^(2-3 min^)...
    call npm install >> "%LOG%" 2>&1
    if errorlevel 1 (
        echo  [!] npm install FAILED. Details are in setup-log.txt
        goto :end
    )
)
if not exist "node_modules\electron\dist\electron.exe" (
    echo  [!] npm install finished but electron.exe is still missing.
    echo      This usually means a corrupted download. Run:
    echo        rmdir /s /q node_modules
    echo        npm install
    goto :end
)
echo  [OK] Dependencies present ^(electron.exe found^).

:: ?? STEP 3: App files ???????????????????????????????????????????????????????
echo.
echo  [3/4] Verifying app files...
set FILES_OK=1
if not exist "main.js"                (echo  [!] main.js is MISSING & set FILES_OK=0)
if not exist "preload.js"             (echo  [!] preload.js is MISSING & set FILES_OK=0)
if not exist "renderer\index.html"    (echo  [!] renderer\index.html is MISSING - blank window guaranteed & set FILES_OK=0)
if not exist "renderer\renderer.js"   (echo  [!] renderer\renderer.js is MISSING - dead UI guaranteed & set FILES_OK=0)
if "%FILES_OK%"=="0" goto :end
echo  [OK] All app files present.

:: ?? STEP 4: Launch with full logging ????????????????????????????????????????
echo.
echo  [4/4] Launching with logging enabled...
echo        When the app closes, check setup-log.txt for errors.
echo.
set ELECTRON_ENABLE_LOGGING=1
call npm start >> "%LOG%" 2>&1
echo.
echo  App exited with code %errorlevel%.
echo  Full output is in setup-log.txt
echo  Renderer/crash details also in: %USERPROFILE%\tih-debug.log

:end
echo.
echo  This window will stay open so you can read the messages above.
pause
