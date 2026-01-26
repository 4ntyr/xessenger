@echo off
REM Xessenger Client Launcher
REM Double-click this file to start the Xessenger client

title Xessenger Client

echo.
echo ========================================
echo      🔐 Xessenger Client Launcher
echo ========================================
echo.

REM Check if Python is available
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Python is not installed or not in PATH
    echo.
    echo Please install Python from python.org
    echo Make sure to check "Add Python to PATH" during installation
    echo.
    echo After installing Python, run update.bat first to install dependencies.
    echo.
    pause
    exit /b 1
)

REM Check if dependencies are installed
echo Checking dependencies...
python -c "import cryptography, winotify, requests, PIL" >nul 2>&1
if %errorlevel% neq 0 (
    echo.
    echo WARNING: Some dependencies are missing!
    echo Please run update.bat first to install all required packages.
    echo.
    set /p "CONTINUE=Continue anyway? (Y/N): "
    if /i not "!CONTINUE!"=="Y" (
        echo.
        echo Exiting. Please run update.bat
        pause
        exit /b 1
    )
)

echo.
echo Starting Xessenger Client...
echo.

REM Start the client
python client.py

REM If client exits with error, pause to show error message
if errorlevel 1 (
    echo.
    echo Client exited with an error.
    pause
)
