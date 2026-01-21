@echo off
REM Xessenger - Update and Setup Script
REM Pulls latest changes from GitHub and installs dependencies

echo ========================================
echo Xessenger Update Script
echo ========================================
echo.

REM Check if git is installed
git --version >nul 2>&1
if %errorlevel% neq 0 (
    echo WARNING: Git is not installed or not in PATH
    echo To enable automatic updates, install Git from https://git-scm.com/
    echo.
    echo Continuing with dependency installation only...
    echo.
    goto INSTALL_DEPS
)

REM Check if this is a git repository
if not exist ".git" (
    echo This directory is not a git repository yet.
    echo.
    set /p INIT_REPO="Do you want to initialize and pull from GitHub? (Y/N): "
    if /i "%INIT_REPO%"=="Y" (
        echo.
        echo Initializing git repository...
        git init
        git remote add origin https://github.com/4ntyr/xessenger
        echo.
        echo Pulling latest version...
        git pull origin main
        echo.
    ) else (
        echo Skipping git initialization.
        echo.
    )
    goto INSTALL_DEPS
)

echo Fetching latest changes from GitHub...
git fetch origin

echo.
echo Pulling latest updates...
git pull origin main

if %errorlevel% neq 0 (
    echo.
    echo WARNING: Git pull failed. Continuing with dependency installation...
    echo.
)

:INSTALL_DEPS
echo ========================================
echo Installing Python Dependencies
echo ========================================
echo.

REM Check if Python is installed
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Python is not installed or not in PATH
    echo Please install Python from https://www.python.org/
    echo.
    pause
    exit /b 1
)

echo Python detected:
python --version
echo.

REM Check if pip is available
python -m pip --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: pip is not available
    echo Please ensure pip is installed with Python
    echo.
    pause
    exit /b 1
)

echo Installing required packages...
echo.

REM Install packages one by one with error checking
echo [1/3] Installing cryptography...
python -m pip install --upgrade cryptography
if %errorlevel% neq 0 (
    echo WARNING: Failed to install cryptography
)

echo.
echo [2/3] Installing winotify...
python -m pip install --upgrade winotify
if %errorlevel% neq 0 (
    echo WARNING: Failed to install winotify
)

echo.
echo [3/3] Installing tzdata...
python -m pip install --upgrade tzdata
if %errorlevel% neq 0 (
    echo WARNING: Failed to install tzdata
)

echo.
echo ========================================
echo Setup Complete!
echo ========================================
echo.
echo To start the server: python server.py
echo To start the client: python client.py
echo.
pause
