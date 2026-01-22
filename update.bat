@echo off
setlocal enabledelayedexpansion
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
    echo To enable automatic updates, install Git from git-scm.com
    echo.
    echo Continuing with dependency installation only...
    echo.
    goto INSTALL_DEPS
)

REM Check if this is a git repository
if not exist ".git" (
    echo This directory is not a git repository yet.
    echo.
    set /p "INIT_REPO=Do you want to initialize and pull from GitHub? (Y/N): "
    if /i "!INIT_REPO!"=="Y" (
        echo.
        echo Initializing git repository...
        git init
        git remote add origin https://github.com/4ntyr/xessenger
        echo.
        echo Pulling latest version...
        git fetch origin
        git reset --hard origin/main
        git branch -M main
        if errorlevel 1 (
            echo.
            echo WARNING: Git pull failed!
            echo.
        ) else (
            echo.
            echo Successfully pulled from GitHub!
            echo.
        )
    ) else (
        echo.
        echo Skipping git initialization.
        echo You can manually initialize later with: git init
        echo.
    )
    goto INSTALL_DEPS
)

echo Fetching latest changes from GitHub...
git fetch origin

echo.
echo Resetting local changes and pulling latest updates...
echo WARNING: This will overwrite any local modifications!
git reset --hard origin/main

if errorlevel 1 (
    echo.
    echo WARNING: Git update failed. Continuing with dependency installation...
    echo.
) else (
    echo.
    echo Successfully updated from GitHub!
    echo.
)

:INSTALL_DEPS
echo ========================================
echo Installing Python Dependencies
echo ========================================
echo.

REM Set default Python command
set PYTHON_CMD=python

REM Check if Python is installed in PATH
echo Checking for Python...
python --version >nul 2>&1
set PYTHON_ERROR=%errorlevel%
echo Python check errorlevel: %PYTHON_ERROR%

if %PYTHON_ERROR% neq 0 (
    echo WARNING: Python is not found in PATH
    echo.
    echo Please choose an option:
    echo [1] Enter custom Python installation path
    echo [2] Exit and add Python to PATH
    echo.
    set /p "PYTHON_CHOICE=Enter your choice (1 or 2): "
    echo You entered: !PYTHON_CHOICE!
    
    if "!PYTHON_CHOICE!"=="1" (
        echo.
        set /p "CUSTOM_PYTHON=Enter full path to python.exe: "
        echo Validating: !CUSTOM_PYTHON!
        
        REM Validate custom Python path
        call "!CUSTOM_PYTHON!" --version >nul 2>&1
        if errorlevel 1 (
            echo ERROR: Invalid Python path or Python not working
            echo.
            pause
            exit /b 1
        )
        set "PYTHON_CMD=!CUSTOM_PYTHON!"
        echo.
        echo Custom Python path set successfully.
        call "!PYTHON_CMD!" --version
    ) else (
        echo.
        echo Please install Python from python.org
        echo or add Python to your system PATH
        echo.
        pause
        exit /b 1
    )
) else (
    echo Python detected:
    call python --version
)

echo.

REM Check if pip is available
call "!PYTHON_CMD!" -m pip --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: pip is not available
    echo Please ensure pip is installed with Python
    echo.
    pause
    exit /b 1
)

echo Installing required packages...
echo.

REM Install packages one by one with error checking
echo [1/6] Installing cryptography...
call "!PYTHON_CMD!" -m pip install --upgrade cryptography
if errorlevel 1 (
    echo WARNING: Failed to install cryptography
)

echo.
echo [2/6] Installing bcrypt...
call "!PYTHON_CMD!" -m pip install --upgrade bcrypt
if errorlevel 1 (
    echo WARNING: Failed to install bcrypt
)

echo.
echo [3/6] Installing winotify...
call "!PYTHON_CMD!" -m pip install --upgrade winotify
if errorlevel 1 (
    echo WARNING: Failed to install winotify
)

echo.
echo [4/6] Installing requests...
call "!PYTHON_CMD!" -m pip install --upgrade requests
if errorlevel 1 (
    echo WARNING: Failed to install requests
)

echo.
echo [5/6] Installing Pillow...
call "!PYTHON_CMD!" -m pip install --upgrade Pillow
if errorlevel 1 (
    echo WARNING: Failed to install Pillow
)

echo.
echo [6/6] Installing tzdata...
call "!PYTHON_CMD!" -m pip install --upgrade tzdata
if errorlevel 1 (
    echo WARNING: Failed to install tzdata
)

echo.
echo ========================================
echo Setup Complete!
echo ========================================
echo.
if "!PYTHON_CMD!"=="python" (
    echo To start the server: python server.py
    echo To start the client: python client.py
) else (
    echo To start the server: "!PYTHON_CMD!" server.py
    echo To start the client: "!PYTHON_CMD!" client.py
)
echo.
pause
