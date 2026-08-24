@echo off
REM ============================================================================
REM  NetAttackAI — Quick Launcher
REM ============================================================================
REM  Double-click this file to start NetAttackAI. No install needed if you
REM  already ran install.bat — this just launches the app.
REM
REM  If the venv or deps are missing it will tell you to run install.bat first.
REM  Pass args through:  START.bat --target 10.0.0.50 --mode attack
REM ============================================================================
setlocal

set "REPO_ROOT=%~dp0"
if "%REPO_ROOT:~-1%"=="\" set "REPO_ROOT=%REPO_ROOT:~0,-1%"
pushd "%REPO_ROOT%" 2>nul || ( echo [!] cannot cd to %REPO_ROOT% & pause & exit /b 1 )

set "VENV_PY=%REPO_ROOT%\.venv\Scripts\python.exe"
set "RUN_PY="

if exist "%VENV_PY%" (
    set "RUN_PY=%VENV_PY%"
) else (
    where python >nul 2>&1 && set "RUN_PY=python"
    if not defined RUN_PY where py >nul 2>&1 && set "RUN_PY=py -3"
)

if not defined RUN_PY (
    echo  [!] Python not found. Run install.bat first.
    echo      Or install Python 3.11+ from https://www.python.org/downloads/
    pause
    popd
    exit /b 1
)

if not exist "%VENV_PY%" (
    echo  [--] .venv not found -- using system python. For best results run install.bat first.
    echo.
)

REM Check deps quickly; if main.py can't import yaml, tell user to install
call :py_run -c "import yaml" >nul 2>&1
if errorlevel 1 (
    echo  [!] Python dependencies not installed.
    echo      Run install.bat first, or use:  python -m pip install -r requirements.txt
    pause
    popd
    exit /b 1
)

REM Launch. Pass through any args given to START.bat (e.g. --target 10.0.0.50)
REM No args = WebUI daemon (same as `python main.py` default). Use --menu for TUI.
if "%~1"=="" (
    echo  Starting NetAttackAI -- WebUI at http://127.0.0.1:8765
    echo  (Use START.bat --menu for the terminal menu, or --help for flags)
    echo.
)
call :py_run "%REPO_ROOT%\main.py" %*
goto :after_py

:py_run
if "%RUN_PY%"=="py -3" (
    py -3 %*
    exit /b
)
if "%RUN_PY%"=="py" (
    py %*
    exit /b
)
"%RUN_PY%" %*
exit /b

:after_py

set "RC=%ERRORLEVEL%"
if not "%RC%"=="0" (
    echo.
    echo  [!] NetAttackAI exited with code %RC%
    echo      Run install.bat --check  or  python main.py --doctor  for diagnostics.
)

popd
endlocal
REM Keep window open when double-clicked so you can see the error
if "%~1"=="" pause
exit /b %RC%
