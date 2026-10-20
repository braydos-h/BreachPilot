@echo off
REM ============================================================================
REM  BreachPilot — Native Go + Rust Windows Launcher
REM ============================================================================
setlocal

set "REPO_ROOT=%~dp0"
if "%REPO_ROOT:~-1%"=="\" set "REPO_ROOT=%REPO_ROOT:~0,-1%"
pushd "%REPO_ROOT%" 2>nul || ( echo [!] cannot cd to %REPO_ROOT% & exit /b 1 )

if not exist "%REPO_ROOT%\bp.exe" (
    where go >nul 2>&1 || (
        echo [!] bp.exe not built and Go toolchain not found. Run install.bat first.
        popd
        exit /b 1
    )
    echo Building BreachPilot native binary bp.exe ...
    go build -o "%REPO_ROOT%\bp.exe" ./cmd/bp || (
        echo [!] Failed to build bp.exe
        popd
        exit /b 1
    )
)

if "%~1"=="" (
    echo Starting BreachPilot native daemon at http://127.0.0.1:8765
)
"%REPO_ROOT%\bp.exe" %*
set "RC=%ERRORLEVEL%"

popd
endlocal & exit /b %RC%
