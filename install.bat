@echo off
REM ============================================================================
REM  NetAttackAI — One-Click Installer for Windows
REM ============================================================================
REM  Double-click this file and it will set up everything you need to run
REM  NetAttackAI. No manual steps required — just follow the prompts.
REM
REM  What it does (all best-effort, safe to re-run any number of times):
REM    1. Checks / installs Python 3.11+, Node.js, Nmap, Ollama via winget
REM    2. Creates a Python venv (.venv) and installs Python deps
REM    3. Builds the WebUI (npm install + build) if Node is available
REM    4. Starts Ollama, pulls the default model + embedding model
REM    5. Guides you through the Ollama Cloud API key (OLLAMA_API_KEY)
REM    6. Runs `python main.py --doctor` to verify everything
REM    7. Installs the `natai` launcher to %USERPROFILE%\.local\bin + PATH
REM    8. Offers to launch the app immediately
REM
REM  Usage:
REM    install.bat                 one-click install (interactive, recommended)
REM    install.bat --yes           non-interactive (auto-approve winget installs)
REM    install.bat --check         only check prerequisites, don't install
REM    install.bat --uninstall     remove the `natai` command
REM    install.bat --help          show this help
REM
REM  Env knobs (set before invoking, all optional):
REM    set PYTHON=py -3.11         Python launcher to try first (default: auto)
REM    set VENV=.venv              venv directory (default: .venv)
REM    set SKIP_MODEL_PULL=1       skip `ollama pull ...`
REM    set SKIP_WEBUI_BUILD=1      skip WebUI npm build
REM    set ADD_TO_PATH=0           skip the `natai` launcher + PATH wiring
REM    set AUTO_WINGET=1           auto-approve winget installs without prompting
REM ============================================================================
setlocal enabledelayedexpansion

REM --- locate repo root (dir of this script) --------------------------------
set "REPO_ROOT=%~dp0"
if "%REPO_ROOT:~-1%"=="\" set "REPO_ROOT=%REPO_ROOT:~0,-1%"
pushd "%REPO_ROOT%" 2>nul || ( echo [!] cannot cd to %REPO_ROOT% & pause & exit /b 1 )

REM --- defaults ---------------------------------------------------------------
if "%PYTHON%"=="" set "PYTHON="
if "%VENV%"=="" set "VENV=.venv"
if "%SKIP_MODEL_PULL%"=="" set "SKIP_MODEL_PULL=0"
if "%SKIP_WEBUI_BUILD%"=="" set "SKIP_WEBUI_BUILD=0"
if "%ADD_TO_PATH%"=="" set "ADD_TO_PATH=1"
if "%AUTO_WINGET%"=="" set "AUTO_WINGET=0"
set "BIN_DIR=%USERPROFILE%\.local\bin"
set "ASSUME_YES=0"
set "CHECK_ONLY=0"

REM --- parse args -------------------------------------------------------------
for %%A in (%*) do (
    if /i "%%~A"=="--yes" set "ASSUME_YES=1"
    if /i "%%~A"=="-y" set "ASSUME_YES=1"
    if /i "%%~A"=="--check" set "CHECK_ONLY=1"
    if /i "%%~A"=="--help" goto :show_help
    if /i "%%~A"=="-h" goto :show_help
    if /i "%%~A"=="--uninstall" goto :do_uninstall
)
if "%ASSUME_YES%"=="1" set "AUTO_WINGET=1"

REM --- banner -----------------------------------------------------------------
echo.
echo  ============================================================
echo    NetAttackAI  --  One-Click Installer  (Windows)
echo  ============================================================
echo.
echo    This will set up everything you need to run NetAttackAI.
echo    Safe to re-run. Takes 2-5 minutes on first run.
echo.
if "%CHECK_ONLY%"=="1" (
    echo    Mode: CHECK ONLY -- no changes will be made.
    echo.
)
REM Small pause so double-click users can read the banner
if "%ASSUME_YES%"=="0" if "%CHECK_ONLY%"=="0" (
    echo    Press Enter to start, or Ctrl+C to cancel...
    set /p "_dummy="
)

REM ============================================================================
REM  0. Check winget availability (used for auto-installs)
REM ============================================================================
set "HAS_WINGET=0"
where winget >nul 2>&1 && set "HAS_WINGET=1"
if "%HAS_WINGET%"=="1" (
    echo  [OK] winget found -- can auto-install missing tools when you approve.
) else (
    echo  [--] winget not found -- missing tools will need manual install.
    echo       Get winget via App Installer: https://aka.ms/getwinget
)

REM ============================================================================
REM  1. Python 3.11+  (HARD REQUIREMENT)
REM ============================================================================
echo.
echo  ============================================================
echo   [1/7] Python 3.11+
echo  ============================================================

set "PY_CMD="
set "PY_VERSION="
set "PY_OK=0"

REM Try candidates in order: PYTHON env override, py -3, python, python3
if not "%PYTHON%"=="" (
    where %PYTHON% >nul 2>&1 && (
        for /f "tokens=*" %%V in ('%PYTHON% --version 2^>^&1') do set "PY_VERSION=%%V"
        echo   trying PYTHON="%PYTHON%" --^> !PY_VERSION!
        call :check_py_version "%PYTHON%"
        if "!PY_OK!"=="1" set "PY_CMD=%PYTHON%"
    )
)
if "!PY_OK!"=="0" (
    where py >nul 2>&1 && (
        for /f "tokens=*" %%V in ('py -3 --version 2^>^&1') do set "PY_VERSION=%%V"
        echo   trying py -3 --^> !PY_VERSION!
        call :check_py_version "py -3"
        if "!PY_OK!"=="1" set "PY_CMD=py -3"
    )
)
if "!PY_OK!"=="0" (
    where python >nul 2>&1 && (
        for /f "tokens=*" %%V in ('python --version 2^>^&1') do set "PY_VERSION=%%V"
        echo   trying python --^> !PY_VERSION!
        call :check_py_version "python"
        if "!PY_OK!"=="1" set "PY_CMD=python"
    )
)
if "!PY_OK!"=="0" (
    where python3 >nul 2>&1 && (
        for /f "tokens=*" %%V in ('python3 --version 2^>^&1') do set "PY_VERSION=%%V"
        echo   trying python3 --^> !PY_VERSION!
        call :check_py_version "python3"
        if "!PY_OK!"=="1" set "PY_CMD=python3"
    )
)

if "!PY_OK!"=="1" (
    echo   [OK] Python found: !PY_CMD! --^> !PY_VERSION!
    set "PYTHON=!PY_CMD!"
) else (
    echo   [!!] Python 3.11+ not found ^(need 3.11, 3.12 or 3.13^).
    if not "!PY_VERSION!"=="" echo       Found: !PY_VERSION! -- but version too old.
    echo.
    if "%CHECK_ONLY%"=="1" (
        echo   [--] check-only: would try winget install Python.Python.3.12 -- skipping.
    ) else if "%HAS_WINGET%"=="1" (
        call :ask_winget "Install Python 3.12 via winget (Python.Python.3.12)?" "winget install --id Python.Python.3.12 -e --silent --accept-package-agreements --accept-source-agreements"
        if "!PY_OK!"=="1" (
            REM re-detect after install
            set "PY_CMD="
            set "PY_OK=0"
            where py >nul 2>&1 && (
                for /f "tokens=*" %%V in ('py -3 --version 2^>^&1') do set "PY_VERSION=%%V"
                call :check_py_version "py -3"
                if "!PY_OK!"=="1" set "PY_CMD=py -3"
            )
            if "!PY_OK!"=="0" where python >nul 2>&1 && (
                for /f "tokens=*" %%V in ('python --version 2^>^&1') do set "PY_VERSION=%%V"
                call :check_py_version "python"
                if "!PY_OK!"=="1" set "PY_CMD=python"
            )
            if "!PY_OK!"=="1" (
                echo   [OK] Python now available: !PY_CMD! --^> !PY_VERSION!
                set "PYTHON=!PY_CMD!"
            ) else (
                echo   [!!] Python still not on PATH after winget install.
                echo       Close and re-open this terminal, then re-run install.bat
                echo       or install manually: https://www.python.org/downloads/
                echo       Tick "Add Python to PATH" in the installer.
                if "%CHECK_ONLY%"=="1" ( echo   [--] check-only: continuing checks... ) else ( pause & popd & exit /b 1 )
            )
        ) else (
            echo   [!] Skipped Python auto-install.
            echo       Install manually: https://www.python.org/downloads/
            echo       Tick "Add Python to PATH", then re-run install.bat
            echo       Or use: winget install Python.Python.3.12
            if "%CHECK_ONLY%"=="1" ( echo   [--] check-only: continuing... ) else ( pause & popd & exit /b 1 )
        )
    ) else (
        echo       Install Python 3.11+ from https://www.python.org/downloads/
        echo       Tick "Add Python to PATH" in the installer, then re-run install.bat
        if "%CHECK_ONLY%"=="1" (
            echo   [--] check-only: continuing...
        ) else (
            pause
            popd
            exit /b 1
        )
    )
)

if "%CHECK_ONLY%"=="1" goto :check_continue_python

REM ============================================================================
REM  2. System tools: Node.js, Nmap, Git, Ollama  (best-effort)
REM ============================================================================
:check_continue_python
echo.
echo  ============================================================
echo   [2/7] System tools  (Node.js, Nmap, Git, Ollama)
echo  ============================================================

REM --- Node.js ---
set "HAS_NODE=0"
where node >nul 2>&1 && set "HAS_NODE=1"
if "!HAS_NODE!"=="1" (
    for /f "tokens=*" %%V in ('node --version 2^>^&1') do set "NODE_VER=%%V"
    for /f "tokens=*" %%V in ('npm --version 2^>^&1') do set "NPM_VER=%%V"
    echo   [OK] Node.js !NODE_VER! / npm !NPM_VER! -- WebUI can be built.
) else (
    echo   [--] Node.js not on PATH -- WebUI build needs Node 18+ and npm.
    if "%HAS_WINGET%"=="1" (
        call :ask_winget "Install Node.js LTS via winget (OpenJS.NodeJS.LTS)?" "winget install --id OpenJS.NodeJS.LTS -e --silent --accept-package-agreements --accept-source-agreements"
        where node >nul 2>&1 && (
            for /f "tokens=*" %%V in ('node --version 2^>^&1') do set "NODE_VER=%%V"
            echo   [OK] Node.js now available: !NODE_VER!
            set "HAS_NODE=1"
        ) || echo   [--] Node.js still not on PATH -- open a NEW terminal after install, then re-run install.bat
    ) else (
        echo       Install from https://nodejs.org/ ^(LTS^) or: winget install OpenJS.NodeJS.LTS
        echo       Without Node, the WebUI builds on first `python main.py --web` if Node is added later.
    )
)

REM --- Nmap ---
where nmap >nul 2>&1 && ( echo   [OK] nmap found on PATH ) || (
    echo   [--] nmap not on PATH -- needed for recon scans.
    if "%HAS_WINGET%"=="1" (
        call :ask_winget "Install Nmap via winget (Insecure.Nmap)?" "winget install --id Insecure.Nmap -e --silent --accept-package-agreements --accept-source-agreements"
        where nmap >nul 2>&1 && echo   [OK] nmap now available || echo   [--] nmap still not on PATH -- re-open terminal or install from https://nmap.org/download.html
    ) else (
        echo       Install from https://nmap.org/download.html or: winget install Insecure.Nmap
    )
)

REM --- Git (optional) ---
where git >nul 2>&1 && ( echo   [OK] git found -- ChatGPT provider clone will work. ) || (
    echo   [--] git not on PATH -- only needed for ChatGPT provider ^(oauth clone^).
    if "%HAS_WINGET%"=="1" (
        call :ask_winget "Install Git via winget (Git.Git)?" "winget install --id Git.Git -e --silent --accept-package-agreements --accept-source-agreements"
        where git >nul 2>&1 && echo   [OK] git now available || echo   [--] git still not on PATH -- optional, re-open terminal if you need it.
    ) else (
        echo       Optional -- install from https://git-scm.com/downloads or: winget install Git.Git
    )
)

REM --- Ollama ---
set "HAS_OLLAMA=0"
where ollama >nul 2>&1 && set "HAS_OLLAMA=1"
if "!HAS_OLLAMA!"=="1" (
    echo   [OK] ollama found on PATH
) else (
    echo   [--] ollama not on PATH -- AI features need it.
    if "%HAS_WINGET%"=="1" (
        call :ask_winget "Install Ollama via winget (Ollama.Ollama)?" "winget install --id Ollama.Ollama -e --silent --accept-package-agreements --accept-source-agreements"
        where ollama >nul 2>&1 && ( echo   [OK] ollama now available & set "HAS_OLLAMA=1" ) || echo   [--] ollama still not on PATH -- install from https://ollama.com/download
    ) else (
        echo       Install from https://ollama.com/download -- OllamaSetup.exe
        echo       or: winget install Ollama.Ollama
    )
)

REM Check ollama daemon
if "!HAS_OLLAMA!"=="1" (
    powershell -NoProfile -Command "try { (Invoke-WebRequest -UseBasicParsing -Uri 'http://localhost:11434/api/version' -TimeoutSec 3).Content | Out-Null; $true } catch { $false }" >"%TEMP%\natai_ollama.txt" 2>nul
    set /p OLLAMA_UP=<"%TEMP%\natai_ollama.txt" 2>nul
    if /i "!OLLAMA_UP!"=="True" (
        echo   [OK] ollama daemon responding on http://localhost:11434
    ) else (
        echo   [--] ollama daemon not responding -- will try to start it later.
        echo       You can also start it via the Ollama tray app or `ollama serve`.
    )
    if exist "%TEMP%\natai_ollama.txt" del "%TEMP%\natai_ollama.txt" >nul 2>&1
)

where curl >nul 2>&1 && ( echo   [OK] curl found on PATH ) || ( echo   [--] curl not on PATH -- Windows 10+ ships it, but not required. )

echo   [--] Kali-only tools -- metasploit/searchsploit/hydra/impacket -- are Linux-only, not needed on Windows.

if "%CHECK_ONLY%"=="1" goto :check_continue_tools

REM ============================================================================
REM  3. Python venv + pip deps
REM ============================================================================
echo.
echo  ============================================================
echo   [3/7] Python environment  (.venv + pip deps)
echo  ============================================================

REM Re-validate PYTHON still works (winget may have placed it but not on current PATH)
set "VENV_OK=1"
set "VENV_PY=%REPO_ROOT%\%VENV%\Scripts\python.exe"
set "RUN_PY=%PYTHON%"

REM Handle "py -3" which has a space -- need to test differently
echo   Using Python: %PYTHON%
%PYTHON% --version 2>&1
if errorlevel 1 (
    echo   [!!] Python command failed: %PYTHON%
    echo       Try:py -3 --version  or  python --version  manually.
    pause
    popd
    exit /b 1
)

if not exist "%VENV_PY%" (
    echo   Creating venv: %VENV%
    %PYTHON% -m venv "%VENV%" 2>&1
    if errorlevel 1 (
        echo   [!!] venv creation failed.
        echo       Try: %PYTHON% -m pip install --upgrade pip
        echo       Or install python3-venv equivalent on Windows: re-install Python with venv support.
        set "VENV_OK=0"
    ) else (
        echo   [OK] venv created at %VENV%
    )
) else (
    echo   [OK] venv already exists at %VENV%
)

if "%VENV_OK%"=="1" if exist "%VENV_PY%" (
    set "RUN_PY=%VENV_PY%"
    echo   Upgrading pip...
    call :py_run -m pip install --upgrade pip >nul 2>&1
    if errorlevel 1 echo   [--] pip upgrade had warnings -- continuing.
    echo   Installing Python dependencies ^(requirements.txt^)...
    call :py_run -m pip install -r requirements.txt
    if errorlevel 1 (
        echo   [!!] pip install had errors -- network issue? Retrying once...
        timeout /t 3 /nobreak >nul 2>&1
        call :py_run -m pip install -r requirements.txt
        if errorlevel 1 (
            echo   [!!] pip install still failing -- check your internet.
            echo       You can re-run install.bat after fixing the network.
            echo       `natai` will still be installed, but `python main.py` may fail until deps are present.
        ) else (
            echo   [OK] dependencies installed on retry.
        )
    ) else (
        echo   [OK] dependencies installed.
    )
) else (
    echo   [--] No usable venv -- will use system python for remaining steps.
    echo       Deps may be missing; `natai` will fall back to system python.
)

REM --- openai-oauth (ChatGPT provider, opt-in) -------------------------------
echo.
echo   Checking ChatGPT provider support ^(optional^)...
if exist "%REPO_ROOT%\oauth\packages\openai-oauth\src\cli.ts" (
    where bun >nul 2>&1 && (
        echo   [OK] oauth checkout + bun found -- preparing openai-oauth...
        pushd "%REPO_ROOT%\oauth" 2>nul
        bun install >nul 2>&1
        if errorlevel 1 (
            echo   [--] bun install failed in oauth\ -- ChatGPT provider not runnable until it succeeds.
            echo       See docs/providers.md -- or run: cd oauth ^&^& bun install
        ) else (
            echo   [OK] openai-oauth ready.
        )
        popd 2>nul
    ) || (
        echo   [--] bun not on PATH -- ChatGPT provider is opt-in.
        echo       To use ChatGPT: install bun from https://bun.sh then run: cd oauth ^&^& bun install
        echo       See docs/providers.md. Ollama provider works without bun.
    )
) else (
    echo   [--] No oauth\ checkout -- ChatGPT provider is opt-in, Ollama works without it.
    echo       See docs/providers.md if you want ChatGPT instead of Ollama.
)

:check_continue_tools

REM ============================================================================
REM  4. WebUI build  (needs Node.js)
REM ============================================================================
echo.
echo  ============================================================
echo   [4/7] WebUI
echo  ============================================================

if "%CHECK_ONLY%"=="1" (
    if not exist "%REPO_ROOT%\webui\dist\index.html" (
        echo   [--] WebUI not built -- would build now ^(check-only: not building^).
        where npm >nul 2>&1 && echo       Would run: npm install ^&^& npm run build in webui\ || echo       Would need Node.js first: https://nodejs.org/
    ) else (
        echo   [OK] WebUI already built at webui\dist\index.html
    )
) else if "%SKIP_WEBUI_BUILD%"=="1" (
    echo   [--] Skipping WebUI build ^(SKIP_WEBUI_BUILD=1^).
) else (
    if not exist "%REPO_ROOT%\webui\package.json" (
        echo   [--] webui\package.json not found -- skipping WebUI build.
    ) else (
        if not exist "%REPO_ROOT%\webui\dist\index.html" (
            echo   WebUI not yet built -- building now ^(first run only, 1-2 min^)...
            where npm >nul 2>&1 && (
                echo   Running: npm install ^(in webui\^)
                pushd "%REPO_ROOT%\webui" 2>nul
                call npm install --no-audit --no-fund
                if errorlevel 1 (
                    echo   [!!] npm install failed -- WebUI will build on first `python main.py --web` instead.
                    echo       Check Node.js is 18+ : node --version
                ) else (
                    echo   Running: npm run build
                    call npm run build
                    if errorlevel 1 (
                        echo   [!!] npm run build failed -- WebUI will build on first `python main.py --web`.
                    ) else (
                        if exist "%REPO_ROOT%\webui\dist\index.html" (
                            echo   [OK] WebUI built to webui\dist\
                        ) else (
                            echo   [!!] Build finished but webui\dist\index.html missing -- will retry on next run.
                        )
                    )
                )
                popd 2>nul
            ) || (
                echo   [--] npm not on PATH -- skipping WebUI build.
                echo       Install Node.js ^(https://nodejs.org/^) then re-run install.bat
                echo       or run: cd webui ^&^& npm install ^&^& npm run build
                echo       The app will also build the WebUI automatically on first `python main.py --web`.
            )
        ) else (
            echo   [OK] WebUI already built at webui\dist\index.html
        )
    )
)

if "%CHECK_ONLY%"=="1" goto :check_summary

REM ============================================================================
REM  5. Ollama daemon + models
REM ============================================================================
echo.
echo  ============================================================
echo   [5/7] Ollama models
echo  ============================================================

if "%SKIP_MODEL_PULL%"=="1" (
    echo   [--] Skipping model pull ^(SKIP_MODEL_PULL=1^).
) else (
    if "!HAS_OLLAMA!"=="0" where ollama >nul 2>&1 && set "HAS_OLLAMA=1"
    if "!HAS_OLLAMA!"=="0" (
        echo   [--] Skipping model pull -- ollama not on PATH.
        echo       Install Ollama, then run: ollama pull glm-5.2:cloud
        echo                            and: ollama pull nomic-embed-text
    ) else (
        REM Try to start daemon if not responding
        powershell -NoProfile -Command "try { (Invoke-WebRequest -UseBasicParsing -Uri 'http://localhost:11434/api/version' -TimeoutSec 2).Content | Out-Null; $true } catch { $false }" >"%TEMP%\natai_ollama2.txt" 2>nul
        set /p OLLAMA_UP2=<"%TEMP%\natai_ollama2.txt" 2>nul
        if /i not "!OLLAMA_UP2!"=="True" (
            echo   Starting ollama serve in background...
            start "" /min ollama serve >nul 2>&1
            echo   Waiting for daemon ^(up to 15s^)...
            for /l %%I in (1,1,15) do (
                timeout /t 1 /nobreak >nul 2>&1
                powershell -NoProfile -Command "try { (Invoke-WebRequest -UseBasicParsing -Uri 'http://localhost:11434/api/version' -TimeoutSec 2).Content | Out-Null; $true } catch { $false }" >"%TEMP%\natai_ollama2.txt" 2>nul
                set /p OLLAMA_UP2=<"%TEMP%\natai_ollama2.txt" 2>nul
                if /i "!OLLAMA_UP2!"=="True" goto :ollama_up
            )
            :ollama_up
            if /i "!OLLAMA_UP2!"=="True" ( echo   [OK] ollama daemon now responding ) else ( echo   [--] ollama daemon still not responding -- model pull may fail. Start it via Ollama app or `ollama serve`. )
        ) else (
            echo   [OK] ollama daemon responding.
        )
        if exist "%TEMP%\natai_ollama2.txt" del "%TEMP%\natai_ollama2.txt" >nul 2>&1

        echo   Pulling models ^(best-effort; cloud model needs OLLAMA_API_KEY^)...
        ollama pull glm-5.2:cloud
        if errorlevel 1 echo   [--] glm-5.2:cloud pull failed -- is OLLAMA_API_KEY set? Is the daemon running?
        ollama pull nomic-embed-text
        if errorlevel 1 echo   [--] nomic-embed-text pull failed -- needed for semantic memory; will retry on next run.
    )
)

REM ============================================================================
REM  6. API keys  (OLLAMA_API_KEY etc.)
REM ============================================================================
echo.
echo  ============================================================
echo   [6/7] API keys
echo  ============================================================
echo   NetAttackAI uses Ollama Cloud by default ^(https://api.ollama.com^).
echo   That needs OLLAMA_API_KEY. Without it, --doctor will report
echo   Ollama unreachable and local-only mode is the fallback.
echo.

set "HAS_KEY=0"
if not "%OLLAMA_API_KEY%"=="" set "HAS_KEY=1"
if exist "%REPO_ROOT%\secr.json" (
    findstr /c:"OLLAMA_API_KEY" "%REPO_ROOT%\secr.json" >nul 2>&1 && set "HAS_KEY=1"
)
if exist "%REPO_ROOT%\.env" (
    findstr /c:"OLLAMA_API_KEY" "%REPO_ROOT%\.env" >nul 2>&1 && set "HAS_KEY=1"
)

if "!HAS_KEY!"=="1" (
    echo   [OK] OLLAMA_API_KEY appears to be set ^(env or secr.json/.env^).
) else (
    echo   [--] OLLAMA_API_KEY not found in env / secr.json / .env
    echo       Get a key at https://ollama.com/settings/keys  ^(free tier available^)
    echo.
    if "%ASSUME_YES%"=="0" (
        echo       Options:
        echo         1. Enter your OLLAMA_API_KEY now  --^> saved to secr.json
        echo         2. Skip -- set it later via:  python main.py --setup-api-keys
        echo            or set env:  set OLLAMA_API_KEY=your_key_here
        echo         3. Use a local Ollama instead -- set ollama.host: http://localhost:11434 in config.yaml
        echo.
        set "OLLAMA_KEY_INPUT="
        set /p OLLAMA_KEY_INPUT="       Paste OLLAMA_API_KEY (or Enter to skip): "
        if not "!OLLAMA_KEY_INPUT!"=="" (
            REM Save via main.py --setup-api-keys non-interactively is not supported,
            REM so we write secr.json directly (minimal, gitignored).
            powershell -NoProfile -Command "$k = $env:OLLAMA_KEY_INPUT.Trim(); if ($k) { $p = Join-Path '%REPO_ROOT%' 'secr.json'; $j = @{}; if (Test-Path $p) { try { $j = Get-Content $p -Raw | ConvertFrom-Json -AsHashtable } catch {} }; $j['OLLAMA_API_KEY'] = $k; $j | ConvertTo-Json | Set-Content $p -Encoding utf8; Write-Host '  [OK] saved to secr.json' } else { Write-Host '  [--] empty key, skipped' }" 2>nul
            REM Also set for this session so doctor/model-pull can use it
            set "OLLAMA_API_KEY=!OLLAMA_KEY_INPUT!"
            echo   [OK] Key set for this session; re-run `ollama pull glm-5.2:cloud` if it failed above.
        ) else (
            echo   [--] Skipped -- you can set it later with: python main.py --setup-api-keys
        )
    ) else (
        echo       Non-interactive: skipped. Set it later with:
        echo         python main.py --setup-api-keys
        echo       or: set OLLAMA_API_KEY=your_key_here
    )
    echo.
    echo   Other optional keys: NVD_API_KEY, GITHUB_TOKEN, SERPAPI_API_KEY
    echo   Set them via: python main.py --setup-api-keys  or  secr.json
)

REM ============================================================================
REM  7. Doctor + natai launcher
REM ============================================================================
echo.
echo  ============================================================
echo   [7/7] Final checks  (doctor + natai launcher)
echo  ============================================================

echo   Running: python main.py --doctor
echo   ------------------------------------------------------------
call :py_run main.py --doctor
set "DOCTOR_RC=%ERRORLEVEL%"
echo   ------------------------------------------------------------
if "%DOCTOR_RC%"=="0" (
    echo   [OK] --doctor passed -- you're ready to run!
) else (
    echo   [--] --doctor reported issues above -- see hints for each FAIL line.
    echo       Common fixes:
    echo         - OLLAMA_API_KEY missing --^> python main.py --setup-api-keys
    echo         - nmap missing --^> winget install Insecure.Nmap
    echo         - ollama daemon not running --^> ollama serve  or start Ollama app
    echo         - model missing --^> ollama pull glm-5.2:cloud
    echo       Re-run install.bat after fixing, or run `python main.py --doctor` again.
)

REM --- Install the `natai` command to %USERPROFILE%\.local\bin ----------------
if "%ADD_TO_PATH%"=="1" (
    echo.
    echo   Installing `natai` launcher...
    if not exist "%BIN_DIR%" mkdir "%BIN_DIR%" >nul 2>&1

    REM Write a tiny launcher that always runs from the repo root, so
    REM config.yaml / mission.yaml / reports/ resolve regardless of cwd.
    REM NOTE: the launcher references %REPO_ROOT% literally at generation time;
    REM re-running install.bat after moving the repo rewrites it correctly.
    > "%BIN_DIR%\natai.bat" echo @echo off
    >> "%BIN_DIR%\natai.bat" echo REM natai - NetAttackAI launcher ^(generated by install.bat^)
    >> "%BIN_DIR%\natai.bat" echo REM Always runs from the repo root so config.yaml/mission.yaml/reports/ resolve.
    >> "%BIN_DIR%\natai.bat" echo pushd "%REPO_ROOT%" 2^>nul ^|^| ( echo natai: repo not found at %REPO_ROOT% ^& exit /b 1 )
    >> "%BIN_DIR%\natai.bat" echo set "NATAI_PY=%VENV_PY%"
    >> "%BIN_DIR%\natai.bat" echo if not exist "%%NATAI_PY%%" set "NATAI_PY=python"
    >> "%BIN_DIR%\natai.bat" echo "%%NATAI_PY%%" "%REPO_ROOT%\main.py" %%*
    >> "%BIN_DIR%\natai.bat" echo set "NATAI_PY="
    >> "%BIN_DIR%\natai.bat" echo popd
    echo   [OK] natai -^> %BIN_DIR%\natai.bat

    REM Ensure %USERPROFILE%\.local\bin is on the user PATH (idempotent)
    for /f "usebackq tokens=*" %%P in (`powershell -NoProfile -Command "try { $p = [Environment]::GetEnvironmentVariable('PATH','User'); if (-not $p) { [Environment]::SetEnvironmentVariable('PATH', '%BIN_DIR%', 'User'); 'added' } elseif ($p.Split(';') -contains '%BIN_DIR%') { 'present' } else { $new = if ($p.EndsWith(';')) { $p + '%BIN_DIR%' } else { $p + ';%BIN_DIR%' }; [Environment]::SetEnvironmentVariable('PATH', $new, 'User'); 'added' } } catch { 'error' }"`) do set "PATHRES=%%P"
    if /i "!PATHRES!"=="present" ( echo   [OK] %BIN_DIR% already on user PATH )
    if /i "!PATHRES!"=="added"  ( echo   [OK] added %BIN_DIR% to user PATH -- open a NEW terminal for `natai` to work )
    if /i "!PATHRES!"=="error"  ( echo   [!] could not update user PATH -- add %BIN_DIR% manually )
) else (
    echo   [--] Skipping `natai` install ^(ADD_TO_PATH=0^)
)

REM ============================================================================
REM  Done
REM ============================================================================
echo.
echo  ============================================================
echo    Done!
echo  ============================================================
echo.
echo    Quick start  (after opening a NEW terminal if PATH was just updated):
echo.
echo      natai                         interactive menu ^(or: START.bat^)
echo      natai --target 10.0.0.50 --mode attack --goal backdoor
echo      natai --doctor                re-check environment
echo      natai --web                   launch WebUI at http://127.0.0.1:8765
echo.
echo    Without `natai` ^(same, from this repo folder^):
echo      python main.py                interactive menu
echo      python main.py --web          WebUI + browser
echo      START.bat                     double-click launcher
echo.
echo    Tips:
echo      - First run builds the WebUI if Node was just installed -- needs npm.
echo      - Set API keys:  python main.py --setup-api-keys
echo      - Ollama Cloud key: https://ollama.com/settings/keys
echo      - Only run against networks you own or are explicitly authorized to test.
echo.
echo    Re-run install.bat any time to update deps or fix issues.
echo    Uninstall the `natai` command with:  install.bat --uninstall
echo.

REM Offer to launch now (interactive only)
if "%ASSUME_YES%"=="0" if "%CHECK_ONLY%"=="0" (
    echo    Launch NetAttackAI now?
    echo      [1] Yes -- interactive menu  ^(python main.py^)
    echo      [2] Yes -- WebUI in browser  ^(python main.py --web^)
    echo      [3] No  -- exit installer
    set "LAUNCH_CHOICE="
    set /p LAUNCH_CHOICE="    Choice [1/2/3, default 3]: "
    if "!LAUNCH_CHOICE!"=="1" (
        echo.
        echo    Launching interactive menu...
        call :py_run main.py --menu
    ) else if "!LAUNCH_CHOICE!"=="2" (
        echo.
        echo    Launching WebUI...
        call :py_run main.py --web
    ) else (
        echo.
        echo    Exit. Run START.bat or `natai` when ready.
    )
)

REM If double-clicked, keep window open
if "%ASSUME_YES%"=="0" (
    echo.
    pause
)

popd
endlocal
exit /b 0

REM ============================================================================
REM  Subroutines
REM ============================================================================

:py_run
REM Run python with args, handling both "py -3" (space) and quoted paths.
REM Uses RUN_PY global. Example: call :py_run -m pip install -r requirements.txt
if "!RUN_PY!"=="py -3" (
    py -3 %*
) else if "!RUN_PY!"=="py" (
    py %*
) else if "!RUN_PY!"=="python3" (
    python3 %*
) else (
    "!RUN_PY!" %*
)
exit /b

:check_py_version
REM Arg %1 is the python command to test (e.g. "py -3" or "python")
REM Sets PY_OK=1 if version >= 3.11, else 0. Uses PY_VERSION already captured
REM but re-queries for robustness.
set "PY_OK=0"
set "_PYCMD=%~1"
REM Use powershell to parse version robustly (handles "Python 3.12.4" etc.)
for /f "tokens=*" %%A in ('powershell -NoProfile -Command "try { $v = & %_PYCMD% --version 2>&1; if ($v -match '(\d+)\.(\d+)') { $maj=[int]$Matches[1]; $min=[int]$Matches[2]; if ($maj -gt 3 -or ($maj -eq 3 -and $min -ge 11)) { 'OK' } else { 'OLD' } } else { 'UNKNOWN' } } catch { 'ERROR' }"') do set "_PYRES=%%A"
if /i "!_PYRES!"=="OK" set "PY_OK=1"
exit /b

:ask_winget
REM %1 = prompt question, %2 = winget command to run
REM Respects CHECK_ONLY / ASSUME_YES / AUTO_WINGET.
set "_Q=%~1"
set "_CMD=%~2"
if "%CHECK_ONLY%"=="1" (
    echo   [--] check-only: would prompt: !_Q!
    echo       Command: !_CMD!
    exit /b
)
if "%AUTO_WINGET%"=="1" (
    echo   Auto-install: !_Q!
    echo   Running: !_CMD!
    call !_CMD!
    exit /b
)
if "%ASSUME_YES%"=="1" (
    echo   Auto-install: !_Q!
    call !_CMD!
    exit /b
)
set "_ANS="
set /p _ANS="   !_Q! [y/N]: "
if /i "!_ANS!"=="y" (
    echo   Running: !_CMD!
    call !_CMD!
) else if /i "!_ANS!"=="yes" (
    echo   Running: !_CMD!
    call !_CMD!
) else (
    echo   [--] Skipped.
)
exit /b

:show_help
echo.
echo  NetAttackAI Installer -- Help
echo.
echo  Usage:
echo    install.bat                 one-click install ^(interactive^)
echo    install.bat --yes           non-interactive ^(auto-approve winget^)
echo    install.bat --check         only check prerequisites, don't install
echo    install.bat --uninstall     remove the `natai` command
echo    install.bat --help          show this help
echo.
echo  What it does:
echo    1. Checks/installs Python 3.11+, Node.js, Nmap, Ollama via winget
echo    2. Creates .venv and installs Python deps
echo    3. Builds the WebUI if Node is available
echo    4. Starts Ollama and pulls default models
echo    5. Guides API key setup ^(OLLAMA_API_KEY^)
echo    6. Runs --doctor and installs the `natai` launcher
echo.
echo  Env knobs:
echo    PYTHON=py -3.11           Python command to try first
echo    VENV=.venv                venv directory
echo    SKIP_MODEL_PULL=1         skip ollama pull
echo    SKIP_WEBUI_BUILD=1        skip WebUI build
echo    ADD_TO_PATH=0             skip natai launcher
echo    AUTO_WINGET=1             auto-approve winget installs
echo.
echo  After install:
echo    natai / START.bat / python main.py
echo.
popd
endlocal
exit /b 0

:do_uninstall
echo  ==^> Removing the `natai` command
if exist "%BIN_DIR%\natai.bat" (
    del "%BIN_DIR%\natai.bat" >nul 2>&1 && echo   [OK] removed %BIN_DIR%\natai.bat
) else (
    echo   [--] %BIN_DIR%\natai.bat was not present
)
echo.
echo  Uninstalled. The `natai` command is gone; %BIN_DIR% left on PATH ^(shared with other tools^).
popd
endlocal
exit /b 0

:check_summary
echo.
echo  ============================================================
echo    Check complete -- no changes made ^(--check mode^)
echo  ============================================================
echo.
echo    Run without --check to install missing pieces:
echo      install.bat
echo.
popd
endlocal
exit /b 0
