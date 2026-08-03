@echo off
REM One-shot host bootstrap for the NetAttackAI engine (Windows).
REM
REM Windows parallel of install.sh: creates the Python venv + requirements, best-effort
REM checks for Ollama + Nmap, pulls the default model + embedding model, runs
REM `python main.py --doctor`, then installs a `natai` launcher to
REM %USERPROFILE%\.local\bin and wires it onto the user PATH.
REM
REM Idempotent: safe to re-run. Run from the repository root:
REM     install.bat
REM     install.bat --uninstall
REM
REM Env knobs (set before invoking):
REM     set PYTHON=py            (default: python)
REM     set VENV=.venv           (default: .venv)
REM     set SKIP_MODEL_PULL=1    (skip `ollama pull ...`)
REM     set ADD_TO_PATH=0        (skip the `natai` launcher + PATH wiring)
setlocal enabledelayedexpansion

REM --- locate repo root (dir of this script) --------------------------------
set "REPO_ROOT=%~dp0"
if "%REPO_ROOT:~-1%"=="\" set "REPO_ROOT=%REPO_ROOT:~0,-1%"
pushd "%REPO_ROOT%" 2>nul || ( echo [!] cannot cd to %REPO_ROOT% & exit /b 1 )

set "PYTHON=%PYTHON%"
if "%PYTHON%"=="" set "PYTHON=python"
set "VENV=%VENV%"
if "%VENV%"=="" set "VENV=.venv"
if "%SKIP_MODEL_PULL%"=="" set "SKIP_MODEL_PULL=0"
if "%ADD_TO_PATH%"=="" set "ADD_TO_PATH=1"
set "BIN_DIR=%USERPROFILE%\.local\bin"

REM --- --uninstall (run before anything else) -------------------------------
if /i "%~1"=="--uninstall" (
    echo ==^> Removing the `natai` command
    if exist "%BIN_DIR%\natai.bat" (
        del "%BIN_DIR%\natai.bat" >nul 2>&1 && echo   [OK] removed %BIN_DIR%\natai.bat
    ) else (
        echo   [--] %BIN_DIR%\natai.bat was not present
    )
    REM NOTE: we deliberately do NOT remove %BIN_DIR% from the user PATH.
    REM That directory is shared with other tools (e.g. uv, claude); stripping it
    REM would break them. install.sh uses a guarded block; on Windows we only
    REM ever add the dir (idempotent), so the entry is harmless once natai.bat is gone.
    echo.
    echo Uninstalled. The `natai` command is gone; %BIN_DIR% left on PATH ^(shared with other tools^).
    popd
    exit /b 0
)

REM --- 1. OS-level prerequisites (best-effort; never aborts the install) ----
echo ==^> Checking OS-level prerequisites

where nmap >nul 2>&1 && ( echo   [OK] nmap found on PATH ) || ( echo   [!] nmap not on PATH -- install from https://nmap.org/download.html )
where curl >nul 2>&1 && ( echo   [OK] curl found on PATH ) || ( echo   [!] curl not on PATH -- Windows 10+ ships it )

REM Optional Kali-style tooling: only mention, never required on Windows.
echo   [--] Kali-only tools -- metasploit/searchsploit/hydra/impacket -- are not auto-installed on Windows.

REM --- 2. Ollama (best-effort) ----------------------------------------------
echo ==^> Ensuring Ollama is installed and running
where ollama >nul 2>&1 && ( echo   [OK] ollama found on PATH ) || (
    echo   [!] ollama not on PATH.
    echo       Install from https://ollama.com/download -- OllamaSetup.exe -- or:  winget install Ollama.Ollama
    echo       AI-backed flows will fail until Ollama is installed.
)
REM If ollama is present, try to confirm the daemon answers (local embed host).
where ollama >nul 2>&1 && (
    powershell -NoProfile -Command "try { (Invoke-WebRequest -UseBasicParsing -Uri 'http://localhost:11434/api/version' -TimeoutSec 3).Content | Out-Null; $true } catch { $false }" >"%TEMP%\natai_ollama.txt" 2>nul
    set /p OLLAMA_UP=<"%TEMP%\natai_ollama.txt"
    if /i "!OLLAMA_UP!"=="True" (
        echo   [OK] ollama daemon responding on http://localhost:11434
    ) else (
        echo   [--] ollama daemon not responding on localhost:11434 ^(start it via the Ollama tray app or `ollama serve`^)
    )
    if exist "%TEMP%\natai_ollama.txt" del "%TEMP%\natai_ollama.txt" >nul 2>&1
)

REM --- 3. Python venv + requirements (resilient) -----------------------------
REM python is the one true hard requirement: without it nothing works.
where %PYTHON% >nul 2>&1 || (
    echo   [!] '%PYTHON%' not found. Install Python 3.10+ from https://www.python.org/downloads/ or set PYTHON=... e.g. py -3.11.
    echo       On Windows, tick "Add Python to PATH" in the installer, or use `py -3` as PYTHON.
    popd
    exit /b 1
)
echo ==^> Creating venv ^(%VENV%^) with:
%PYTHON% --version
set "VENV_OK=1"
if not exist "%REPO_ROOT%\%VENV%\Scripts\python.exe" (
    %PYTHON% -m venv "%VENV%" || (
        echo   [!] venv creation failed. Continuing -- `natai` will fall back to system python, but deps may be missing.
        set "VENV_OK=0"
    )
)
set "VENV_PY=%REPO_ROOT%\%VENV%\Scripts\python.exe"
set "RUN_PY=%PYTHON%"
if "%VENV_OK%"=="1" if exist "%VENV_PY%" (
    set "RUN_PY=%VENV_PY%"
    echo ==^> Upgrading pip + installing requirements
    call "!RUN_PY!" -m pip install --upgrade pip || echo   [!] pip upgrade failed -- continuing
    call "!RUN_PY!" -m pip install -r requirements.txt || echo   [!] pip install -r requirements.txt failed -- network? Re-run install.bat once available -- `natai` still installs.
) else (
    echo   [!] no usable venv interpreter; skipping pip install. `natai` will use system python.
)

REM --- 4. Pull models (best-effort) -----------------------------------------
if not "%SKIP_MODEL_PULL%"=="1" (
    where ollama >nul 2>&1 && (
        echo ==^> Pulling default model + embedding model ^(best-effort^)
        ollama pull glm-5.2:cloud      || echo   [--] glm-5.2:cloud pull failed ^(daemon running? reachable?^)
        ollama pull nomic-embed-text   || echo   [--] nomic-embed-text pull failed ^(needed for semantic memory^)
    ) || (
        echo ==^> Skipping model pull ^(ollama absent^)
    )
) else (
    echo ==^> Skipping model pull ^(SKIP_MODEL_PULL=1^)
)

REM --- 5. Doctor (best-effort) ----------------------------------------------
echo ==^> Running --doctor
"%RUN_PY%" main.py --doctor || echo   [!] --doctor reported failures above; fix them before running the engine.

REM --- 6. Install the `natai` command to %USERPROFILE%\.local\bin ------------
if "%ADD_TO_PATH%"=="1" (
    echo ==^> Installing `natai` command
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
    >> "%BIN_DIR%\natai.bat" echo if not exist "%VENV_PY%" set "NATAI_PY=python"
    >> "%BIN_DIR%\natai.bat" echo "%%NATAI_PY%%" "%REPO_ROOT%\main.py" %%*
    >> "%BIN_DIR%\natai.bat" echo set "NATAI_PY="
    >> "%BIN_DIR%\natai.bat" echo popd
    echo   [OK] natai -^> %BIN_DIR%\natai.bat

    REM --- 7. Ensure %USERPROFILE%\.local\bin is on the user PATH (idempotent) -
    REM Use PowerShell against the User scope (setx truncates PATH at 1024 chars
    REM and is unsafe). Append only when the dir is not already present.
    for /f "usebackq tokens=*" %%P in (`powershell -NoProfile -Command "try { $p = [Environment]::GetEnvironmentVariable('PATH','User'); if (-not $p) { [Environment]::SetEnvironmentVariable('PATH', '%BIN_DIR%', 'User'); 'added' } elseif ($p.Split(';') -contains '%BIN_DIR%') { 'present' } else { $new = if ($p.EndsWith(';')) { $p + '%BIN_DIR%' } else { $p + ';%BIN_DIR%' }; [Environment]::SetEnvironmentVariable('PATH', $new, 'User'); 'added' } } catch { 'error' }"`) do set "PATHRES=%%P"
    if /i "!PATHRES!"=="present" ( echo   [OK] %BIN_DIR% already on user PATH )
    if /i "!PATHRES!"=="added"  ( echo   [OK] added %BIN_DIR% to user PATH ^& echo        open a new terminal before first use )
    if /i "!PATHRES!"=="error"  ( echo   [!] could not update user PATH -- add %BIN_DIR% manually )
) else (
    echo ==^> Skipping `natai` command install ^(ADD_TO_PATH=0^)
)

echo.
echo Done. Next steps:
echo   natai                       ^(interactive menu, after opening a new terminal^)
echo   natai --target 10.0.0.50 --mode attack --goal backdoor
echo   ^(or, inside the venv^)  python main.py ...
echo.
echo Reminder: only run against networks you own or are explicitly authorized to test.

popd
endlocal