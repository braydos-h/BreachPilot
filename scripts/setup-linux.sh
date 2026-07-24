#!/usr/bin/env bash
# Linux/macOS bootstrap for the NetAttackAI engine.
#
# Idempotent: safe to re-run. Creates the venv, installs Python deps, checks
# for the external tools the engine uses (nmap, ollama, optional Kali
# tooling), prints install hints for anything missing, and finally runs
# `python main.py --doctor`.
#
# This does NOT install or run anything against a target. It only prepares the
# operator's host. Run it from the repository root.
set -euo pipefail

PYTHON="${PYTHON:-python3}"
VENV="${VENV:-.venv}"

if ! command -v "$PYTHON" >/dev/null 2>&1; then
    echo "  [!] '$PYTHON' not found. Install Python 3.10+ (apt install python3 / brew install python) or set PYTHON=..."
    exit 1
fi

echo "==> Creating venv ($VENV) with $($PYTHON --version)"
"$PYTHON" -m venv "$VENV"

# Active venv for the rest of the script.
# shellcheck disable=SC1091
source "$VENV/bin/activate"

echo "==> Upgrading pip + installing requirements"
python -m pip install --upgrade pip
python -m pip install -r requirements.txt

echo "==> Checking external tools"
check() {
    local name="$1"; local hint="$2"
    if command -v "$name" >/dev/null 2>&1; then
        echo "  [OK] $name ($(command -v "$name"))"
    else
        echo "  [--] $name missing  -> $hint"
    fi
}

check nmap      "sudo apt install -y nmap  (or: brew install nmap)"
check ollama    "curl -fsSL https://ollama.com/install.sh | sh  (or: brew install ollama)"
check tmux      "sudo apt install -y tmux  (or: brew install tmux)"
check searchsploit "sudo apt install -y exploitdb   (Kali-only; optional unless using the exploit engine)"
check msfconsole "sudo apt install -y metasploit-framework  (optional; Kali-only)"
check hydra     "sudo apt install -y hydra  (optional)"
check impacket-secretsdump "pip install impacket  (or: apt install impacket-scripts)"

echo "==> Pulling default model (best-effort)"
ollama pull glm-5.2:cloud 2>/dev/null || echo "  [--] ollama pull skipped (is the ollama daemon running?)"

echo "==> Running --doctor"
python main.py --doctor || echo "  [!] --doctor reported failures above; fix them before running the engine."

echo
echo "Done. Activate the venv with:  source $VENV/bin/activate"
echo "Then run:                      python main.py           (interactive menu)"
echo "                               python main.py --doctor  (re-check)"
echo "                               python -m tui            (dashboard)"