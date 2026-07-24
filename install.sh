#!/usr/bin/env bash
# One-shot host bootstrap for the NetAttackAI engine.
#
# Actually installs everything (unlike scripts/setup-linux.sh, which only
# checks and prints hints): OS-level prereqs (nmap, tmux, optional Kali
# tooling), Ollama, the Python venv + requirements, then pulls the default
# model + embedding model and runs `python main.py --doctor`.
#
# Idempotent: safe to re-run. Run from the repository root:
#     ./install.sh
#
# Env knobs: PYTHON=python3  VENV=.venv  INSTALL_KALI_TOOLS=1  SKIP_MODEL_PULL=1
set -euo pipefail

PYTHON="${PYTHON:-python3}"
VENV="${VENV:-.venv}"
INSTALL_KALI_TOOLS="${INSTALL_KALI_TOOLS:-1}"
SKIP_MODEL_PULL="${SKIP_MODEL_PULL:-0}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_ROOT"

# --- detect OS ---------------------------------------------------------------
OS_KIND="unknown"
if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    case "${ID:-}" in
        debian|ubuntu|kali|linuxmint|pop) OS_KIND="debian" ;;
    esac
    case "${ID_LIKE:-}" in
        *debian*|*ubuntu*) OS_KIND="debian" ;;
    esac
elif [[ "$(uname -s)" == "Darwin" ]]; then
    OS_KIND="macos"
fi

have() { command -v "$1" >/dev/null 2>&1; }

# --- 1. OS-level prerequisites ----------------------------------------------
echo "==> Installing OS-level prerequisites ($OS_KIND)"
case "$OS_KIND" in
    debian)
        sudo apt-get update
        sudo apt-get install -y nmap python3-venv tmux curl
        if [[ "$INSTALL_KALI_TOOLS" == "1" ]]; then
            # Only present on Kali; missing packages are tolerated so this stays
            # safe on plain Ubuntu/Debian.
            sudo apt-get install -y metasploit-framework exploitdb hydra \
                crackmapexec impacket-scripts 2>/dev/null \
                || echo "  [--] some Kali-only packages unavailable on this distro (fine if staying in read_only)"
        fi
        ;;
    macos)
        have brew || {
            echo "  [!] Homebrew not found. Install it first:  https://brew.sh"
            exit 1
        }
        brew install nmap python tmux curl
        ;;
    *)
        echo "  [!] Unsupported or unknown OS. Install manually: nmap, python3-venv, tmux, ollama."
        echo "      Then re-run this script."
        exit 1
        ;;
esac

# --- 2. Ollama -------------------------------------------------------------
echo "==> Ensuring Ollama is installed and running"
if ! have ollama; then
    case "$OS_KIND" in
        debian) curl -fsSL https://ollama.com/install.sh | sh ;;
        macos)  brew install ollama ;;
    esac
fi
# Start the daemon if it isn't up (best-effort; non-fatal if already running).
if have ollama; then
    if ! curl -sf http://localhost:11434/api/version >/dev/null 2>&1; then
        echo "  -> starting ollama serve in the background"
        (nohup ollama serve >/tmp/ollama-serve.log 2>&1 &) || true
        # wait for it to come up
        for _ in $(seq 1 20); do
            curl -sf http://localhost:11434/api/version >/dev/null 2>&1 && break
            sleep 1
        done
    fi
    echo "  [OK] ollama ($(command -v ollama))"
else
    echo "  [!] ollama still not on PATH — AI-backed flows will fail until you install it."
fi

# --- 3. Python venv + requirements -----------------------------------------
if ! have "$PYTHON"; then
    echo "  [!] '$PYTHON' not found. Install Python 3.10+ and re-run (or set PYTHON=...)."
    exit 1
fi
echo "==> Creating venv ($VENV) with $($PYTHON --version)"
"$PYTHON" -m venv "$VENV"
# shellcheck disable=SC1091
source "$VENV/bin/activate"

echo "==> Upgrading pip + installing requirements"
python -m pip install --upgrade pip
python -m pip install -r requirements.txt

# --- 4. Pull models --------------------------------------------------------
if [[ "$SKIP_MODEL_PULL" != "1" ]] && have ollama; then
    echo "==> Pulling default model + embedding model (best-effort)"
    ollama pull glm-5.2:cloud        || echo "  [--] glm-5.2:cloud pull failed (daemon running? reachable?)"
    ollama pull nomic-embed-text     || echo "  [--] nomic-embed-text pull failed (needed for semantic memory)"
else
    echo "==> Skipping model pull (SKIP_MODEL_PULL=1 or ollama absent)"
fi

# --- 5. Doctor ------------------------------------------------------------
echo "==> Running --doctor"
python main.py --doctor || echo "  [!] --doctor reported failures above; fix them before running the engine."

echo
echo "Done. Next steps:"
echo "  source $VENV/bin/activate"
echo "  python main.py            # interactive menu"
echo "  python main.py --doctor   # re-check environment"
echo "  python -m tui             # dashboard"
echo
echo "Reminder: only run against networks you own or are explicitly authorized to test."