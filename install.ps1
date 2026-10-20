# BreachPilot native Windows installer (Go control plane + Rust sidecar + WebUI).
[CmdletBinding()]
param(
    [switch]$Yes,
    [switch]$Check,
    [switch]$Update,
    [switch]$Repair,
    [switch]$Uninstall,
    [switch]$Help
)

$ErrorActionPreference = 'Stop'
$RepoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Push-Location $RepoRoot

function Write-Log {
    param([string]$Message)
    Write-Host $Message
}

try {
    if ($Help) {
        Write-Log "Usage: .\install.ps1 [-Yes] [-Check] [-Update] [-Repair] [-Uninstall] [-Help]"
        Write-Log "Builds native BreachPilot Go + Rust binaries and WebUI assets without external script runtimes."
        exit 0
    }

    if ($Uninstall) {
        foreach ($bin in @('bp.exe','bp-mcp-defensive.exe','bp-mcp-assess.exe','bp-mcp-engine.exe','bp-codegen.exe')) {
            if (Test-Path $bin) { Remove-Item $bin -Force }
        }
        Write-Log "[OK] Removed built BreachPilot native binaries."
        exit 0
    }

    $missing = $false
    foreach ($cmd in @('go','cargo','npm')) {
        if (Get-Command $cmd -ErrorAction SilentlyContinue) {
            Write-Log "[OK] Found $cmd"
        } else {
            Write-Log "[FAIL] Missing required toolchain: $cmd"
            $missing = $true
        }
    }

    if ($Check) {
        if ($missing) { exit 1 }
        exit 0
    }

    if ($missing) {
        Write-Log "[FAIL] Install Go 1.24+, Rust (cargo), and Node.js 22+ (npm), then re-run install.ps1."
        exit 1
    }

    Write-Log "==> Building Rust execution sidecar (bp-sidecar.exe)"
    cargo build --manifest-path rust/Cargo.toml --workspace --release
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    Write-Log "==> Building Go control plane and MCP servers"
    go build -trimpath -o bp.exe ./cmd/bp
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    go build -trimpath -o bp-mcp-defensive.exe ./cmd/bp-mcp-defensive
    go build -trimpath -o bp-mcp-assess.exe ./cmd/bp-mcp-assess
    go build -trimpath -o bp-mcp-engine.exe ./cmd/bp-mcp-engine
    go build -trimpath -o bp-codegen.exe ./cmd/bp-codegen

    if (Test-Path "webui\package.json") {
        Write-Log "==> Building React/TypeScript WebUI"
        Push-Location webui
        try {
            npm ci --no-audit --no-fund
            npm run build
        } finally {
            Pop-Location
        }
    }

    Write-Log "==> Running .\bp.exe --doctor"
    .\bp.exe --doctor
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    Write-Log "[OK] BreachPilot native Windows build complete."
} finally {
    Pop-Location
}
