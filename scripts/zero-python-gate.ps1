# Zero-Python gate (Windows): report mode exits 0; -Strict fails if Python remains.
# Usage: powershell -File scripts\zero-python-gate.ps1 [-Strict]
param([switch]$Strict)
$root = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
if (-not (Test-Path "$root\.git")) { $root = (Get-Location).Path }
Push-Location $root
try {
  $py = (git ls-files '*.py' | Measure-Object).Count
  Write-Output "tracked .py files: $py"
  $fail = $false
  if ($py -ne 0) { Write-Output "pending: first-party .py files remain (see docs/native-migration/INVENTORY.md)"; $fail = $true }
  foreach ($f in @('pyproject.toml','requirements.txt','constraints-dev.txt','conftest.py','MANIFEST.in')) {
    if (Test-Path $f) { Write-Output "pending: $f still present"; $fail = $true }
  }
  $hits = Select-String -Path Dockerfile.native,Makefile,install.sh,install.ps1,install.bat,START.bat,.github/workflows/*,go.mod `
    -Pattern '\bpython3?\b|\bpip\b|pytest|uvicorn|requirements\.txt' -ErrorAction SilentlyContinue | Select-Object -First 30
  if ($hits) { $hits | ForEach-Object { Write-Output $_.Line }; Write-Output "pending: Python references above"; $fail = $true }
  else { Write-Output "no Python references in runtime/install/CI paths" }
  $native = Get-ChildItem internal,rust/crates,cmd -Recurse -Include *.go,*.rs -ErrorAction SilentlyContinue |
    Select-String -Pattern '"python3?"' | Select-Object -First 20
  if ($native) { $native | ForEach-Object { Write-Output $_.Line }; Write-Output "pending: native code invokes Python"; $fail = $true }
  else { Write-Output "native code does not invoke Python" }
  if ($Strict -and $fail) { Write-Output "ZERO-PYTHON GATE: FAIL"; exit 1 }
  Write-Output "ZERO-PYTHON GATE: report done (pending items above)"
} finally { Pop-Location }
