<#
.SYNOPSIS
Verify the checksum and GitHub build attestation for a BreachPilot release installer.

.EXAMPLE
./scripts/verify-installer.ps1 ./install-v0.68.4.ps1

.EXAMPLE
./scripts/verify-installer.ps1 -ChecksumOnly ./install-v0.68.4.ps1
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string] $InstallerPath,

    [Parameter(Position = 1)]
    [string] $ChecksumPath,

    [switch] $ChecksumOnly
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $InstallerPath -PathType Leaf)) {
    throw "Missing installer: $InstallerPath"
}
$InstallerPath = (Resolve-Path -LiteralPath $InstallerPath).Path
if (-not $ChecksumPath) {
    $ChecksumPath = "$InstallerPath.sha256"
}
if (-not (Test-Path -LiteralPath $ChecksumPath -PathType Leaf)) {
    throw "Missing checksum file: $ChecksumPath"
}

$checksumText = Get-Content -LiteralPath $ChecksumPath -Raw
if ($checksumText -notmatch '(?m)^\s*([0-9a-fA-F]{64})\s+\*?([^\r\n]+?)\s*$') {
    throw "Invalid SHA-256 checksum file: $ChecksumPath"
}
$expectedHash = $Matches[1]
$expectedName = [System.IO.Path]::GetFileName($Matches[2].Trim())
$actualName = [System.IO.Path]::GetFileName($InstallerPath)
if ($expectedName -ne $actualName) {
    throw "Checksum names '$expectedName', but the installer is '$actualName'."
}
$actualHash = (Get-FileHash -LiteralPath $InstallerPath -Algorithm SHA256).Hash
if ($actualHash -ne $expectedHash) {
    throw "Checksum mismatch for $InstallerPath"
}
Write-Output "checksum OK: $InstallerPath"

if ($ChecksumOnly) {
    Write-Warning 'Checksum-only mode; publisher attestation was not verified.'
    exit 0
}

if (-not (Get-Command gh -ErrorAction SilentlyContinue)) {
    throw 'GitHub CLI with attestation support is required; use -ChecksumOnly only when checksum-only verification is acceptable.'
}
& gh attestation verify $InstallerPath --repo braydos-h/BreachPilot
if ($LASTEXITCODE -ne 0) {
    throw "Attestation verification failed for $InstallerPath"
}
Write-Output "checksum and publisher attestation verified: $InstallerPath -- inspect the file before running"
