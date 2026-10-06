#!/usr/bin/env bash
# Verify a pinned BreachPilot release installer before executing (TODO 013).
#
#   scripts/verify-installer.sh install-v0.68.4.sh install-v0.68.4.sh.sha256
#   scripts/verify-installer.sh --checksum-only install-v0.68.4.sh
#
# Checks SHA-256 and requires GitHub build attestation verification by default.
# Checksum-only mode is explicit and never describes the installer as verified.
set -Eeuo pipefail

CHECKSUM_ONLY=0
if [[ "${1:-}" == "--checksum-only" ]]; then
  CHECKSUM_ONLY=1
  shift
fi

if [[ $# -lt 1 || $# -gt 2 ]]; then
  echo "usage: $0 [--checksum-only] <installer.sh> [<installer.sh.sha256>]" >&2
  exit 2
fi
INSTALLER="$1"
SUMFILE="${2:-$1.sha256}"

if [[ ! -f "$INSTALLER" ]]; then
  echo "missing installer: $INSTALLER" >&2
  exit 1
fi
if [[ -f "$SUMFILE" ]]; then
  (cd "$(dirname "$SUMFILE")" && sha256sum -c "$(basename "$SUMFILE")") || {
    echo "checksum mismatch for $INSTALLER" >&2
    exit 1
  }
  echo "checksum OK: $INSTALLER"
else
  echo "no checksum file $SUMFILE -- refusing to run without verification" >&2
  exit 1
fi

if [[ "$CHECKSUM_ONLY" -eq 1 ]]; then
  echo "WARNING: checksum-only mode; publisher attestation was not verified." >&2
  exit 0
fi

if ! command -v gh >/dev/null 2>&1; then
  echo "GitHub CLI with attestation support is required; use --checksum-only only when checksum-only verification is acceptable." >&2
  exit 1
fi
gh attestation verify "$INSTALLER" --repo braydos-h/BreachPilot || {
  echo "attestation verification failed for $INSTALLER -- refusing to mark it verified" >&2
  exit 1
}
echo "checksum and publisher attestation verified: $INSTALLER -- inspect with 'less $INSTALLER' before running"
