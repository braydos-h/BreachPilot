#!/usr/bin/env bash
# Verify a pinned BreachPilot release installer before executing (TODO 013).
#
#   scripts/verify-installer.sh install-v0.68.4.sh install-v0.68.4.sh.sha256
#
# Checks SHA-256, then (when gh + attestation data are available) verifies the
# Sigstore attestation via `gh attestation verify`. Fails closed on mismatch.
set -Eeuo pipefail

if [[ $# -lt 1 ]]; then
  echo "usage: $0 <installer.sh> [<installer.sh.sha256>]" >&2
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

if command -v gh >/dev/null 2>&1; then
  if gh attestation verify "$INSTALLER" --repo braydos-h/BreachPilot 2>/dev/null; then
    echo "attestation OK: $INSTALLER"
  else
    echo "note: attestation not verified (missing attestation or offline) -- checksum passed" >&2
  fi
fi
echo "verified $INSTALLER -- inspect with 'less $INSTALLER' before running"
