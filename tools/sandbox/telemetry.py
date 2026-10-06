"""Host-side serialization for trusted sandbox network measurements.

The worker only receives its run workspace mount. Scope telemetry is written
to a caller-provided host path outside that mount after sandbox teardown, so an
agent command cannot forge a clean-zero measurement.
"""

from __future__ import annotations

import json
import os
import secrets
from pathlib import Path
from typing import Any

NETWORK_SCOPE_METRIC = "blocked_off_scope_egress_packets"
_SCHEMA_VERSION = 1


def read_network_scope_measurement(path: Path | None) -> int | None:
    """Read a complete measurement; absence, malformed data, or failure is unknown."""
    if path is None:
        return None
    try:
        payload: Any = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return None
    if not isinstance(payload, dict):
        return None
    count = payload.get(NETWORK_SCOPE_METRIC)
    if (
        payload.get("schema_version") != _SCHEMA_VERSION
        or payload.get("metric") != NETWORK_SCOPE_METRIC
        or payload.get("complete") is not True
        or type(count) is not int
        or count < 0
    ):
        return None
    return count


def write_network_scope_measurement(path: Path | None, count: int | None) -> bool:
    """Atomically write a host-side measurement, retaining unknown as null."""
    if path is None:
        return False
    valid_count = count if type(count) is int and count >= 0 else None
    payload = {
        "schema_version": _SCHEMA_VERSION,
        "metric": NETWORK_SCOPE_METRIC,
        "complete": valid_count is not None,
        NETWORK_SCOPE_METRIC: valid_count,
    }
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}-{secrets.token_hex(4)}")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        return True
    except OSError:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
        return False
