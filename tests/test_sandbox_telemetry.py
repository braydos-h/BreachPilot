from __future__ import annotations

import json
from pathlib import Path

from tools.sandbox.telemetry import (
    NETWORK_SCOPE_METRIC,
    read_network_scope_measurement,
    write_network_scope_measurement,
)


def test_network_scope_measurement_requires_complete_explicit_count(tmp_path: Path) -> None:
    path = tmp_path / "scope.json"
    assert read_network_scope_measurement(path) is None

    assert write_network_scope_measurement(path, 0)
    assert read_network_scope_measurement(path) == 0
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload == {
        "schema_version": 1,
        "metric": NETWORK_SCOPE_METRIC,
        "complete": True,
        NETWORK_SCOPE_METRIC: 0,
    }


def test_incomplete_or_invalid_measurement_is_never_zero(tmp_path: Path) -> None:
    path = tmp_path / "scope.json"
    assert write_network_scope_measurement(path, None)
    assert read_network_scope_measurement(path) is None
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["complete"] is False
    assert payload[NETWORK_SCOPE_METRIC] is None

    for invalid in (-1, True):
        assert write_network_scope_measurement(path, invalid)
        assert read_network_scope_measurement(path) is None


def test_network_scope_measurement_rejects_incomplete_or_malformed_json(tmp_path: Path) -> None:
    path = tmp_path / "scope.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "metric": NETWORK_SCOPE_METRIC,
                "complete": False,
                NETWORK_SCOPE_METRIC: 0,
            }
        ),
        encoding="utf-8",
    )
    assert read_network_scope_measurement(path) is None

    path.write_text("{", encoding="utf-8")
    assert read_network_scope_measurement(path) is None
