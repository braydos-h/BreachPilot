"""Create an explicit sandbox config for the repository's loopback-only CI lab.

This helper is for the shipped local Docker evaluation targets. It copies a
validated operator config and enables only the documented host-loopback mapping;
it refuses to produce a config with sandboxing, egress enforcement, or
fail-closed policy disabled.
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

import yaml


def prepare_ci_lab_config(source: Path, output: Path) -> Path:
    """Copy ``source`` to ``output`` with contained loopback-lab mapping on."""
    payload: Any = yaml.safe_load(source.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("source config must contain a YAML mapping")

    sandbox = payload.get("sandbox")
    if not isinstance(sandbox, dict) or sandbox.get("enabled") is not True:
        raise ValueError("sandbox.enabled must remain true for CI lab runs")
    network = sandbox.get("network")
    if not isinstance(network, dict):
        raise ValueError("sandbox.network must be a mapping")
    if network.get("enforce") is not True or network.get("fail_closed") is not True:
        raise ValueError("sandbox network enforcement and fail-closed behavior must remain enabled")

    network["map_host_loopback"] = True
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
    return output


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=Path("config.yaml"))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    prepare_ci_lab_config(args.source, args.output)
    print(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
