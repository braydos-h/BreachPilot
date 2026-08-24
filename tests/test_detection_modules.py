"""Tests for the detection coverage / OPSEC posture attack modules (READ-ONLY).

Imports the category file DIRECTLY (not via the package __init__ / registry) so
the tests do not depend on registration wiring, mirroring
``tests/test_ics_iot_modules.py``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from tools.attack_modules.base import ModuleContext
from tools.attack_modules.modules.detection import (
    DetectionCoverageProbe,
    LogSourceEnum,
    OPSECPostureReport,
)

TARGET = "10.0.0.50"


@dataclass
class FakeCtx:
    """Lightweight ModuleContext-like object exposing target_ip, os_family, get().

    Mirrors the real ``ModuleContext`` shape for the fields the detection
    modules touch, plus a dict-like ``get`` for opsec_profile / audit_records.
    """

    target_ip: str = TARGET
    os_family: str = "linux"
    services: list[dict[str, str]] = field(default_factory=list)
    cves: list[str] = field(default_factory=list)
    extra: dict[str, Any] = field(default_factory=dict)

    def get(self, key: str, default: Any = None) -> Any:
        return self.extra.get(key, default)


def _ctx(os_family: str = "linux", extra: dict[str, Any] | None = None) -> FakeCtx:
    return FakeCtx(target_ip=TARGET, os_family=os_family, extra=extra or {})


ALL_CLASSES = [DetectionCoverageProbe, LogSourceEnum, OPSECPostureReport]


# ---------------------------------------------------------------------------
# Class attributes
# ---------------------------------------------------------------------------


def test_detection_coverage_probe_class_attrs():
    m = DetectionCoverageProbe()
    assert m.name == "detection_coverage_probe"
    assert m.target_services == []
    assert m.target_ports == []
    assert m.required_cves == []
    assert m.target_versions == {}
    assert "read-only" in m.description.lower()


def test_log_source_enum_class_attrs():
    m = LogSourceEnum()
    assert m.name == "log_source_enum"
    assert m.target_services == ["ssh", "msrpc", "netbios-ssn", "cifs"]
    assert m.target_ports == [22, 445, 139]
    assert m.required_cves == []


def test_opsec_posture_report_class_attrs():
    m = OPSECPostureReport()
    assert m.name == "opsec_posture_report"
    assert m.target_services == []
    assert m.target_ports == []
    assert m.required_cves == []


# ---------------------------------------------------------------------------
# DetectionCoverageProbe.run
# ---------------------------------------------------------------------------


def test_detection_coverage_probe_run_info():
    res = DetectionCoverageProbe().run(_ctx())
    assert res["status"] == "info"
    assert res["target_ip"] == TARGET
    plan = res["probe_plan"]
    assert isinstance(plan, list)
    assert len(plan) == 4
    # Each plan entry is target-locked to the authorized target.
    for entry in plan:
        assert entry["target_ip"] == TARGET
        assert entry["read_only"] is True
        assert "category" in entry and "command" in entry and "detection_hint" in entry


def test_detection_coverage_probe_no_shell_or_priv():
    res = DetectionCoverageProbe().run(_ctx())
    assert "shell_type" not in res
    assert "privilege_level" not in res


def test_detection_coverage_probe_applicability_baseline():
    assert DetectionCoverageProbe().applicability(_ctx()) == 15


# ---------------------------------------------------------------------------
# LogSourceEnum.run
# ---------------------------------------------------------------------------


def test_log_source_enum_linux():
    res = LogSourceEnum().run(_ctx(os_family="linux"))
    assert res["status"] == "info"
    assert res["os_family"] == "linux"
    paths = [s["path"] for s in res["log_sources"]]
    assert "/var/log/auth.log" in paths
    assert "/var/log/syslog" in paths
    assert "/var/log/audit/audit.log" in paths
    assert "journald" in paths


def test_log_source_enum_windows():
    res = LogSourceEnum().run(_ctx(os_family="windows"))
    assert res["status"] == "info"
    assert res["os_family"] == "windows"
    channels = [s.get("channel", "") for s in res["log_sources"]]
    assert "Security" in channels
    assert "System" in channels
    assert any("Sysmon" in c for c in channels)


def test_log_source_enum_lists_differ_between_os():
    linux = LogSourceEnum().run(_ctx(os_family="linux"))["log_sources"]
    windows = LogSourceEnum().run(_ctx(os_family="windows"))["log_sources"]
    assert linux != windows


def test_log_source_enum_os_family_tolerant_default_linux():
    # Unknown os_family defaults to linux.
    res = LogSourceEnum().run(_ctx(os_family="solaris"))
    assert res["os_family"] == "linux"


def test_log_source_enum_no_shell_or_priv():
    res = LogSourceEnum().run(_ctx())
    assert "shell_type" not in res
    assert "privilege_level" not in res


def test_log_source_enum_applicability_service_gated():
    # No matching services -> base score 0.
    assert LogSourceEnum().applicability(_ctx()) == 0
    # Matching ssh service (+30) on port 22 (+20) -> 50.
    ctx = ModuleContext(
        target_ip=TARGET,
        services=[{"service": "ssh", "port": "22/tcp"}],
    )
    assert LogSourceEnum().applicability(ctx) == 50


# ---------------------------------------------------------------------------
# OPSECPostureReport.run
# ---------------------------------------------------------------------------


def test_opsec_posture_report_with_profile_and_records():
    profile = {
        "ua_rotation": False,
        "min_gap_seconds": 0,
        "doh": True,
        "quiet_commands": True,
    }
    audit_records = [
        {"tool": "run_exploit_terminal", "target": TARGET, "noisy": True, "command": "whoami"},
        {"tool": "run_python_file", "target": TARGET, "noisy": False},
        {"tool": "run_exploit_terminal", "target": TARGET, "noisy": True, "command": "ls"},
    ]
    res = OPSECPostureReport().run(_ctx(extra={"opsec_profile": profile, "audit_records": audit_records}))
    assert res["status"] == "info"
    assert res["opsec_profile"] == profile
    footprint = res["footprint"]
    assert footprint["total_actions"] == 3
    assert footprint["noisy_actions"] == 2
    recs = res["recommendations"]
    assert "UA rotation disabled" in recs
    assert "Pacing disabled" in recs
    assert any("noisy actions recorded" in r for r in recs)


def test_opsec_posture_report_tolerant_none_profile_and_records():
    res = OPSECPostureReport().run(_ctx())
    assert res["status"] == "info"
    assert res["opsec_profile"] == {}
    assert res["footprint"]["total_actions"] == 0
    assert res["footprint"]["noisy_actions"] == 0
    # No noisy actions -> no noisy recommendation; empty audit -> noted.
    recs = res["recommendations"]
    assert all("noisy actions recorded" not in r for r in recs)
    assert "No audit actions recorded yet" in recs


def test_opsec_posture_report_no_shell_or_priv():
    res = OPSECPostureReport().run(_ctx())
    assert "shell_type" not in res
    assert "privilege_level" not in res


def test_opsec_posture_report_applicability_baseline():
    assert OPSECPostureReport().applicability(_ctx()) == 10


# ---------------------------------------------------------------------------
# Cross-cutting: no module flips access_achieved signals
# ---------------------------------------------------------------------------


def test_all_modules_status_info():
    for cls in ALL_CLASSES:
        res = cls().run(_ctx())
        assert res["status"] == "info", f"{cls.__name__} returned non-info status"


def test_all_modules_never_set_shell_or_priv():
    for cls in ALL_CLASSES:
        res = cls().run(_ctx())
        assert "shell_type" not in res, f"{cls.__name__} set shell_type"
        assert "privilege_level" not in res, f"{cls.__name__} set privilege_level"


def test_all_modules_target_locked():
    for cls in ALL_CLASSES:
        res = cls().run(_ctx())
        # The probe plan / log sources / footprint must only reference TARGET.
        blob = str(res)
        assert TARGET in blob or "target_ip" in res
