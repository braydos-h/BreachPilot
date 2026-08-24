"""Tests for ICS/SCADA/IoT enumeration attack modules (READ-ONLY / non-disruptive).

Imports the category file DIRECTLY (not via the package __init__ / registry) so
the tests do not depend on Round 2 registration wiring.
"""

from __future__ import annotations

from tools.attack_modules.base import ModuleContext
from tools.attack_modules.modules.ics_iot import (
    BACnetEnum,
    DNP3Enum,
    HMIDefaultCred,
    IoTDefaultCred,
    ModbusEnum,
    S7Enum,
)

TARGET = "10.0.0.50"


def _ctx(services=None, cves=None):
    return ModuleContext(
        target_ip=TARGET,
        target_os=None,
        services=services or [],
        cves=cves or [],
    )


ALL_CLASSES = [ModbusEnum, DNP3Enum, S7Enum, BACnetEnum, HMIDefaultCred, IoTDefaultCred]


# ---------------------------------------------------------------------------
# Class attributes
# ---------------------------------------------------------------------------


def test_modbus_class_attrs():
    m = ModbusEnum()
    assert m.name == "ModbusEnum"
    assert "modbus" in m.target_services
    assert 502 in m.target_ports
    assert m.required_cves == []


def test_dnp3_class_attrs():
    m = DNP3Enum()
    assert m.name == "DNP3Enum"
    assert "dnp3" in m.target_services
    assert 20000 in m.target_ports
    assert m.required_cves == []


def test_s7_class_attrs():
    m = S7Enum()
    assert m.name == "S7Enum"
    assert "s7" in m.target_services or "s7comm" in m.target_services
    assert 102 in m.target_ports
    assert m.required_cves == []


def test_bacnet_class_attrs():
    m = BACnetEnum()
    assert m.name == "BACnetEnum"
    assert "bacnet" in m.target_services
    assert 47808 in m.target_ports
    assert m.required_cves == []


def test_hmi_class_attrs():
    m = HMIDefaultCred()
    assert m.name == "HMIDefaultCred"
    assert "http" in m.target_services and "https" in m.target_services
    assert 80 in m.target_ports and 443 in m.target_ports
    assert m.required_cves == []


def test_iot_class_attrs():
    m = IoTDefaultCred()
    assert m.name == "IoTDefaultCred"
    assert "http" in m.target_services
    assert 23 in m.target_ports and 7547 in m.target_ports
    assert m.required_cves == []


# ---------------------------------------------------------------------------
# run() contract
# ---------------------------------------------------------------------------


def test_run_returns_script_generated_and_contains_target():
    ctx = _ctx()
    for cls in ALL_CLASSES:
        m = cls()
        out = m.run(ctx)
        assert out["status"] == "script_generated", cls.name
        assert out["module"] == m.name, cls.name
        assert isinstance(out["script"], str) and out["script"], cls.name
        assert TARGET in out["script"], f"{cls.name} script must reference target_ip"


# ---------------------------------------------------------------------------
# generate_python_script() content
# ---------------------------------------------------------------------------


def test_scripts_have_readonly_marker():
    ctx = _ctx()
    for cls in ALL_CLASSES:
        script = cls().generate_python_script(ctx)
        assert script, cls.name
        assert TARGET in script, cls.name
        assert "READ-ONLY" in script.upper(), f"{cls.name} must declare READ-ONLY non-disruptive"


def test_modbus_script_read_only_no_writes():
    script = ModbusEnum().generate_python_script(_ctx())
    assert "502" in script
    # read-side markers present
    assert "read" in script.lower()
    assert "0x04" in script.lower() or "Read Input Registers".lower() in script.lower() or "function" in script.lower()
    # write-side forbidden phrasing absent
    assert "write coil" not in script.lower()
    assert "write register" not in script.lower()


def test_dnp3_script_has_port():
    assert "20000" in DNP3Enum().generate_python_script(_ctx())


def test_s7_script_has_port():
    assert "102" in S7Enum().generate_python_script(_ctx())


def test_bacnet_script_has_port():
    assert "47808" in BACnetEnum().generate_python_script(_ctx())


def test_hmi_script_has_default_cred_and_login_path():
    script = HMIDefaultCred().generate_python_script(_ctx())
    assert "admin" in script.lower()
    assert "/login" in script or "/WinCC" in script or "/ignition" in script


def test_iot_script_has_default_cred_and_login_path():
    script = IoTDefaultCred().generate_python_script(_ctx())
    assert "admin" in script.lower()
    assert "/onvif/" in script or "/HNAP1" in script or "/login" in script or "/cgi-bin/" in script


# ---------------------------------------------------------------------------
# Applicability scoring
# ---------------------------------------------------------------------------


def test_modbus_applicability_matches_and_misses():
    m = ModbusEnum()
    match = _ctx(services=[{"service": "modbus", "port": "502/tcp", "version": ""}])
    assert m.applicability(match) > 0
    miss = _ctx(services=[{"service": "ssh", "port": "22/tcp", "version": ""}])
    assert m.applicability(miss) == 0


def test_dnp3_applicability_matches_and_misses():
    m = DNP3Enum()
    match = _ctx(services=[{"service": "dnp3", "port": "20000/tcp", "version": ""}])
    assert m.applicability(match) > 0
    miss = _ctx(services=[{"service": "ssh", "port": "22/tcp", "version": ""}])
    assert m.applicability(miss) == 0


def test_s7_applicability_matches_and_misses():
    m = S7Enum()
    match = _ctx(services=[{"service": "iso-tsap", "port": "102/tcp", "version": ""}])
    assert m.applicability(match) > 0
    miss = _ctx(services=[{"service": "ssh", "port": "22/tcp", "version": ""}])
    assert m.applicability(miss) == 0


def test_bacnet_applicability_matches_and_misses():
    m = BACnetEnum()
    match = _ctx(services=[{"service": "bacnet", "port": "47808/udp", "version": ""}])
    assert m.applicability(match) > 0
    miss = _ctx(services=[{"service": "ssh", "port": "22/tcp", "version": ""}])
    assert m.applicability(miss) == 0


def test_hmi_applicability_matches_and_misses():
    m = HMIDefaultCred()
    match = _ctx(services=[{"service": "http", "port": "80/tcp", "version": ""}])
    assert m.applicability(match) > 0
    miss = _ctx(services=[{"service": "ssh", "port": "22/tcp", "version": ""}])
    assert m.applicability(miss) == 0


def test_iot_applicability_matches_and_misses():
    m = IoTDefaultCred()
    match = _ctx(services=[{"service": "http", "port": "80/tcp", "version": ""}])
    assert m.applicability(match) > 0
    miss = _ctx(services=[{"service": "ssh", "port": "22/tcp", "version": ""}])
    assert m.applicability(miss) == 0
