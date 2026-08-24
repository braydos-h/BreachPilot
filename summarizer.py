"""Output summarizer — prevents raw tool output from flooding LLM context.

Takes verbose tool output (nmap, MSF, curl, search results) and produces
compact, structured summaries that preserve signal while removing noise.

Used by the Observer and when messages need context compaction.
"""

from __future__ import annotations

import re
from typing import Any


def summarize_tool_output(
    raw_output: str,
    tool_name: str = "",
    max_tokens_estimate: int = 4000,
) -> str:
    """Produce a compact summary of tool output suitable for LLM context.

    Args:
        raw_output: Full raw output from the tool
        tool_name: Tool that produced this output (for type-specific parsing)
        max_tokens_estimate: Approximate max output length in characters (1 token ≈ 4 chars)

    Returns:
        Compact summary string
    """
    # Type-specific summarizers
    if "nmap" in tool_name.lower() or "scan" in tool_name.lower():
        return _summarize_nmap(raw_output, max_tokens_estimate)
    if "search" in tool_name.lower() or "exploit_db" in tool_name.lower() or "search_cve" in tool_name.lower():
        return _summarize_search(raw_output, max_tokens_estimate)
    if "http" in tool_name.lower() or "curl" in tool_name.lower() or "web" in tool_name.lower():
        return _summarize_http(raw_output, max_tokens_estimate)
    if "msf" in tool_name.lower():
        return _summarize_msf(raw_output, max_tokens_estimate)
    if "python" in tool_name.lower():
        return _summarize_python(raw_output, max_tokens_estimate)
    if "terminal" in tool_name.lower() or "run_" in tool_name.lower():
        return _summarize_terminal(raw_output, max_tokens_estimate)

    return _summarize_generic(raw_output, max_tokens_estimate)


def _summarize_nmap(output: str, max_chars: int) -> str:
    lines: list[str] = []
    # Extract version info
    ver = re.search(r"Nmap\s+(\S+)\s+", output)
    if ver:
        lines.append(f"Nmap {ver.group(1)}")

    # Extract open ports summary
    open_ports: list[str] = []
    port_pattern = re.compile(r"(\d+)/(tcp|udp)\s+(open)\s+(\S.+?)(?=\n|$)")
    for m in port_pattern.finditer(output):
        open_ports.append(f"{m.group(1)}/{m.group(2)} {m.group(4).strip()[:60]}")
    if open_ports:
        lines.append(f"Open ports: {len(open_ports)}")
        lines.extend(f"  - {p}" for p in open_ports[:50])

    # Host count
    host_match = re.search(r"(\d+)\s+hosts?\s+up", output, re.IGNORECASE)
    if host_match:
        lines.insert(0, f"Hosts up: {host_match.group(1)}")

    # OS detection
    os_match = re.search(r"OS details:\s*(.+)", output)
    if os_match:
        lines.append(f"OS: {os_match.group(1).strip()[:100]}")

    return _cap("\n".join(lines), max_chars)


def _summarize_search(output: str, max_chars: int) -> str:
    # Strip raw JSON/HTML tags
    clean = re.sub(r"<[^>]+>", "", output)
    entries = [l.strip() for l in clean.split("\n") if l.strip() and not l.startswith(("http", "www"))]
    result = "\n".join(entries[:30])
    return _cap(result, max_chars)


def _summarize_http(output: str, max_chars: int) -> str:
    lines: list[str] = []
    # Status line
    status = re.search(r"(HTTP/\d\.\d\s+)?(\d{3})", output)
    if status:
        lines.append(f"Status: {status.group(2)}")

    # Key headers
    for header_name in ("Server", "Content-Type", "Location", "Set-Cookie"):
        h = re.search(rf"{header_name}:\s*(.+)", output, re.IGNORECASE)
        if h:
            lines.append(f"{header_name}: {h.group(1).strip()[:100]}")

    # Body size
    body_marker = output.find("\n\n")
    if body_marker > 0:
        body_size = len(output) - body_marker
        lines.append(f"Body: ~{body_size} bytes")

    return _cap("\n".join(lines), max_chars)


def _summarize_msf(output: str, max_chars: int) -> str:
    # Extract key lines: module info, target, result
    lines: list[str] = []
    for line in output.split("\n"):
        stripped = line.strip()
        if any(kw in stripped.lower() for kw in ("[*]", "[+]", "[-]", "vulnerable", "exploit", "session", "meterpreter")):
            lines.append(stripped[:200])
    if not lines:
        lines.append(output.strip()[:max_chars])
    return _cap("\n".join(lines[:20]), max_chars)


def _summarize_python(output: str, max_chars: int) -> str:
    # Python output: extract first few lines and any JSON
    lines = output.strip().split("\n")
    important: list[str] = []
    for line in lines[:30]:
        clean = line.strip()
        if clean and not clean.startswith("#"):
            important.append(clean[:200])
    return _cap("\n".join(important), max_chars)


def _summarize_terminal(output: str, max_chars: int) -> str:
    """Summarize raw terminal output — extract exit_code, strip ANSI, trim."""
    # Strip ANSI
    clean = re.sub(r"\x1b\[[0-9;]*[a-zA-Z]", "", output)
    # Extract exit code
    exit_m = re.search(r"EXIT_CODE[:\s]*(\d+)", clean)
    exit_code = exit_m.group(1) if exit_m else "?"

    # Extract command
    cmd_m = re.search(r"COMMAND:\s*(.+)", clean)
    command = cmd_m.group(1).strip()[:100] if cmd_m else "unknown"

    # Get tail of output (last 5 meaningful lines)
    tail_lines = [l.strip() for l in clean.split("\n") if l.strip() and "===" not in l][-5:]

    parts = [
        f"Command: {command}",
        f"Exit: {exit_code}",
        "Output tail:",
    ]
    parts.extend(f"  {l[:150]}" for l in tail_lines)
    return _cap("\n".join(parts), max_chars)


def _summarize_generic(output: str, max_chars: int) -> str:
    """Generic fallback summarizer."""
    clean = re.sub(r"\x1b\[[0-9;]*[a-zA-Z]", "", output)
    lines = [l.strip() for l in clean.split("\n") if l.strip()][:40]
    result = "\n".join(lines)
    return _cap(result, max_chars)


def _cap(text: str, max_chars: int) -> str:
    if len(text) <= max_chars:
        return text
    return text[:max_chars] + "\n... [truncated, full output saved as evidence]"


def summarize_observation(obs_dict: dict[str, Any]) -> str:
    """Create a one-liner summary of an Observation for task updates."""
    facts = obs_dict.get("facts", [])
    signals = obs_dict.get("interesting_signals", [])
    findings = obs_dict.get("possible_findings", [])
    dead = obs_dict.get("dead_ends", [])
    parts: list[str] = []
    if facts:
        parts.append(f"{len(facts)} fact(s)")
    if signals:
        parts.append(f"{len(signals)} signal(s)")
    if findings:
        parts.append(f"{len(findings)} possible finding(s)")
    if dead:
        parts.append(f"{len(dead)} dead end(s)")
    return "; ".join(parts) if parts else "no notable output"
