"""Durable current-attack memory.

This store is intentionally tactical and session-scoped. It keeps facts the
exploit loop must not forget when chat context is compacted or rebuilt on
resume. It does not write cross-mission lessons.
"""

from __future__ import annotations

import json
import re
import sqlite3
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Generator


ATTACK_MEMORY_DB = "attack_memory.db"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _new_id() -> str:
    short = uuid.uuid4().hex[:8].upper()
    seq = int(time.time() * 1000) % 100000
    return f"ATM-{seq:05d}-{short}"


@dataclass(frozen=True)
class AttackMemoryItem:
    id: str
    session_id: str
    target_ip: str
    category: str
    item_key: str
    item_value: str
    source_tool: str
    success: bool
    metadata: dict[str, Any]
    first_seen_at: str
    last_seen_at: str
    seen_count: int


class AttackMemoryStore:
    """SQLite-backed memory for the active attack session."""

    _CATEGORY_ORDER = {
        "access": 0,
        "credentials": 1,
        "services": 2,
        "os": 3,
        "cves": 4,
        "endpoints": 5,
        "evidence": 6,
        "findings": 7,
        "failures": 8,
        "actions": 9,
        "notes": 10,
    }

    def __init__(self, workspace: Path, session_id: str, target_ip: str) -> None:
        self.workspace = Path(workspace)
        self.workspace.mkdir(parents=True, exist_ok=True)
        self.session_id = str(session_id or "default")
        self.target_ip = str(target_ip or "")
        self._path = self.workspace / ATTACK_MEMORY_DB
        self._ensure_schema()

    @property
    def path(self) -> Path:
        return self._path

    @contextmanager
    def _connect(self) -> Generator[sqlite3.Connection, None, None]:
        conn = sqlite3.connect(str(self._path))
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout=5000")
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def _ensure_schema(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS attack_memory_items (
                    id TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    target_ip TEXT NOT NULL DEFAULT '',
                    category TEXT NOT NULL,
                    item_key TEXT NOT NULL DEFAULT '',
                    item_value TEXT NOT NULL DEFAULT '',
                    source_tool TEXT NOT NULL DEFAULT '',
                    success INTEGER NOT NULL DEFAULT 0,
                    metadata_json TEXT NOT NULL DEFAULT '{}',
                    first_seen_at TEXT NOT NULL,
                    last_seen_at TEXT NOT NULL,
                    seen_count INTEGER NOT NULL DEFAULT 1,
                    UNIQUE(session_id, target_ip, category, item_key, item_value)
                )
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_attack_memory_session
                ON attack_memory_items(session_id, target_ip, category, last_seen_at)
                """
            )

    def capture_tool_result(
        self,
        tool_name: str,
        result_text: str,
        success: bool,
        command: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> int:
        """Extract and persist useful facts from one tool result.

        Returns the number of memory upserts attempted.
        """
        text = str(result_text or "")
        source = str(tool_name or "tool")
        base_meta = dict(metadata or {})
        if command:
            base_meta.setdefault("command", command)

        records: list[tuple[str, str, str, dict[str, Any]]] = []
        summary = _summarize_for_memory(source, text)
        if summary:
            records.append(("actions" if success else "failures", source, summary, base_meta))

        for category, key, value, extra in _extract_facts(text, self.target_ip, source, success):
            merged = dict(base_meta)
            merged.update(extra)
            records.append((category, key, value, merged))

        count = 0
        for category, key, value, meta in records:
            if self.capture_note(
                category=category,
                key=key,
                value=value,
                source_tool=source,
                success=success,
                metadata=meta,
            ):
                count += 1
        return count

    def capture_note(
        self,
        category: str,
        key: str,
        value: str,
        *,
        source_tool: str = "",
        success: bool = True,
        metadata: dict[str, Any] | None = None,
    ) -> bool:
        category = _clean_field(category, default="notes")
        key = _clean_field(key, default="note")
        value = _clean_value(value)
        if not value:
            return False

        now = _now_iso()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO attack_memory_items(
                    id, session_id, target_ip, category, item_key, item_value,
                    source_tool, success, metadata_json, first_seen_at, last_seen_at,
                    seen_count
                )
                VALUES(?,?,?,?,?,?,?,?,?,?,?,1)
                ON CONFLICT(session_id, target_ip, category, item_key, item_value)
                DO UPDATE SET
                    source_tool=excluded.source_tool,
                    success=excluded.success,
                    metadata_json=excluded.metadata_json,
                    last_seen_at=excluded.last_seen_at,
                    seen_count=attack_memory_items.seen_count + 1
                """,
                (
                    _new_id(),
                    self.session_id,
                    self.target_ip,
                    category,
                    key,
                    value,
                    str(source_tool or ""),
                    1 if success else 0,
                    json.dumps(metadata or {}, default=str),
                    now,
                    now,
                ),
            )
        return True

    def list_items(self, category: str | None = None, limit: int = 200) -> list[AttackMemoryItem]:
        sql = (
            "SELECT * FROM attack_memory_items "
            "WHERE session_id=? AND target_ip=?"
        )
        params: list[Any] = [self.session_id, self.target_ip]
        if category:
            sql += " AND category=?"
            params.append(category)
        sql += " ORDER BY last_seen_at DESC LIMIT ?"
        params.append(limit)

        with self._connect() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [_row_to_item(row) for row in rows]

    def format_context(self, max_items: int = 40, max_chars: int = 6000) -> str:
        """Return a compact memory block for prompt injection."""
        items = self.list_items(limit=max(80, max_items * 3))
        if not items:
            return ""

        items.sort(
            key=lambda item: (
                self._CATEGORY_ORDER.get(item.category, 99),
                item.last_seen_at,
            ),
            reverse=False,
        )

        grouped: dict[str, list[AttackMemoryItem]] = {}
        for item in items:
            grouped.setdefault(item.category, []).append(item)

        lines = ["CURRENT ATTACK MEMORY"]
        emitted = 0
        for category in sorted(grouped, key=lambda c: self._CATEGORY_ORDER.get(c, 99)):
            if emitted >= max_items:
                break
            lines.append(category.upper())
            category_items = sorted(grouped[category], key=lambda item: item.last_seen_at, reverse=True)
            for item in category_items:
                if emitted >= max_items:
                    break
                seen = f" x{item.seen_count}" if item.seen_count > 1 else ""
                value = _one_line(item.item_value, max_chars=500)
                lines.append(f"- {item.item_key}: {value}{seen}")
                emitted += 1

        return _cap_text("\n".join(lines), max_chars)


def _row_to_item(row: sqlite3.Row) -> AttackMemoryItem:
    try:
        metadata = json.loads(row["metadata_json"] or "{}")
    except (TypeError, json.JSONDecodeError):
        metadata = {}
    return AttackMemoryItem(
        id=row["id"],
        session_id=row["session_id"],
        target_ip=row["target_ip"],
        category=row["category"],
        item_key=row["item_key"],
        item_value=row["item_value"],
        source_tool=row["source_tool"],
        success=bool(row["success"]),
        metadata=metadata,
        first_seen_at=row["first_seen_at"],
        last_seen_at=row["last_seen_at"],
        seen_count=int(row["seen_count"]),
    )


def _extract_facts(
    text: str,
    target_ip: str,
    source_tool: str,
    success: bool,
) -> list[tuple[str, str, str, dict[str, Any]]]:
    records: list[tuple[str, str, str, dict[str, Any]]] = []
    if not text:
        return records

    for service in _extract_services(text, target_ip):
        records.append(("services", service["key"], service["value"], {"source": "service_parser"}))

    for os_hint in _extract_os_hints(text, source_tool):
        records.append(("os", "target_os", os_hint, {"source": "os_parser"}))

    for cve in sorted(set(re.findall(r"CVE-\d{4}-\d{4,7}", text, flags=re.IGNORECASE))):
        records.append(("cves", cve.upper(), cve.upper(), {"source": "cve_regex"}))

    for endpoint in _extract_endpoints(text):
        records.append(("endpoints", "endpoint", endpoint, {"source": "endpoint_regex"}))

    for key, value in _extract_credentials(text):
        records.append(("credentials", key, value, {"source": "credential_regex"}))

    for access in _extract_access(text):
        records.append(("access", "access", access, {"source": "access_regex"}))

    for ref in _extract_references(text):
        records.append(("evidence", "reference", ref, {"source": "reference_regex"}))

    for finding in _extract_findings(text):
        records.append(("findings", "signal", finding, {"source": "finding_regex"}))

    if not success or _looks_like_failure(text):
        records.append(("failures", source_tool or "tool", _summarize_for_memory(source_tool, text), {"source": "failure"}))

    return records


def _extract_services(text: str, target_ip: str) -> list[dict[str, str]]:
    services: list[dict[str, str]] = []
    patterns = [
        re.compile(r"(?m)^\s*(\d{1,5})/(tcp|udp)\s+open\s+(.+?)\s*$", re.IGNORECASE),
        re.compile(r"Port\s+(\d{1,5})/(tcp|udp)\s+open:?\s+(.+?)(?:\n|$)", re.IGNORECASE),
    ]
    for pattern in patterns:
        for match in pattern.finditer(text):
            port, proto, info = match.group(1), match.group(2).lower(), _one_line(match.group(3), 180)
            value = f"{target_ip}:{port}/{proto} {info}" if target_ip else f"{port}/{proto} {info}"
            key = f"{port}/{proto}"
            services.append({"key": key, "value": value})
    return _dedupe_dicts(services)


def _extract_os_hints(text: str, source_tool: str) -> list[str]:
    hints: list[str] = []
    for pattern in (
        r"OS details:\s*([^\r\n]+)",
        r"Target OS identified as\s+([^:\r\n]+)",
        r"Target OS detected as:\s*([^\r\n.]+)",
        r"OS guess:\s*([^\r\n.]+)",
    ):
        for match in re.finditer(pattern, text, flags=re.IGNORECASE):
            hints.append(_one_line(match.group(1), 160))

    lower = text.lower()
    if "check_os" in source_tool.lower() or "os" in source_tool.lower():
        if "windows" in lower:
            hints.append("Windows")
        if "linux" in lower:
            hints.append("Linux")
    return _dedupe_values(hints)


def _extract_endpoints(text: str) -> list[str]:
    endpoints: list[str] = []
    for match in re.finditer(r"https?://[^\s\"'<>]+", text, flags=re.IGNORECASE):
        endpoints.append(match.group(0).rstrip(".,;)"))
    for match in re.finditer(r"\b(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(/[^\s\"']*)", text):
        endpoints.append(match.group(1).rstrip(".,;)"))
    return _dedupe_values(endpoints)


def _extract_credentials(text: str) -> list[tuple[str, str]]:
    creds: list[tuple[str, str]] = []
    patterns = [
        ("username", r"\b(?:username|user|login)\s*[:=]\s*([^\s,;]+)"),
        ("password", r"\b(?:password|passwd|pass|pwd)\s*[:=]\s*([^\s,;]+)"),
        ("token", r"\b(?:api[_-]?key|access[_-]?token|token|secret)\s*[:=]\s*([^\s,;]+)"),
        ("bearer", r"\bBearer\s+([A-Za-z0-9._~+/=-]+)"),
        ("credentials", r"\b(?:creds?|credentials)\s*[:=]\s*([^\r\n]{1,200})"),
    ]
    for key, pattern in patterns:
        for match in re.finditer(pattern, text, flags=re.IGNORECASE):
            value = match.group(1).strip().strip("\"'")
            if value:
                creds.append((key, _one_line(value, 240)))
    return _dedupe_pairs(creds)


def _extract_access(text: str) -> list[str]:
    access: list[str] = []
    markers = (
        "meterpreter session",
        "command shell session",
        "shell opened",
        "session opened",
        "access achieved",
        "logged in",
        "login successful",
        "uid=",
        "nt authority\\",
        "root@",
    )
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        lower = stripped.lower()
        if any(marker in lower for marker in markers):
            access.append(_one_line(stripped, 260))
    return _dedupe_values(access)


def _extract_references(text: str) -> list[str]:
    refs: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        lower = stripped.lower()
        if any(marker in lower for marker in ("evidence", "saved to", "written to", "artifact", "path:", "file:")):
            refs.append(_one_line(stripped, 260))
    path_pattern = re.compile(
        r"(?:[A-Za-z]:\\[^\s\"']+|(?:\.{0,2}[/\\])?[A-Za-z0-9_.-]+(?:[/\\][A-Za-z0-9_. -]+)+)"
    )
    for match in path_pattern.finditer(text):
        refs.append(match.group(0).rstrip(".,;)"))
    return _dedupe_values(refs)


def _extract_findings(text: str) -> list[str]:
    findings: list[str] = []
    markers = ("vulnerable", "exploit succeeded", "successfully exploited", "[+]", "possible finding")
    for line in text.splitlines():
        stripped = line.strip()
        if stripped and any(marker in stripped.lower() for marker in markers):
            findings.append(_one_line(stripped, 260))
    return _dedupe_values(findings)


def _looks_like_failure(text: str) -> bool:
    lower = text.lower()
    return any(
        marker in lower
        for marker in (
            "error",
            "failed",
            "failure",
            "timeout",
            "connection refused",
            "blocked",
            "denied",
            "exit_code: 1",
            "exit_code=1",
        )
    )


def _summarize_for_memory(tool_name: str, text: str) -> str:
    if not text:
        return ""
    try:
        from summarizer import summarize_tool_output

        summary = summarize_tool_output(text, tool_name=tool_name, max_tokens_estimate=1200)
    except Exception:
        summary = text
    return _one_line(summary, max_chars=1000)


def _clean_field(value: str, default: str) -> str:
    clean = str(value or "").strip().lower()
    clean = re.sub(r"[^a-z0-9_.:-]+", "_", clean).strip("_")
    return clean or default


def _clean_value(value: str) -> str:
    return _one_line(str(value or "").strip(), max_chars=2000)


def _one_line(text: str, max_chars: int) -> str:
    clean = re.sub(r"\s+", " ", str(text or "")).strip()
    return _cap_text(clean, max_chars)


def _cap_text(text: str, max_chars: int) -> str:
    if max_chars <= 0:
        return ""
    if len(text) <= max_chars:
        return text
    return text[: max_chars - 3].rstrip() + "..."


def _dedupe_values(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value and value not in seen:
            seen.add(value)
            result.append(value)
    return result


def _dedupe_pairs(values: list[tuple[str, str]]) -> list[tuple[str, str]]:
    seen: set[tuple[str, str]] = set()
    result: list[tuple[str, str]] = []
    for pair in values:
        if pair[1] and pair not in seen:
            seen.add(pair)
            result.append(pair)
    return result


def _dedupe_dicts(values: list[dict[str, str]]) -> list[dict[str, str]]:
    seen: set[tuple[str, str]] = set()
    result: list[dict[str, str]] = []
    for value in values:
        key = (value.get("key", ""), value.get("value", ""))
        if key[1] and key not in seen:
            seen.add(key)
            result.append(value)
    return result
