"""Unified memory facade — single entry point for BreachPilot memory systems.

This module is the canonical home of all Flow A memory logic:

- **Per-attempt window** — :class:`AttackMemoryStore` (tactical, session-scoped
  facts extracted from tool results) plus :class:`SessionManager` /
  :class:`SessionState` (attempt checkpoint state + context windowing).
- **Cross-mission store** — :class:`SemanticMemoryManager` (embedding-based
  lesson retrieval) plus :class:`ExperienceStore` (Bayesian outcome confidence).
- **Checkpoint/resume** — :class:`SessionManager` persistence helpers and
  :func:`_load_resume_state` (CLI recon-assessment restore).
- **Bayesian confidence** — :class:`ExperienceStore` posterior queries, backed
  by the shared :func:`beta_mean` / :func:`decay_weight` helpers.

The original modules (``tools/attack_memory.py``, ``tools/experience_store.py``,
``tools/semantic_memory.py``, ``tools/session_manager.py``,
``tools/resume_state.py``) are thin re-export shims over this facade so every
existing import path keeps working. They must not be deleted (legacy flows,
tests, and lazy call-site imports reference them directly).

Explicitly out of scope: ``tools/persistent_session_manager.py`` manages
tmux/background/listener OS processes, not memory — it stays untouched.

Deduplicated here (previously copied across the memory modules):

- :func:`cap_text` / :func:`one_line` — char-budget truncation.
- :func:`take_last` — bounded list windowing (``state[-N:]`` idiom).
- :func:`decay_weight` — exponential time-decay for outcomes.
- :func:`beta_mean` — Beta(1+s, 1+f) posterior mean.
- :func:`cosine_similarity` — zero/NaN/shape-safe cosine (numpy loaded lazily).
"""

from __future__ import annotations

import argparse
import json
import logging
import math
import re
import sqlite3
import time
import uuid
from collections.abc import Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, Generator, TypeVar

from db import DatabaseManager, _new_id, _now_iso
from tools.attack_planner import AttackPlanner
from tools.goal_suggester import ReconAssessment
from tools.providers.embeddings import OllamaEmbeddingProvider

if TYPE_CHECKING:
    import numpy as _np

    from tools.providers.embeddings import EmbeddingProvider

_logger = logging.getLogger(__name__)

T = TypeVar("T")


# ---------------------------------------------------------------------------
# Shared helpers (deduplicated windowing / truncation / decay logic)
# ---------------------------------------------------------------------------


def cap_text(text: str, max_chars: int) -> str:
    """Truncate ``text`` to ``max_chars`` with a ``...`` suffix on overflow."""
    if max_chars <= 0:
        return ""
    if len(text) <= max_chars:
        return text
    return text[: max_chars - 3].rstrip() + "..."


def one_line(text: str, max_chars: int = 500) -> str:
    """Collapse ``text`` to a single line capped at ``max_chars``."""
    clean = re.sub(r"\s+", " ", str(text or "")).strip()
    return cap_text(clean, max_chars)


def take_last(items: Sequence[T], limit: int) -> list[T]:
    """Return the last ``limit`` items as a list (bounded-window helper).

    Behavior-identical to the ``items[-limit:]`` slices previously scattered
    across the session/checkpoint code; ``limit <= 0`` yields ``[]``.
    """
    if limit <= 0:
        return []
    return list(items[-limit:])


def decay_weight(created_at: str, half_life_days: float) -> float:
    """Exponential decay weight in [0, 1] for a row's ``created_at``.

    1.0 at age 0, 0.5 at age ``half_life_days``, decaying toward 0. Returns
    1.0 (no decay) when ``half_life_days`` <= 0 or the timestamp is
    unparseable — never raises on a bad row.
    """
    if half_life_days <= 0.0:
        return 1.0
    try:
        created = datetime.fromisoformat(created_at)
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        age_days = max(
            0.0,
            (datetime.now(timezone.utc) - created).total_seconds() / 86400.0,
        )
        return float(math.exp(-age_days / half_life_days))
    except Exception:
        return 1.0


def beta_mean(successes: float, failures: float, partials: float = 0.0) -> float:
    """Mean of the Beta(1+s+p, 1+f+p) posterior for outcome weights."""
    alpha = 1.0 + successes + partials
    beta = 1.0 + failures + partials
    return alpha / (alpha + beta)


def cosine_similarity(a: _np.ndarray, b: _np.ndarray) -> float:
    """Cosine similarity with defensive 0.0 guards.

    Shape mismatch (different embedding dimensions across rows), non-finite
    (NaN/inf) inputs, and a non-finite result all return 0.0 — the neutral
    "no information" score callers already treat as a non-match.
    """
    import numpy as np  # ponytail: lazy — paid only when recall actually runs

    if a.shape != b.shape:
        return 0.0
    if not (np.isfinite(a).all() and np.isfinite(b).all()):
        return 0.0
    norm_a = np.linalg.norm(a)
    norm_b = np.linalg.norm(b)
    if norm_a == 0 or norm_b == 0:
        return 0.0
    sim = float(np.dot(a, b) / (norm_a * norm_b))
    if not np.isfinite(sim):
        return 0.0
    return sim


# ---------------------------------------------------------------------------
# Per-attempt window: durable current-attack memory.
# ---------------------------------------------------------------------------


ATTACK_MEMORY_DB = "attack_memory.db"


def _attack_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _attack_new_id() -> str:
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
        # ponytail: WAL + NORMAL keeps per-action writes from blocking readers;
        # single-transaction batch in capture_tool_result cuts N connects to 1.
        try:
            conn.execute("PRAGMA journal_mode=WAL")
        except sqlite3.Error:
            pass
        try:
            conn.execute("PRAGMA synchronous=NORMAL")
        except sqlite3.Error:
            pass
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
        if not records:
            return 0
        # ponytail: one transaction for all facts — was N connects/commits
        # (one per capture_note) on every tool result.
        now = _attack_now_iso()
        with self._connect() as conn:
            for category, key, value, meta in records:
                if self._upsert_note(
                    conn,
                    category=category,
                    key=key,
                    value=value,
                    source_tool=source,
                    success=success,
                    metadata=meta,
                    now=now,
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

        now = _attack_now_iso()
        with self._connect() as conn:
            return self._upsert_note(
                conn,
                category=category,
                key=key,
                value=value,
                source_tool=source_tool,
                success=success,
                metadata=metadata,
                now=now,
            )

    def _upsert_note(
        self,
        conn: sqlite3.Connection,
        *,
        category: str,
        key: str,
        value: str,
        source_tool: str = "",
        success: bool = True,
        metadata: dict[str, Any] | None = None,
        now: str = "",
    ) -> bool:
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
                _attack_new_id(),
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
        sql = "SELECT * FROM attack_memory_items WHERE session_id=? AND target_ip=?"
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
                if category == "credentials":
                    value = "[redacted]"
                else:
                    value = one_line(item.item_value, max_chars=500)
                lines.append(f"- {item.item_key}: {value}{seen}")
                emitted += 1

        return cap_text("\n".join(lines), max_chars)


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
        records.append(
            ("failures", source_tool or "tool", _summarize_for_memory(source_tool, text), {"source": "failure"})
        )

    return records


def _extract_services(text: str, target_ip: str) -> list[dict[str, str]]:
    services: list[dict[str, str]] = []
    patterns = [
        re.compile(r"(?m)^\s*(\d{1,5})/(tcp|udp)\s+open\s+(.+?)\s*$", re.IGNORECASE),
        re.compile(r"Port\s+(\d{1,5})/(tcp|udp)\s+open:?\s+(.+?)(?:\n|$)", re.IGNORECASE),
    ]
    for pattern in patterns:
        for match in pattern.finditer(text):
            port, proto, info = match.group(1), match.group(2).lower(), one_line(match.group(3), 180)
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
            hints.append(one_line(match.group(1), 160))

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
                creds.append((key, one_line(value, 240)))
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
            access.append(one_line(stripped, 260))
    return _dedupe_values(access)


def _extract_references(text: str) -> list[str]:
    refs: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        lower = stripped.lower()
        if any(marker in lower for marker in ("evidence", "saved to", "written to", "artifact", "path:", "file:")):
            refs.append(one_line(stripped, 260))
    path_pattern = re.compile(r"(?:[A-Za-z]:\\[^\s\"']+|(?:\.{0,2}[/\\])?[A-Za-z0-9_.-]+(?:[/\\][A-Za-z0-9_. -]+)+)")
    for match in path_pattern.finditer(text):
        refs.append(match.group(0).rstrip(".,;)"))
    return _dedupe_values(refs)


def _extract_findings(text: str) -> list[str]:
    findings: list[str] = []
    markers = ("vulnerable", "exploit succeeded", "successfully exploited", "[+]", "possible finding")
    for line in text.splitlines():
        stripped = line.strip()
        if stripped and any(marker in stripped.lower() for marker in markers):
            findings.append(one_line(stripped, 260))
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
    return one_line(summary, max_chars=1000)


def _clean_field(value: str, default: str) -> str:
    clean = str(value or "").strip().lower()
    clean = re.sub(r"[^a-z0-9_.:-]+", "_", clean).strip("_")
    return clean or default


def _clean_value(value: str) -> str:
    return one_line(str(value or "").strip(), max_chars=2000)


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


# ---------------------------------------------------------------------------
# Cross-mission store (Bayesian): exploit-outcome confidence.
# ---------------------------------------------------------------------------


class ExperienceStore:
    """Tracks action outcomes and maintains Bayesian confidence scores.

    Confidence is the mean of a Beta posterior, updated per recorded outcome.
    Two soundness gates (Tier 1.1) keep the "principled action selector" honest:

    - **min_samples**: when fewer than ``min_samples`` outcomes have been
      recorded for a (target_signature, action_type) pair, ``get_confidence``
      returns a neutral ``0.5`` instead of a confident-looking ratio built on
      thin data (one success used to read as 0.67 — "high confidence").
    - **time_decay_days**: outcomes are weighted by an exponential time decay
      (half-life ``time_decay_days``) so an ancient outcome counts less than a
      recent one; the default half-life of 90 days means a 90-day-old result
      weighs half as much as one recorded today. Set ``time_decay_days <= 0``
      to disable decay (weight 1.0 for every row, the pre-1.1 behavior).
    """

    def __init__(
        self,
        db: DatabaseManager,
        *,
        min_samples: int = 3,
        time_decay_days: float = 90.0,
    ) -> None:
        self._db = db
        self._min_samples = max(1, int(min_samples))
        self._time_decay_days = float(time_decay_days) if time_decay_days and time_decay_days > 0 else 0.0

    def _decay_weight(self, created_at: str) -> float:
        """Exponential decay weight for a row — see :func:`decay_weight`."""
        return decay_weight(created_at, self._time_decay_days)

    # ── Recording outcomes ──────────────────────────────────────────────

    def record_outcome(
        self,
        target_signature: str,
        action_type: str,
        outcome: str,  # 'success', 'failure', 'partial'
        metadata: dict[str, Any] | None = None,
        *,
        action_suffix: str = "",
    ) -> str:
        """Record an outcome observation. Returns the record ID.

        ``action_suffix`` is an optional free-form tag (e.g. ``"shell"``,
        ``"creds"``, ``"partial"``) appended to ``action_type`` as
        ``f"{action_type}:{action_suffix}"`` for storage and querying. This
        lets the Bayesian posterior condition on the distinct outcome class —
        a shell compromise (``"module:strategy:shell"``) is scored
        independently from a credential dump (``"module:strategy:creds"``)
        or a bare operational outcome (``"module:strategy"``), instead of all
        three collapsing into one Beta distribution. Empty / falsy
        ``action_suffix`` preserves the original behavior (callers that pass
        a bare ``action_type`` are byte-identical to pre-1.1 runs).
        """
        stored_action = f"{action_type}:{action_suffix}" if action_suffix else action_type
        rid = _new_id("EXP")
        with self._db.connection(write=True) as conn:
            conn.execute(
                """INSERT INTO lessons(id, pattern_hash, target_signature, action_type, outcome, confidence, embedding_json, metadata_json, created_at)
                   VALUES(?,?,?,?,?,?,?,?,?)""",
                (
                    rid,
                    f"{target_signature}:{stored_action}",
                    target_signature,
                    stored_action,
                    outcome,
                    0.5,  # initial confidence
                    "[]",
                    json.dumps(metadata or {}),
                    _now_iso(),
                ),
            )
        return rid

    def record_evidential_outcome(
        self,
        target_signature: str,
        action_type: str,
        hypothesis_status: str,
        *,
        confidence: float,
        evidence_refs: list[str],
        metadata: dict[str, Any] | None = None,
    ) -> str | None:
        """Record learning only for evidence-supported confirmation/refutation.

        Operational success/failure is intentionally not accepted here.
        Inconclusive, open, and exhausted hypotheses return ``None`` so they
        cannot reinforce a tool or strategy.
        """
        normalized_status = str(hypothesis_status).strip().lower()
        outcome_by_status = {
            "confirmed": "success",
            "refuted": "failure",
        }
        outcome = outcome_by_status.get(normalized_status)
        if outcome is None:
            return None
        try:
            calibrated_confidence = max(0.0, min(float(confidence), 1.0))
        except (TypeError, ValueError):
            calibrated_confidence = 0.5
        if not evidence_refs:
            return None
        evidence_metadata = dict(metadata or {})
        evidence_metadata.update(
            {
                "hypothesis_status": normalized_status,
                "judgment_confidence": calibrated_confidence,
                "evidence_refs": list(dict.fromkeys(str(ref) for ref in evidence_refs if ref)),
                "evidence_grounded": True,
            }
        )
        return self.record_outcome(
            target_signature,
            action_type,
            outcome,
            evidence_metadata,
        )

    # ── Bayesian confidence query ───────────────────────────────────────

    def get_confidence(
        self,
        target_signature: str,
        action_type: str,
    ) -> float:
        """Return the Bayesian confidence for a (target_signature, action_type) pair.

        Uses the decay-weighted Beta(1+successes, 1+failures) mean as the
        confidence score. Returns a neutral ``0.5`` when fewer than
        ``min_samples`` outcomes have been recorded so thin data does not
        masquerade as a confident ratio.
        """
        successes = 0.0
        failures = 0.0
        partials = 0.0
        n = 0

        with self._db.connection() as conn:
            cur = conn.execute(
                "SELECT outcome, created_at FROM lessons "
                "WHERE target_signature = ? AND action_type = ? "
                "AND embedding_json = '[]'",
                (target_signature, action_type),
            )
            for row in cur.fetchall():
                w = self._decay_weight(row["created_at"])
                outcome = row["outcome"]
                if outcome == "success":
                    n += 1
                    successes += w
                elif outcome == "failure":
                    n += 1
                    failures += w
                elif outcome == "partial":
                    partials += 0.5 * w

        if n < self._min_samples:
            return 0.5

        return beta_mean(successes, failures, partials)

    def observation_count(
        self,
        target_signature: str,
        action_type: str,
    ) -> int:
        """Return the total number of decisive outcomes for a pair.

        Unlike ``get_confidence`` (which gates on ``min_samples`` and returns a
        posterior), this is the row count used by callers that need their own
        sample-size gate -- e.g. the runtime-skill feedback loop applies a
        separate ``feedback_min_observations`` threshold before trusting a
        ``skill_prior``. Counts only ``success``/``failure`` rows; neutral
        ``partial`` observations (skill loads) never satisfy a min-samples gate.
        """
        try:
            with self._db.connection() as conn:
                cur = conn.execute(
                    "SELECT COUNT(*) AS n FROM lessons "
                    "WHERE target_signature = ? AND action_type = ? "
                    "AND embedding_json = '[]' AND outcome IN ('success','failure')",
                    (target_signature, action_type),
                )
                row = cur.fetchone()
                return int(row["n"]) if row is not None else 0
        except Exception:
            return 0

    def get_best_action(
        self,
        target_signature: str,
        candidates: list[str],
    ) -> tuple[str, float] | None:
        """Return the candidate action with the highest confidence for the target."""
        best_action: str | None = None
        best_conf = -1.0
        for action in candidates:
            conf = self.get_confidence(target_signature, action)
            if conf > best_conf:
                best_conf = conf
                best_action = action
        if best_action is None:
            return None
        return best_action, best_conf

    def get_all_confidences(
        self,
        target_signature: str,
    ) -> dict[str, float]:
        """Return confidence scores for all known actions against a target signature.

        Each action's score is the decay-weighted Beta mean, gated on
        ``min_samples`` (actions with too few observations read as a neutral
        0.5 rather than a confident-looking thin-data ratio).
        """
        results: dict[str, float] = {}
        # action -> {success: weight_sum, failure: weight_sum, partial: weight_sum, n: int}
        agg: dict[str, dict[str, float]] = {}
        with self._db.connection() as conn:
            cur = conn.execute(
                "SELECT action_type, outcome, created_at FROM lessons "
                "WHERE target_signature = ? AND embedding_json = '[]'",
                (target_signature,),
            )
            for row in cur.fetchall():
                action = row["action_type"]
                bucket = agg.setdefault(action, {"success": 0.0, "failure": 0.0, "partial": 0.0, "n": 0.0})
                w = self._decay_weight(row["created_at"])
                outcome = row["outcome"]
                if outcome == "success":
                    bucket["n"] += 1
                    bucket["success"] += w
                elif outcome == "failure":
                    bucket["n"] += 1
                    bucket["failure"] += w
                elif outcome == "partial":
                    bucket["partial"] += 0.5 * w

        for action, b in agg.items():
            if b["n"] < self._min_samples:
                results[action] = 0.5
                continue
            results[action] = beta_mean(b["success"], b["failure"], b["partial"])

        return results

    # ── Feedback loop ───────────────────────────────────────────────────

    def update_from_result(
        self,
        target_signature: str,
        action_type: str,
        success: bool,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Convenience wrapper to record a binary success/failure outcome."""
        outcome = "success" if success else "failure"
        self.record_outcome(target_signature, action_type, outcome, metadata)

    def record_module_outcome(
        self,
        target_signature: str,
        module_name: str,
        status_str: str,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Phase 1: map an AttackModule's run() status string to a Bayesian
        outcome and record it. ``info`` → ``partial`` (neutral 0.5 weight --
        the module ran but produced no compromise signal, so it should not
        inflate or deflate confidence); ``success``/``exploited``/
        ``script_generated`` → ``success``; ``failed``/``blocked`` →
        ``failure``. This feeds the orchestrator's module runs into the
        same ExperienceStore the exploit-agent loop writes to, so
        ``find_modules`` on the next campaign reflects orchestrator history.
        """
        s = str(status_str or "").lower()
        if s in ("success", "exploited", "script_generated"):
            outcome = "success"
        elif s in ("failed", "blocked", "error"):
            outcome = "failure"
        else:
            outcome = "partial"
        self.record_outcome(
            target_signature=target_signature,
            action_type=module_name,
            outcome=outcome,
            metadata=metadata,
        )

    def update_from_exploit_result(
        self,
        service_name: str,
        version: str,
        os_hint: str,
        module_name: str,
        mutation_strategy: str,
        success: bool,
    ) -> None:
        """Record an exploit outcome with full context for adaptive generation."""
        target_signature = f"{service_name}:{version}:{os_hint}"
        action_type = f"{module_name}:{mutation_strategy}"
        self.update_from_result(
            target_signature=target_signature,
            action_type=action_type,
            success=success,
            metadata={
                "service_name": service_name,
                "version": version,
                "os_hint": os_hint,
                "module_name": module_name,
                "mutation_strategy": mutation_strategy,
            },
        )

    def batch_skill_stats(self, skill_names: list[str]) -> dict[str, tuple[int, float]]:
        """One-query count+prior for many skills (perf: was 2 SELECTs each)."""
        # ponytail: skill selector did 2 SELECTs per candidate (40-60 total).
        result: dict[str, tuple[int, float]] = {}
        names = [str(n) for n in skill_names if str(n)]
        if not names:
            return result
        try:
            sigs = [f"skill:{n}" for n in names]
            placeholders = ",".join("?" for _ in sigs)
            with self._db.connection() as conn:
                cur = conn.execute(
                    "SELECT target_signature, outcome, created_at FROM lessons "
                    f"WHERE target_signature IN ({placeholders}) AND action_type = 'skill' "
                    "AND embedding_json = '[]'",
                    tuple(sigs),
                )
                buckets: dict[str, list[tuple[str, str]]] = {}
                for row in cur.fetchall():
                    buckets.setdefault(row["target_signature"], []).append((row["outcome"], row["created_at"]))
            for name, sig in zip(names, sigs):
                rows = buckets.get(sig, [])
                n = sum(1 for outcome, _ in rows if outcome in ("success", "failure"))
                if n < self._min_samples:
                    result[name] = (n, 0.5)
                    continue
                successes = failures = partials = 0.0
                for outcome, created_at in rows:
                    w = self._decay_weight(created_at)
                    if outcome == "success":
                        successes += w
                    elif outcome == "failure":
                        failures += w
                    elif outcome == "partial":
                        partials += 0.5 * w
                result[name] = (n, beta_mean(successes, failures, partials))
        except Exception:
            return {}
        return result


# ---------------------------------------------------------------------------
# Cross-mission store (semantic): embedding-based retrieval.
# ---------------------------------------------------------------------------


class SemanticMemoryManager:
    """Generates, stores, and retrieves embeddings via a provider + SQLite."""

    def __init__(
        self,
        db: DatabaseManager,
        ollama_host: str = "https://api.ollama.com",
        embedding_model: str = "nomic-embed-text",
        embedding_provider: Any | None = None,
    ) -> None:
        """``ollama_host`` / ``embedding_model`` are the legacy kwargs (still
        accepted — the frozen Flow B research loop passes them); newer callers
        pass ``embedding_provider`` from ``tools.providers.embeddings``.
        When no provider is given, the legacy Ollama behavior is preserved
        byte-identically (raw /api/embeddings against ``ollama_host``).
        """
        self._db = db
        if embedding_provider is not None:
            self._embedding_provider = embedding_provider
        else:
            self._embedding_provider = OllamaEmbeddingProvider(host=ollama_host, model=embedding_model)
        self._ollama_host = ollama_host.rstrip("/")
        self._embedding_model = embedding_model

    # ── Embedding generation ──────────────────────────────────────────

    def embed(self, text: str) -> list[float] | None:
        """Public single-text embedding accessor.

        Returns the embedding vector for ``text``, or ``None`` on any failure
        (Ollama unreachable, network error, non-finite response). Same contract
        as the internal generator; exposed so the runtime-skill semantic ranker
        (``tools/skill_embeddings.py``) and other consumers can embed without
        reaching into a private method.
        """
        return self._generate_embedding(text)

    def _generate_embedding(self, text: str) -> list[float] | None:
        """Embed ``text`` via the configured embedding provider.

        Returns ``None`` on any failure (provider unreachable, network error, or
        a response with no embedding). Failures are logged at WARNING so a down
        endpoint does not silently degrade cross-mission learning to a no-op —
        this matches the boot ``[WARN]`` visibility convention. Every caller
        (``store_embedding``/``store_lesson``/``find_similar``/
        ``find_similar_lessons``) already handles ``None`` gracefully. With
        ``embeddings.provider: none`` this always returns ``None`` and no
        request is ever made.
        """
        return self._embedding_provider.embed(text)

    # ── Storage ─────────────────────────────────────────────────────────

    def store_embedding(
        self,
        source_table: str,
        source_id: str,
        text: str,
        mission_id: str = "",
    ) -> str | None:
        """Generate and store an embedding for the given text."""
        embedding = self._generate_embedding(text)
        if embedding is None:
            return None

        eid = _new_id("EMB")
        with self._db.connection(write=True) as conn:
            conn.execute(
                """INSERT INTO embeddings(id, mission_id, source_table, source_id, embedding_json, created_at)
                   VALUES(?,?,?,?,?,?)""",
                (eid, mission_id, source_table, source_id, json.dumps(embedding), _now_iso()),
            )
        return eid

    def store_lesson(
        self,
        target_signature: str,
        action_type: str,
        outcome: str,
        text: str,
        metadata: dict[str, Any] | None = None,
        confidence: float = 0.5,
    ) -> str | None:
        """Store a learned lesson with its embedding for cross-mission retrieval.

        The audit flagged that the lesson ``text`` (the ``why it failed`` /
        ``why it worked`` explanation) was embedded for similarity search but
        never persisted -- retrieval returned labels + metadata but NOT the
        text, so the model never saw the lesson. The ``text`` column is now
        populated (migration v5 adds it to existing DBs).
        """
        embedding = self._generate_embedding(text)
        if embedding is None:
            return None

        lid = _new_id("LSN")
        pattern_hash = f"{target_signature}:{action_type}:{outcome}"
        with self._db.connection(write=True) as conn:
            conn.execute(
                """INSERT INTO lessons(id, pattern_hash, target_signature, action_type, outcome, confidence, embedding_json, metadata_json, text, created_at)
                   VALUES(?,?,?,?,?,?,?,?,?,?)""",
                (
                    lid,
                    pattern_hash,
                    target_signature,
                    action_type,
                    outcome,
                    confidence,
                    json.dumps(embedding),
                    json.dumps(metadata or {}),
                    str(text or "")[:8000],
                    _now_iso(),
                ),
            )
        return lid

    # ── Retrieval ───────────────────────────────────────────────────────

    def find_similar(
        self,
        text: str,
        source_table: str | None = None,
        top_k: int = 5,
        mission_id: str | None = None,
    ) -> list[dict[str, Any]]:
        """Find the top-k most similar stored embeddings to the query text."""
        query_emb = self._generate_embedding(text)
        if query_emb is None:
            return []

        import numpy as np  # ponytail: lazy — paid only when recall runs

        query_vec = np.array(query_emb, dtype=np.float32)

        # Tier 1.1: skip zero-length embeddings. ``record_outcome`` (ExperienceStore)
        # writes lessons rows with embedding_json='[]' to track Bayesian outcomes;
        # those rows have no vector and would tie at cosine 0.0, polluting recall.
        # The same guard on the embeddings table is defensive (store_embedding only
        # ever writes a real vector or skips, but never trust that across flows).
        # Determinism: score the full filtered table (no LIMIT sampling).
        sql = (
            "SELECT id, mission_id, source_table, source_id, embedding_json "
            "FROM embeddings WHERE embedding_json != '[]'"
        )
        params: list[Any] = []
        if source_table:
            sql += " AND source_table = ?"
            params.append(source_table)
        if mission_id:
            sql += " AND mission_id = ?"
            params.append(mission_id)

        candidates: list[dict[str, Any]] = []
        with self._db.connection() as conn:
            cur = conn.execute(sql, params)
            for row in cur.fetchall():
                row_id = row["id"]
                # Guard the per-row parse + vector build + similarity computation.
                # A corrupt embedding_json (truncated, non-JSON, wrong dtype) or a
                # dimension mismatch against the query must not crash the whole
                # recall — skip the offending row and warn, mirroring the failure
                # contract callers already expect (None/[]) for bad embeddings.
                try:
                    emb = json.loads(row["embedding_json"])
                    vec = np.array(emb, dtype=np.float32)
                    sim = cosine_similarity(query_vec, vec)
                except (TypeError, json.JSONDecodeError, ValueError) as exc:
                    _logger.warning(
                        "find_similar: skipping embeddings row %s: %s",
                        row_id,
                        exc,
                    )
                    continue
                candidates.append(
                    {
                        "id": row_id,
                        "mission_id": row["mission_id"],
                        "source_table": row["source_table"],
                        "source_id": row["source_id"],
                        "similarity": float(sim),
                    }
                )

        candidates.sort(key=lambda x: x["similarity"], reverse=True)
        return candidates[:top_k]

    def find_similar_lessons(
        self,
        text: str,
        action_type: str | None = None,
        outcome: str | None = None,
        top_k: int = 5,
    ) -> list[dict[str, Any]]:
        """Find top-k lessons similar to the query text, optionally filtered."""
        query_emb = self._generate_embedding(text)
        if query_emb is None:
            return []

        import numpy as np  # ponytail: lazy — paid only when recall runs

        query_vec = np.array(query_emb, dtype=np.float32)

        # Tier 1.1: skip zero-length embeddings. ``record_outcome`` writes
        # embedding_json='[]' (it has no text to embed); without this filter those
        # rows would load as np.array([]), score cosine 0.0, and tie at the bottom
        # of every recall — defeating the whole point of wiring find_similar_lessons.
        # Determinism: score the full filtered table (no LIMIT sampling).
        sql = (
            "SELECT id, pattern_hash, target_signature, action_type, outcome, "
            "confidence, embedding_json, metadata_json, text "
            "FROM lessons WHERE embedding_json != '[]'"
        )
        params: list[Any] = []
        if action_type:
            sql += " AND action_type = ?"
            params.append(action_type)
        if outcome:
            sql += " AND outcome = ?"
            params.append(outcome)

        candidates: list[dict[str, Any]] = []
        with self._db.connection() as conn:
            cur = conn.execute(sql, params)
            for row in cur.fetchall():
                row_id = row["id"]
                # Guard the per-row parse + vector build + similarity computation
                # (same rationale as find_similar): corrupt embedding_json or a
                # dimension mismatch must skip the row, not crash recall. The
                # metadata_json parse is guarded too; on its failure we skip the
                # row (consistent with the embedding case) rather than emit a
                # half-formed candidate.
                try:
                    emb = json.loads(row["embedding_json"])
                    vec = np.array(emb, dtype=np.float32)
                    sim = cosine_similarity(query_vec, vec)
                except (TypeError, json.JSONDecodeError, ValueError) as exc:
                    _logger.warning(
                        "find_similar_lessons: skipping lessons row %s: %s",
                        row_id,
                        exc,
                    )
                    continue
                try:
                    metadata = json.loads(row["metadata_json"])
                except (TypeError, json.JSONDecodeError, ValueError) as exc:
                    _logger.warning(
                        "find_similar_lessons: skipping lessons row %s with corrupt metadata_json: %s",
                        row_id,
                        exc,
                    )
                    continue
                candidates.append(
                    {
                        "id": row_id,
                        "pattern_hash": row["pattern_hash"],
                        "target_signature": row["target_signature"],
                        "action_type": row["action_type"],
                        "outcome": row["outcome"],
                        "confidence": row["confidence"],
                        "similarity": float(sim),
                        "metadata": metadata,
                        # The lesson text (the "why" explanation). The audit flagged
                        # this was embedded for similarity but never returned, so the
                        # model never saw the lesson. Now persisted in the text column
                        # (migration v5) and selected here.
                        "text": str(row["text"] or "") if "text" in row.keys() else "",
                    }
                )

        candidates.sort(key=lambda x: x["similarity"], reverse=True)
        return candidates[:top_k]

    # ── Helpers ─────────────────────────────────────────────────────────

    @staticmethod
    def _cosine_similarity(a: _np.ndarray, b: _np.ndarray) -> float:
        """Back-compat alias — canonical implementation is :func:`cosine_similarity`."""
        return cosine_similarity(a, b)

    # ── Summarization ─────────────────────────────────────────────────

    def summarize_episodes(
        self,
        memory_type: str,
        mission_id: str,
        client: Any | None = None,
        model: str = "",
    ) -> str:
        """Use an LLM to distill episodic memories into semantic lessons.

        Returns ``""`` on failure (no memories, no client, or LLM error) so the
        caller's ``if not summary`` check falls through to the factual fallback.
        The previous error return ``"Summarization failed: {exc}"`` was
        indistinguishable from a real summary and got embedded as a "lesson"
        and retrieved later -- a real error-as-lesson bug.
        """
        memories: list[str] = []
        with self._db.connection() as conn:
            cur = conn.execute(
                "SELECT fact FROM memories WHERE mission_id = ? AND memory_type = ? ORDER BY created_at DESC LIMIT 50",
                (mission_id, memory_type),
            )
            for row in cur.fetchall():
                memories.append(row["fact"])

        if not memories or not client:
            return ""

        trunc_marker = " [truncated] - only the 30 most recent observations were shown." if len(memories) > 30 else ""
        prompt = (
            "Summarize the following research observations into concise, reusable security patterns. "
            "Focus on what worked, what failed, and why.\n\n"
            + "\n".join(f"- {m}" for m in memories[:30])
            + trunc_marker
            + "\n\nReturn a JSON object only (no markdown fences):\n"
            "{\n"
            '  "lessons": [{"pattern": "...", "worked_or_failed": "worked|failed", "why": "..."}],\n'
            '  "contradictions": ["observation pairs that conflict"]\n'
            "}\n"
            'If no reusable pattern emerges, return {"lessons": [], "contradictions": []}.'
        )
        messages = [
            {"role": "system", "content": "You are a security research summarizer. Return only valid JSON."},
            {"role": "user", "content": prompt},
        ]
        try:
            response = client.chat(model, messages=messages, stream=False)
            return response.get("message", {}).get("content", "")
        except Exception:
            # Return empty string (not an error message) so the caller's
            # ``if not summary`` falls to the factual fallback instead of
            # embedding the error text as a retrieved "lesson".
            return ""


# ---------------------------------------------------------------------------
# Checkpoint / resume: exploitation-session state.
# ---------------------------------------------------------------------------


@dataclass
class SessionState:
    session_id: str
    target_ip: str
    target_cve: str
    target_os: str | None = None
    known_cves: list[str] = field(default_factory=list)
    service_context: str = ""
    attacker_os: str = ""
    attack_mode: bool = False
    started_at: float = field(default_factory=time.time)
    last_activity: float = field(default_factory=time.time)
    total_actions: int = 0
    successful_exploits: int = 0
    current_phase: str = "recon"
    plan: dict[str, Any] | None = None
    context_history: list[dict[str, Any]] = field(default_factory=list)
    loot: list[dict[str, Any]] = field(default_factory=list)
    credentials: list[dict[str, Any]] = field(default_factory=list)
    compromised_hosts: list[str] = field(default_factory=list)
    messages: list[dict[str, Any]] = field(default_factory=list)
    # ponytail: when True (long-session mode), to_json persists the compacted
    # messages list (bounded to last 200) so a crashed run resumes with real
    # conversation context. Default False → old behavior (reconstituted
    # condensed from context_history) → backward compat with existing state files.
    persist_messages: bool = False
    reasoning_log: list[dict[str, Any]] = field(default_factory=list)  # NEW: tracks critic approvals and reflections

    def touch(self) -> None:
        self.last_activity = time.time()

    def to_json(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "target_ip": self.target_ip,
            "target_cve": self.target_cve,
            "target_os": self.target_os,
            "known_cves": self.known_cves,
            "service_context": self.service_context,
            "attacker_os": self.attacker_os,
            "attack_mode": self.attack_mode,
            "started_at": self.started_at,
            "last_activity": self.last_activity,
            "total_actions": self.total_actions,
            "successful_exploits": self.successful_exploits,
            "current_phase": self.current_phase,
            "plan": self.plan,
            "context_history": take_last(self.context_history, 50),
            "loot": take_last(self.loot, 100),
            "credentials": self.credentials,
            "compromised_hosts": self.compromised_hosts,
            "messages": take_last(self.messages, 200) if self.persist_messages else [],
            "persist_messages": self.persist_messages,
            "reasoning_log": take_last(self.reasoning_log, 50),
        }

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> SessionState:
        state = cls(
            session_id=str(data.get("session_id", "")),
            target_ip=str(data.get("target_ip", "")),
            target_cve=str(data.get("target_cve", "")),
            target_os=data.get("target_os") if data.get("target_os") else None,
            known_cves=data.get("known_cves", []),
            service_context=str(data.get("service_context", "")),
            attacker_os=str(data.get("attacker_os", "")),
            attack_mode=bool(data.get("attack_mode", False)),
            started_at=data.get("started_at", time.time()),
            last_activity=data.get("last_activity", time.time()),
            total_actions=int(data.get("total_actions", 0)),
            successful_exploits=int(data.get("successful_exploits", 0)),
            current_phase=str(data.get("current_phase", "recon")),
            plan=data.get("plan"),
            context_history=data.get("context_history", []),
            loot=data.get("loot", []),
            credentials=data.get("credentials", []),
            compromised_hosts=data.get("compromised_hosts", []),
            reasoning_log=data.get("reasoning_log", []),
            persist_messages=bool(data.get("persist_messages", False)),
            messages=data.get("messages", []) if data.get("persist_messages", False) else [],
        )
        return state


class SessionManager:
    """Persist and resume exploitation sessions across restarts."""

    def __init__(self, workspace: Path) -> None:
        self.workspace = workspace
        self.workspace.mkdir(parents=True, exist_ok=True)
        self._state_path = workspace / "session_state.json"
        self._state: SessionState | None = None
        self._planner = AttackPlanner(workspace)
        self._dirty: bool = False
        self._pending_save_count: int = 0
        self._save_interval: int = 10

    def new_session(
        self,
        *,
        target_ip: str,
        target_cve: str = "",
        target_os: str | None = None,
        known_cves: list[str] | None = None,
        service_context: str = "",
        attacker_os: str = "",
        attack_mode: bool = False,
    ) -> SessionState:
        session_id = f"{target_ip.replace('.', '_')}_{int(time.time())}"
        self._state = SessionState(
            session_id=session_id,
            target_ip=target_ip,
            target_cve=target_cve,
            target_os=target_os,
            known_cves=known_cves or [],
            service_context=service_context,
            attacker_os=attacker_os,
            attack_mode=attack_mode,
            current_phase="recon",
        )
        self._dirty = True
        self._flush()
        return self._state

    def resume_or_new(
        self,
        *,
        target_ip: str,
        target_cve: str = "",
        target_os: str | None = None,
        known_cves: list[str] | None = None,
        service_context: str = "",
        attacker_os: str = "",
        attack_mode: bool = False,
    ) -> SessionState:
        existing = self.load()
        if existing and existing.target_ip == target_ip:
            print(f"[SessionManager] Resuming session {existing.session_id} for {target_ip}")
            existing.touch()
            existing.attacker_os = attacker_os or existing.attacker_os
            existing.attack_mode = attack_mode
            self._state = existing
            self._pending_save_count = 0
            self._dirty = True
            self._flush()
            return existing
        return self.new_session(
            target_ip=target_ip,
            target_cve=target_cve,
            target_os=target_os,
            known_cves=known_cves,
            service_context=service_context,
            attacker_os=attacker_os,
            attack_mode=attack_mode,
        )

    def _mark_dirty(self) -> None:
        self._dirty = True
        self._pending_save_count += 1
        if self._pending_save_count >= self._save_interval:
            self._flush()

    def _flush(self) -> None:
        if self._state is None or not self._dirty:
            return
        self._state.touch()
        self._state_path.write_text(json.dumps(self._state.to_json(), indent=2, default=str), encoding="utf-8")
        self._dirty = False
        self._pending_save_count = 0

    def save(self) -> None:
        self._flush()

    def load(self) -> SessionState | None:
        if not self._state_path.exists():
            return None
        try:
            data = json.loads(self._state_path.read_text(encoding="utf-8"))
            self._state = SessionState.from_json(data)
            return self._state
        except (json.JSONDecodeError, KeyError, TypeError):
            return None

    def record_action(self, action: str, result: str, success: bool = False) -> None:
        if self._state is None:
            return
        self._state.total_actions += 1
        if success:
            self._state.successful_exploits += 1
        self._state.context_history.append(
            {
                "timestamp": time.time(),
                "action": action,
                "result": result[:1000],
                "success": success,
            }
        )
        if len(self._state.context_history) > 100:
            self._state.context_history = take_last(self._state.context_history, 100)
        self._mark_dirty()

    def record_phase(self, phase: str) -> None:
        if self._state is None:
            return
        self._state.current_phase = phase
        self._mark_dirty()

    def record_loot(self, loot_type: str, data: dict[str, Any]) -> None:
        if self._state is None:
            return
        self._state.loot.append(
            {
                "timestamp": time.time(),
                "type": loot_type,
                "data": data,
            }
        )
        self._mark_dirty()

    def record_credentials(self, host: str, username: str, password: str, source: str) -> None:
        if self._state is None:
            return
        self._state.credentials.append(
            {
                "timestamp": time.time(),
                "host": host,
                "username": username,
                "password": password,
                "source": source,
            }
        )
        self._mark_dirty()

    def mark_compromised(self, host: str) -> None:
        if self._state is None:
            return
        if host not in self._state.compromised_hosts:
            self._state.compromised_hosts.append(host)
            self._mark_dirty()

    def get_context_summary(self) -> str:
        """Generate a running summary for context compaction."""
        if self._state is None:
            return "No session state."
        lines = [
            f"Session: {self._state.session_id}",
            f"Target: {self._state.target_ip}",
            f"Phase: {self._state.current_phase}",
            f"Actions: {self._state.total_actions}",
            f"Successful Exploits: {self._state.successful_exploits}",
            f"Compromised Hosts: {', '.join(self._state.compromised_hosts) or 'None'}",
        ]
        if self._state.credentials:
            lines.append(f"Credentials Found: {len(self._state.credentials)}")
        if self._state.loot:
            lines.append(f"Loot Items: {len(self._state.loot)}")
        lines.append("Recent Context:")
        for entry in take_last(self._state.context_history, 10):
            status = "✓" if entry["success"] else "✗"
            lines.append(f"  [{status}] {entry['action']}: {entry['result'][:100]}")
        return "\n".join(lines)

    def build_resume_messages(
        self,
        system_prompt: str,
    ) -> list[dict[str, Any]]:
        """Reconstitute message history for the LLM from saved state."""
        # ponytail: long-session mode persisted the already-compacted messages
        # (system + memory + summary + recent turns via _build_compacted_messages).
        # Return them verbatim instead of the lossy condensed rebuild. Old state
        # files / non-long runs have persist_messages=False → empty list → fall
        # through to the existing rebuild (backward compat).
        if self._state and self._state.persist_messages and self._state.messages:
            return list(self._state.messages)
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": system_prompt},
            {
                "role": "user",
                "content": f"Resuming active exploitation session.\n{self.get_context_summary()}\nContinue from where you left off.",
            },
        ]
        # Add recent context as condensed tool results
        if self._state:
            for entry in take_last(self._state.context_history, 20):
                messages.append(
                    {
                        "role": "tool",
                        "tool_name": entry["action"],
                        "content": f"[{'SUCCESS' if entry['success'] else 'FAILED'}] {entry['result'][:300]}",
                    }
                )
        return messages


def _load_resume_state(reports_dir: Path, args: argparse.Namespace) -> tuple[ReconAssessment, str, str] | None:
    """M21: on a successful --resume, reload the saved recon assessment and
    the operator's previously chosen goal so the resumed run reuses them
    instead of re-running recon and re-asking for a goal.

    Reads ``reports_dir / 'recon_assessment.json'`` (written by
    ``run_recon_assessment`` and annotated with ``chosen_goal`` /
    ``chosen_goal_description`` by the recon-first block). Falls back to
    ``args.goal`` / ``args.custom_goal`` when the saved goal keys are absent so
    a run that was started without recon-first can still resume cleanly.

    Returns ``None`` when there is nothing to restore (no file / unreadable),
    so callers can simply skip the override.
    """
    path = reports_dir / "recon_assessment.json"
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    try:
        assessment = ReconAssessment.from_dict(data)
    except Exception:
        return None
    goal_name = str(data.get("chosen_goal") or getattr(args, "goal", "") or "").strip()
    goal_desc = str(data.get("chosen_goal_description") or getattr(args, "custom_goal", "") or "").strip()
    return assessment, goal_name, goal_desc


# ---------------------------------------------------------------------------
# Facade: one object for the whole memory stack.
# ---------------------------------------------------------------------------


class MemoryService:
    """Single facade over the per-attempt window, cross-mission store,
    checkpoint/resume, and Bayesian confidence.

    Best-effort wiring mirrors the exploit-loop bootstrap
    (``tools/exploit_agent/runner/_impl.py``): sub-stores that cannot be built
    (no DB, no embedding provider) stay ``None`` and their methods return the
    same neutral values the unwired path already produces (``0.5`` / ``[]`` /
    ``None`` / ``""``) instead of raising.
    """

    def __init__(
        self,
        workspace: Path,
        session_id: str = "default",
        target_ip: str = "",
        db: DatabaseManager | None = None,
        *,
        min_samples: int = 3,
        time_decay_days: float = 90.0,
        embedding_provider: EmbeddingProvider | None = None,
    ) -> None:
        self.workspace = Path(workspace)
        self.session_manager = SessionManager(self.workspace)
        self.attack_memory = AttackMemoryStore(self.workspace, session_id, target_ip)
        if db is not None:
            self.experience_store: ExperienceStore | None = ExperienceStore(
                db, min_samples=min_samples, time_decay_days=time_decay_days
            )
        else:
            self.experience_store = None
        if db is not None and embedding_provider is not None:
            self.semantic_memory: SemanticMemoryManager | None = SemanticMemoryManager(
                db, embedding_provider=embedding_provider
            )
        else:
            self.semantic_memory = None

    # ── Checkpoint / resume ───────────────────────────────────────────

    @property
    def session(self) -> SessionState | None:
        """The currently loaded checkpoint state, if any."""
        return self.session_manager._state

    def resume_or_new(self, **kwargs: Any) -> SessionState:
        """Resume the checkpointed session for the target or start a new one."""
        return self.session_manager.resume_or_new(**kwargs)  # type: ignore[arg-type]

    def new_session(self, **kwargs: Any) -> SessionState:
        """Start a fresh checkpointed session."""
        return self.session_manager.new_session(**kwargs)  # type: ignore[arg-type]

    def checkpoint(self) -> None:
        """Flush pending checkpoint state to ``session_state.json``."""
        self.session_manager.save()

    def build_resume_messages(self, system_prompt: str) -> list[dict[str, Any]]:
        """Reconstitute message history for the LLM from saved state."""
        return self.session_manager.build_resume_messages(system_prompt)

    def get_context_summary(self) -> str:
        """Generate a running summary for context compaction."""
        return self.session_manager.get_context_summary()

    def record_action(self, action: str, result: str, success: bool = False) -> None:
        self.session_manager.record_action(action, result, success)

    def record_phase(self, phase: str) -> None:
        self.session_manager.record_phase(phase)

    @staticmethod
    def load_resume_state(reports_dir: Path, args: argparse.Namespace) -> tuple[ReconAssessment, str, str] | None:
        """Reload a saved recon assessment + chosen goal (CLI ``--resume``)."""
        return _load_resume_state(reports_dir, args)

    # ── Per-attempt window ────────────────────────────────────────────

    def capture_tool_result(
        self,
        tool_name: str,
        result_text: str,
        success: bool,
        command: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> int:
        """Extract and persist useful facts from one tool result."""
        return self.attack_memory.capture_tool_result(tool_name, result_text, success, command, metadata)

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
        """Persist one tactical note to the per-attempt window."""
        return self.attack_memory.capture_note(
            category, key, value, source_tool=source_tool, success=success, metadata=metadata
        )

    def format_attack_context(self, max_items: int = 40, max_chars: int = 6000) -> str:
        """Return a compact per-attempt memory block for prompt injection."""
        return self.attack_memory.format_context(max_items, max_chars)

    def list_attack_items(self, category: str | None = None, limit: int = 200) -> list[AttackMemoryItem]:
        """List tactical items in the per-attempt window."""
        return self.attack_memory.list_items(category, limit)

    # ── Cross-mission lessons ─────────────────────────────────────────

    def store_lesson(
        self,
        target_signature: str,
        action_type: str,
        outcome: str,
        text: str,
        metadata: dict[str, Any] | None = None,
        confidence: float = 0.5,
    ) -> str | None:
        """Store a learned lesson; ``None`` when the semantic store is unwired."""
        if self.semantic_memory is None:
            return None
        return self.semantic_memory.store_lesson(target_signature, action_type, outcome, text, metadata, confidence)

    def find_similar_lessons(
        self,
        text: str,
        action_type: str | None = None,
        outcome: str | None = None,
        top_k: int = 5,
    ) -> list[dict[str, Any]]:
        """Find top-k cross-mission lessons; ``[]`` when unwired."""
        if self.semantic_memory is None:
            return []
        return self.semantic_memory.find_similar_lessons(text, action_type, outcome, top_k)

    def find_similar(
        self,
        text: str,
        source_table: str | None = None,
        top_k: int = 5,
        mission_id: str | None = None,
    ) -> list[dict[str, Any]]:
        """Find top-k similar embeddings; ``[]`` when unwired."""
        if self.semantic_memory is None:
            return []
        return self.semantic_memory.find_similar(text, source_table, top_k, mission_id)

    # ── Bayesian confidence ───────────────────────────────────────────

    def record_outcome(
        self,
        target_signature: str,
        action_type: str,
        outcome: str,
        metadata: dict[str, Any] | None = None,
        *,
        action_suffix: str = "",
    ) -> str:
        """Record an outcome observation; ``""`` when the store is unwired."""
        if self.experience_store is None:
            return ""
        return self.experience_store.record_outcome(
            target_signature, action_type, outcome, metadata, action_suffix=action_suffix
        )

    def get_confidence(self, target_signature: str, action_type: str) -> float:
        """Bayesian confidence; neutral ``0.5`` when unwired or thin data."""
        if self.experience_store is None:
            return 0.5
        return self.experience_store.get_confidence(target_signature, action_type)

    def get_best_action(self, target_signature: str, candidates: list[str]) -> tuple[str, float] | None:
        """Highest-confidence candidate; ``None`` when unwired or no candidates."""
        if self.experience_store is None:
            return None
        return self.experience_store.get_best_action(target_signature, candidates)

    def get_all_confidences(self, target_signature: str) -> dict[str, float]:
        """Confidence scores for all known actions; ``{}`` when unwired."""
        if self.experience_store is None:
            return {}
        return self.experience_store.get_all_confidences(target_signature)

    def observation_count(self, target_signature: str, action_type: str) -> int:
        """Decisive-outcome row count; ``0`` when unwired."""
        if self.experience_store is None:
            return 0
        return self.experience_store.observation_count(target_signature, action_type)


__all__ = [
    "ATTACK_MEMORY_DB",
    "AttackMemoryItem",
    "AttackMemoryStore",
    "ExperienceStore",
    "MemoryService",
    "SemanticMemoryManager",
    "SessionManager",
    "SessionState",
    "_load_resume_state",
    "beta_mean",
    "cap_text",
    "cosine_similarity",
    "decay_weight",
    "one_line",
    "take_last",
]
