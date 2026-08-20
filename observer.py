"""Observer agent — turns raw tool output into structured facts.

After every tool call, the Observer:
1. Extracts facts from raw output
2. Identifies new assets, endpoints, parameters, technologies
3. Detects interesting signals and possible findings
4. Marks dead ends
5. Creates follow-up task candidates
6. Updates memory and graph
7. Saves evidence references

The Observer does NOT claim vulnerabilities — only flags possible_findings
for the Finding Verifier to evaluate.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from tools.semantic_memory import SemanticMemoryManager

@dataclass
class Observation:
    """Structured output from the Observer after processing a tool result."""

    task_id: str = ""
    target: str = ""
    tool_name: str = ""
    input_summary: str = ""
    output_summary: str = ""

    facts: list[str] = field(default_factory=list)
    new_assets: list[str] = field(default_factory=list)
    new_endpoints: list[str] = field(default_factory=list)
    new_parameters: list[str] = field(default_factory=list)
    new_technologies: list[str] = field(default_factory=list)
    new_identities: list[str] = field(default_factory=list)
    new_objects: list[str] = field(default_factory=list)

    interesting_signals: list[str] = field(default_factory=list)
    possible_findings: list[dict[str, Any]] = field(default_factory=list)
    dead_ends: list[str] = field(default_factory=list)
    recommended_followup_tasks: list[dict[str, Any]] = field(default_factory=list)

    memory_updates: list[dict[str, Any]] = field(default_factory=list)
    graph_updates: list[dict[str, Any]] = field(default_factory=list)
    evidence_refs: list[str] = field(default_factory=list)
    # Explicit structured claims for OutcomeJudge. Entries use
    # {"polarity": "supports"|"contradicts", "claim": ..., "confidence": ...}.
    # The heuristic parsers intentionally do not manufacture these from raw
    # words such as "success"; tools or higher-level observers must provide a
    # concrete claim.
    hypothesis_evidence: list[dict[str, Any]] = field(default_factory=list)

    confidence: float = 0.0
    usefulness: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "target": self.target,
            "tool_name": self.tool_name,
            "input_summary": self.input_summary,
            "output_summary": self.output_summary,
            "facts": self.facts,
            "new_assets": self.new_assets,
            "new_endpoints": self.new_endpoints,
            "new_parameters": self.new_parameters,
            "new_technologies": self.new_technologies,
            "new_identities": self.new_identities,
            "new_objects": self.new_objects,
            "interesting_signals": self.interesting_signals,
            "possible_findings": self.possible_findings,
            "dead_ends": self.dead_ends,
            "recommended_followup_tasks": self.recommended_followup_tasks,
            "memory_updates": self.memory_updates,
            "graph_updates": self.graph_updates,
            "evidence_refs": self.evidence_refs,
            "hypothesis_evidence": self.hypothesis_evidence,
            "confidence": self.confidence,
            "usefulness": self.usefulness,
        }


class ObserverAgent:
    """Analyzes tool output and produces structured observations.

    This is a heuristic-based observer that uses regex patterns to extract
    structured information from common tool outputs (nmap, HTTP probes, etc.).
    It is designed to be replaced or augmented by an LLM-based observer
    when one is available.
    """

    def __init__(self, semantic_memory: SemanticMemoryManager | None = None) -> None:
        self._semantic = semantic_memory

    # ── Main entry point ───────────────────────────────────────────────

    def observe(
        self,
        task: dict[str, Any],
        raw_output: str,
        tool_name: str = "",
        prior_state: dict[str, Any] | None = None,
        evidence_refs: list[str] | None = None,
    ) -> Observation:
        """Process raw tool output into a structured Observation.

        Args:
            task: Task dict from the task queue (must contain task_id, target, objective, hypothesis, phase)
            raw_output: Raw output from the tool execution
            tool_name: Name of the tool that was executed
            prior_state: Optional prior target state for comparison
            evidence_refs: List of evidence IDs created for this execution

        Returns:
            Structured Observation
        """
        task_id = task.get("task_id", task.get("id", ""))
        target = task.get("target", "")

        # Basic metadata
        obs = Observation(
            task_id=task_id,
            target=target,
            tool_name=tool_name,
            input_summary=task.get("hypothesis", task.get("objective", ""))[:200],
            output_summary=_compact_output(raw_output),
            evidence_refs=evidence_refs or [],
        )

        # Extract structured information based on tool type
        if "nmap" in tool_name.lower() or "scan" in tool_name.lower():
            self._parse_nmap_output(obs, raw_output, target)
        elif "http" in tool_name.lower() or "web" in tool_name.lower() or "curl" in tool_name.lower():
            self._parse_http_output(obs, raw_output, target)
        elif "cve" in tool_name.lower() or "vuln" in tool_name.lower():
            self._parse_cve_output(obs, raw_output, target)
        elif "os" in tool_name.lower() or "check_os" in tool_name.lower():
            self._parse_os_output(obs, raw_output, target)
        else:
            self._parse_generic_output(obs, raw_output, target, tool_name)

        # Score usefulness based on what was found
        obs.usefulness = self._score_usefulness(obs)

        # Store embedding for semantic retrieval
        if self._semantic is not None:
            summary_text = f"{tool_name} on {target}: {obs.output_summary[:300]}"
            self._semantic.store_embedding(
                source_table="observations",
                source_id=task_id,
                text=summary_text,
            )

        # C4: populate the dead confidence field when parsers produced facts
        if obs.confidence == 0.0 and obs.evidence_refs:
            try:
                from tools.intelligence.adapters.observer_adapter import ObserverAdapter

                ObserverAdapter().infer_confidence(obs)
            except ImportError:
                pass

        return obs

    # ── Parsers ─────────────────────────────────────────────────────────

    @staticmethod
    def _parse_nmap_output(obs: Observation, output: str, target: str) -> None:
        # Extract open ports with services
        port_pattern = re.compile(
            r"(\d+)/(tcp|udp)\s+(\w+)\s+(\S.*?)(?:\s{2,}|\n|$)"
        )
        for m in port_pattern.finditer(output):
            port = m.group(1)
            proto = m.group(2)
            state = m.group(3)
            service_info = m.group(4).strip() if m.group(4) else ""
            fact = f"Port {port}/{proto} {state}: {service_info}"
            obs.facts.append(fact)
            obs.new_endpoints.append(f"{target}:{port}/{proto}")
            # Extract technology
            if service_info:
                obs.new_technologies.append(f"{service_info}")

        # OS detection
        if "OS details:" in output:
            os_line = output.split("OS details:", 1)[1].split("\n")[0].strip()
            obs.facts.append(f"Detected OS: {os_line}")
            obs.new_technologies.append(f"OS: {os_line}")

        # Interesting signals
        if "open" in output.lower() or "filtered" in output.lower():
            obs.interesting_signals.append("Open/filtered ports detected for further investigation")

    @staticmethod
    def _parse_http_output(obs: Observation, output: str, target: str) -> None:
        # HTTP status codes
        status_match = re.search(r"(HTTP/\d\.\d\s+)?(\d{3})\s", output)
        if status_match:
            code = status_match.group(2)
            if code != "200":
                obs.interesting_signals.append(f"HTTP status {code} on {target}")
            else:
                obs.facts.append(f"HTTP 200 OK on {target}")

        # Headers
        server_header = re.search(r"[Ss]erver:\s*(\S[^\r\n]*)", output)
        if server_header:
            tech = server_header.group(1).strip()
            obs.facts.append(f"Server header: {tech}")
            obs.new_technologies.append(tech)

        # Interesting header patterns
        if "X-Powered-By" in output:
            obs.new_technologies.append(
                output.split("X-Powered-By:", 1)[1].split("\n")[0].strip()
            )

        # Endpoints found
        url_pattern = re.findall(r'(?:GET|POST|PUT|DELETE|HEAD)\s+([^\s]+)', output)
        for u in url_pattern[:10]:
            if u not in obs.new_endpoints:
                obs.new_endpoints.append(u)

        # Sensitive file indicators
        for pattern in [".git", ".env", ".htaccess", "wp-config", "phpinfo"]:
            if pattern in output.lower():
                obs.interesting_signals.append(f"Possible sensitive file: {pattern}")

    @staticmethod
    def _parse_cve_output(obs: Observation, output: str, target: str) -> None:
        cve_ids = re.findall(r"CVE-\d{4}-\d{4,7}", output)
        for cve in cve_ids:
            obs.facts.append(f"CVE identified: {cve}")
            obs.new_technologies.append(cve)

        cvss_scores = re.findall(r"CVSS[^:]*:\s*(\d+\.?\d*)", output, re.IGNORECASE)
        for score in cvss_scores:
            try:
                if float(score) >= 7.0:
                    obs.interesting_signals.append(f"High severity CVE (CVSS {score}) affecting {target}")
                    obs.possible_findings.append({
                        "type": "cve_with_high_cvss",
                        "cve": cve_ids[0] if cve_ids else "unknown",
                        "cvss": float(score),
                        "target": target,
                    })
            except ValueError:
                pass

    @staticmethod
    def _parse_os_output(obs: Observation, output: str, target: str) -> None:
        if "WINDOWS" in output.upper():
            obs.facts.append(f"Target OS identified as Windows: {target}")
        elif "LINUX" in output.upper():
            obs.facts.append(f"Target OS identified as Linux: {target}")
        else:
            obs.facts.append(f"OS detection attempted for {target}: inconclusive")

        obs.new_technologies.append(output.strip().split("\n")[-1][:100])

    @staticmethod
    def _parse_generic_output(obs: Observation, output: str, target: str, tool_name: str) -> None:
        """Generic parser for unknown tool outputs."""
        if output:
            fact_count = min(3, output.count("\n"))
            for line in output.split("\n")[:fact_count]:
                line = line.strip()
                if line and len(line) < 200:
                    obs.facts.append(line)

        if "error" in output.lower() or "fail" in output.lower() or "timeout" in output.lower():
            obs.dead_ends.append(f"{tool_name} on {target}: encountered errors")
        elif "success" in output.lower() or "complete" in output.lower():
            obs.interesting_signals.append(f"{tool_name} on {target}: completed successfully")

    # ── Scoring ─────────────────────────────────────────────────────────

    @staticmethod
    def _score_usefulness(obs: Observation) -> int:
        score = 0
        if obs.facts:
            score += len(obs.facts)
        if obs.new_endpoints:
            score += len(obs.new_endpoints) * 2
        if obs.new_technologies:
            score += len(obs.new_technologies) * 2
        if obs.interesting_signals:
            score += len(obs.interesting_signals) * 3
        if obs.possible_findings:
            score += len(obs.possible_findings) * 5
        return min(score, 100)


# ── Helpers ─────────────────────────────────────────────────────────────────


def _compact_output(raw: str, max_len: int = 500) -> str:
    """Compress output to a readable snippet."""
    clean = raw.strip()
    if len(clean) <= max_len:
        return clean
    return clean[:max_len] + f"\n... [{len(clean) - max_len} more chars]"
