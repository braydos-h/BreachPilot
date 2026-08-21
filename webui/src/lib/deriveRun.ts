import type { RunEvent, RunResultTelemetry } from "@/api/types";

// ── Phase vocabulary ─────────────────────────────────────────────────────────
// Mirrors tools/exploit_agent/loop.py PHASE_ORDER plus the two out-of-sequence
// phases (starting during boot, research_assistant during a peer consult).

export interface PhaseInfo {
  key: string;
  label: string;
  short: string;
  summary: string;
}

export const PHASES: Record<string, PhaseInfo> = {
  starting: { key: "starting", label: "Starting", short: "Start", summary: "Booting the agent and MCP tools" },
  recon: { key: "recon", label: "Recon", short: "Recon", summary: "Finding what services it's running" },
  service_enumeration: { key: "service_enumeration", label: "Enumeration", short: "Enumeration", summary: "Probing each open port for versions and banners" },
  vulnerability_research: { key: "vulnerability_research", label: "Vuln Research", short: "Vuln Research", summary: "Matching findings to known CVEs and exploits" },
  validation: { key: "validation", label: "Validation", short: "Validation", summary: "Running exploits to confirm access" },
  reporting: { key: "reporting", label: "Reporting", short: "Report", summary: "Writing up findings and audit trail" },
  research_assistant: { key: "research_assistant", label: "Researching", short: "Research", summary: "Consulting web/CVE sources for context" },
};

export const PHASE_ORDER = [
  "starting",
  "recon",
  "service_enumeration",
  "vulnerability_research",
  "validation",
  "reporting",
];

/** The 5 visible stepper steps (boot "starting" is not a step). */
export const STEP_PHASES = PHASE_ORDER.filter((p) => p !== "starting");

export function phaseInfo(phase: string): PhaseInfo {
  return PHASES[phase] ?? { key: phase, label: phase, short: phase, summary: "Working" };
}

/** Last phase the backend announced, from phase + progress events. */
export function deriveCurrentPhase(events: RunEvent[]): string {
  let phase = "starting";
  for (let i = 0; i < events.length; i++) {
    const ev = events[i];
    if (ev.type === "phase" && typeof ev.payload.phase === "string" && ev.payload.phase) {
      phase = ev.payload.phase;
    } else if (ev.type === "progress" && typeof ev.payload.phase === "string" && ev.payload.phase) {
      phase = ev.payload.phase;
    }
  }
  return phase;
}

export interface ToolSnapshot {
  name: string;
  action: number | null;
  phase: string | null;
  round: number | null;
  /** Present only for tool_request (the raw arguments). */
  args?: string;
  started: boolean;
  completed: boolean;
  success: boolean | null;
  exitCode: number | null;
  startedAt: string | null;
  endedAt: string | null;
}

export interface DerivedRun {
  phase: string;
  /** PHASE_ORDER index of the current phase, -1 when out of sequence. */
  phaseIndex: number;
  /** Highest PHASE_ORDER index ever reached (for terminal "reached" display). */
  lastReachedIndex: number;
  round: number | null;
  actions: number | null;
  elapsedSeconds: number | null;
  source: "agent" | "swarm" | null;
  lastAssistant: string;
  lastAssistantAt: string | null;
  assistantCount: number;
  /** A tool that started but hasn't produced a result yet (running/waiting). */
  currentTool: ToolSnapshot | null;
  /** The most recent tool activity (request/start/result). */
  lastTool: ToolSnapshot | null;
  toolCount: number;
  toolErrors: number;
  bootDone: number;
  bootTotal: number;
  bootFailed: number;
  artifacts: number;
  /** Count of error events (not just tool errors). */
  errorEvents: number;
  tokens: number | null;
  lastTelemetry: RunResultTelemetry | null;
  telemetrySeries: Array<{ tokens: number; ctxPct: number | null }>;
  eventsPerMin: number | null;
  /** Timestamp of the last event that is not a heartbeat. */
  lastMeaningfulAt: string | null;
  lastEventType: string | null;
}

function argsSummary(args: unknown): string {
  if (!args || typeof args !== "object") return "";
  const entries = Object.entries(args as Record<string, unknown>).slice(0, 4);
  const parts = entries.map(([k, v]) => {
    let s: string;
    if (typeof v === "string") s = v;
    else if (v == null) s = String(v);
    else if (typeof v === "object") s = JSON.stringify(v);
    else s = String(v);
    return `${k}=${s.length > 40 ? `${s.slice(0, 37)}…` : s}`;
  });
  return parts.join(" · ");
}

/**
 * Single-pass derivation over the live (append-only, capped) event buffer.
 * One scan produces everything the header, Now card, telemetry card, phase
 * stepper and rail summary need — no repeated passes, no per-consumer derives.
 */
export function deriveRunState(events: RunEvent[]): DerivedRun {
  let phase = "starting";
  let phaseIndex = -1;
  let lastReachedIndex = -1;
  let round: number | null = null;
  let actions: number | null = null;
  let elapsedSeconds: number | null = null;
  let source: "agent" | "swarm" | null = null;
  let lastAssistant = "";
  let lastAssistantAt: string | null = null;
  let assistantCount = 0;
  let toolCount = 0;
  let toolErrors = 0;
  let artifacts = 0;
  let errorEvents = 0;
  let tokens: number | null = null;
  let lastTelemetry: RunResultTelemetry | null = null;
  const telemetrySeries: Array<{ tokens: number; ctxPct: number | null }> = [];
  const bootSteps = new Map<string, boolean>();
  // Track tool calls by their backend `action` counter across
  // request → start → result so we can tell "running" from "finished".
  const requestByAction = new Map<number, { round: number | null; args?: string }>();
  const runningByAction = new Map<number, ToolSnapshot>();
  let lastTool: ToolSnapshot | null = null;
  let lastMeaningfulAt: string | null = null;
  let lastEventType: string | null = null;

  const notePhase = (p: unknown) => {
    if (typeof p !== "string" || !p) return;
    phase = p;
    const idx = PHASE_ORDER.indexOf(p);
    if (idx > lastReachedIndex) lastReachedIndex = idx;
  };

  for (let i = 0; i < events.length; i++) {
    const ev = events[i];
    const p = ev.payload ?? {};
    lastEventType = ev.type;
    if (ev.type !== "heartbeat") lastMeaningfulAt = ev.timestamp ?? lastMeaningfulAt;

    switch (ev.type) {
      case "progress": {
        notePhase(p.phase);
        if (typeof p.round === "number") round = p.round;
        if (typeof p.actions === "number") actions = p.actions;
        if (typeof p.elapsed_seconds === "number") elapsedSeconds = p.elapsed_seconds;
        if (p.source === "swarm") source = "swarm";
        else if (p.source === "agent") source = "agent";
        const tel = p.telemetry as RunResultTelemetry | undefined;
        if (tel && typeof tel === "object") {
          lastTelemetry = tel;
          if (typeof tel.total_tokens === "number") {
            tokens = tel.total_tokens;
            telemetrySeries.push({
              tokens,
              ctxPct: typeof tel.last_ctx_pct === "number" ? tel.last_ctx_pct : null,
            });
            if (telemetrySeries.length > 200) telemetrySeries.shift();
          }
        }
        break;
      }
      case "phase":
        notePhase(p.phase);
        break;
      case "assistant": {
        const txt = typeof p.text === "string" ? p.text : "";
        if (txt.trim()) {
          lastAssistant = txt;
          lastAssistantAt = ev.timestamp ?? null;
          assistantCount++;
        }
        break;
      }
      case "tool_request": {
        toolCount++;
        const name = typeof p.name === "string" ? p.name : "";
        const action = typeof p.action === "number" ? p.action : null;
        const req = {
          round: typeof p.round === "number" ? p.round : null,
          args: argsSummary(p.arguments),
        };
        if (action != null) requestByAction.set(action, req);
        if (name) {
          lastTool = {
            name,
            action,
            phase: typeof p.phase === "string" && p.phase ? p.phase : null,
            round: req.round,
            args: req.args,
            started: false,
            completed: false,
            success: null,
            exitCode: null,
            startedAt: null,
            endedAt: ev.timestamp ?? null,
          };
        }
        break;
      }
      case "tool_start": {
        const name = typeof p.name === "string" ? p.name : "";
        const action = typeof p.action === "number" ? p.action : null;
        const req = action != null ? requestByAction.get(action) : undefined;
        const snap: ToolSnapshot = {
          name: name || "tool",
          action,
          phase: typeof p.phase === "string" && p.phase ? p.phase : null,
          round: req?.round ?? null,
          args: req?.args,
          started: true,
          completed: false,
          success: null,
          exitCode: null,
          startedAt: ev.timestamp ?? null,
          endedAt: null,
        };
        if (action != null) runningByAction.set(action, snap);
        if (name) lastTool = snap;
        break;
      }
      case "tool_result": {
        const action = typeof p.action === "number" ? p.action : null;
        const running = action != null ? runningByAction.get(action) : undefined;
        const req = action != null ? requestByAction.get(action) : undefined;
        const completed: ToolSnapshot = {
          name: typeof p.name === "string" && p.name ? p.name : running?.name ?? "tool",
          action,
          phase: typeof p.phase === "string" && p.phase ? p.phase : running?.phase ?? null,
          round: running?.round ?? req?.round ?? null,
          args: running?.args ?? req?.args,
          started: true,
          completed: true,
          success: p.success === true,
          exitCode: typeof p.exit_code === "number" ? p.exit_code : null,
          startedAt: running?.startedAt ?? null,
          endedAt: ev.timestamp ?? null,
        };
        lastTool = completed;
        if (action != null) {
          runningByAction.delete(action);
          requestByAction.delete(action);
        }
        if (completed.success === false) toolErrors++;
        break;
      }
      case "boot":
      case "ok": {
        const step = typeof p.step === "string" && p.step ? p.step : "";
        if (step) {
          const ok = p.ok === true || ev.type === "ok";
          bootSteps.set(step, ok || (bootSteps.get(step) ?? false));
        }
        break;
      }
      case "artifact":
        artifacts++;
        break;
      case "error":
        errorEvents++;
        break;
      default:
        break;
    }
  }

  // Current tool = newest started-but-not-finished tool; else the most recent
  // not-completed request (a decision still pending or about to run).
  let currentTool: ToolSnapshot | null = null;
  for (const snap of runningByAction.values()) {
    if (!currentTool || (snap.action ?? -1) > (currentTool.action ?? -1)) currentTool = snap;
  }
  if (!currentTool && lastTool && !lastTool.completed) currentTool = lastTool;

  const bootDone = Array.from(bootSteps.values()).filter(Boolean).length;
  const bootFailed = Array.from(bootSteps.values()).filter((v) => !v).length;

  let eventsPerMin: number | null = null;
  if (events.length >= 2) {
    const first = events[0].timestamp ? Date.parse(events[0].timestamp) : NaN;
    const last = events[events.length - 1].timestamp ? Date.parse(events[events.length - 1].timestamp) : NaN;
    if (Number.isFinite(first) && Number.isFinite(last) && last > first) {
      const mins = (last - first) / 60000;
      eventsPerMin = mins > 0 ? Math.round(events.length / mins) : null;
    }
  }

  return {
    phase,
    phaseIndex: PHASE_ORDER.indexOf(phase),
    lastReachedIndex,
    round,
    actions,
    elapsedSeconds,
    source,
    lastAssistant,
    lastAssistantAt,
    assistantCount,
    currentTool,
    lastTool,
    toolCount,
    toolErrors,
    bootDone,
    bootTotal: bootSteps.size,
    bootFailed,
    artifacts,
    errorEvents,
    tokens,
    lastTelemetry,
    telemetrySeries,
    eventsPerMin,
    lastMeaningfulAt,
    lastEventType,
  };
}
