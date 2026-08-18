import { memo } from "react";
import { Loader2, Check } from "lucide-react";
import { cn } from "@/lib/utils";
import type { RunEvent, RunState } from "@/api/types";
import { isTerminalState } from "@/api/types";

interface PhaseTrackerProps {
  events: RunEvent[];
  runState?: RunState;
  className?: string;
}

interface PhaseInfo {
  key: string;
  label: string;
  summary: string;
}

const PHASES: Record<string, PhaseInfo> = {
  starting: { key: "starting", label: "Starting", summary: "Booting the agent and MCP tools" },
  recon: { key: "recon", label: "Recon", summary: "Finding what services it's running" },
  service_enumeration: { key: "service_enumeration", label: "Enumeration", summary: "Probing each open port for versions and banners" },
  vulnerability_research: { key: "vulnerability_research", label: "Vuln Research", summary: "Matching findings to known CVEs and exploits" },
  validation: { key: "validation", label: "Validation", summary: "Running exploits to confirm access" },
  reporting: { key: "reporting", label: "Reporting", summary: "Writing up findings and audit trail" },
  research_assistant: { key: "research_assistant", label: "Researching", summary: "Consulting web/CVE sources for context" },
};

const PHASE_ORDER = [
  "starting",
  "recon",
  "service_enumeration",
  "vulnerability_research",
  "validation",
  "reporting",
];

function infoFor(phase: string): PhaseInfo {
  return PHASES[phase] ?? { key: phase, label: phase, summary: "Working" };
}

export const PhaseTracker = memo(function PhaseTracker({ events, runState, className }: PhaseTrackerProps) {
  const currentPhase = deriveCurrentPhase(events);
  const terminal = isTerminalState(runState as RunState);
  const info = infoFor(currentPhase);
  const orderIndex = PHASE_ORDER.indexOf(currentPhase);
  const showSpinner = !terminal && currentPhase !== "reporting";

  return (
    <div className={cn("flex flex-col gap-2 rounded-lg border bg-card/60 p-3", className)}>
      <div className="flex items-center gap-2">
        {showSpinner ? (
          <Loader2 className="h-4 w-4 animate-spin text-primary" />
        ) : (
          <Check className="h-4 w-4 text-emerald-400" />
        )}
        <div className="min-w-0 flex-1">
          <div className="flex items-baseline gap-2">
            <span className="text-xs uppercase tracking-wide text-muted-foreground">Phase</span>
            <span className="font-mono text-sm text-foreground">{info.label}</span>
          </div>
          <div className="truncate text-xs text-muted-foreground">{info.summary}</div>
        </div>
      </div>

      <div
        className="flex items-center gap-1"
        role="progressbar"
        aria-valuenow={orderIndex >= 0 ? orderIndex + 1 : 0}
        aria-valuemin={0}
        aria-valuemax={PHASE_ORDER.length}
        aria-label="Phase progress"
      >
        {PHASE_ORDER.filter((p) => p !== "starting").map((p) => {
          const idx = PHASE_ORDER.indexOf(p);
          const pInfo = infoFor(p);
          // ponytail: orderIndex === -1 (phase not in PHASE_ORDER, e.g.
          // research_assistant) shows no current segment; nearest prior
          // segment highlighting is skipped as it adds little for a rare case.
          const isDone = terminal || (orderIndex > idx && orderIndex >= 0);
          const isCurrent = p === currentPhase;
          return (
            <div
              key={p}
              title={pInfo.summary}
              className={cn(
                "h-1.5 flex-1 rounded-full transition-colors",
                isCurrent && "bg-primary",
                isDone && !isCurrent && "bg-emerald-500/70",
                !isCurrent && !isDone && "bg-muted-foreground/20",
              )}
            />
          );
        })}
      </div>
    </div>
  );
});

function deriveCurrentPhase(events: RunEvent[]): string {
  let phase = "starting";
  for (let i = 0; i < events.length; i++) {
    const ev = events[i];
    if (ev.type === "phase" && typeof ev.payload.phase === "string" && ev.payload.phase) {
      phase = ev.payload.phase as string;
    } else if (ev.type === "progress" && typeof ev.payload.phase === "string" && ev.payload.phase) {
      phase = ev.payload.phase as string;
    }
  }
  return phase;
}