import { memo } from "react";
import { Link } from "react-router-dom";
import { Clock, Crosshair, FlaskConical, Loader2, Play, Square } from "lucide-react";
import { cn, formatRelative, truncateId } from "@/lib/utils";
import { fmtElapsed } from "@/lib/format";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { StatusBadge } from "@/components/StatusBadge";
import { CopyButton } from "@/components/CopyButton";
import { phaseInfo, type DerivedRun } from "@/lib/deriveRun";
import type { RunDetail, RunState } from "@/api/types";
import type { WsStatus } from "@/api/ws";

interface RunCommandHeaderProps {
  run: RunDetail;
  state: RunState;
  active: boolean;
  terminal: boolean;
  transportLabel: string;
  eventsStatus: WsStatus;
  derived: DerivedRun;
  onCancelRequest: () => void;
  cancelPending: boolean;
  onResume: () => void;
  resumePending: boolean;
}

/**
 * Run Command Center — the header every operator reads first. Target is the
 * strongest identifier; state, current phase, connection health and the
 * run-critical actions sit beside it. Run ID is deliberately not the hero.
 */
export const RunCommandHeader = memo(function RunCommandHeader({
  run,
  state,
  active,
  terminal,
  transportLabel,
  eventsStatus,
  derived,
  onCancelRequest,
  cancelPending,
  onResume,
  resumePending,
}: RunCommandHeaderProps) {
  const preview = run.preview ?? {};
  const request = run.request ?? {};
  const target = String(preview.original_target ?? request.target ?? preview.target_ip ?? "—");
  const resolvedIp =
    typeof preview.resolved_ip === "string" && preview.resolved_ip && preview.resolved_ip !== target
      ? preview.resolved_ip
      : typeof preview.target_ip === "string" && preview.target_ip !== target
        ? preview.target_ip
        : null;
  const phase = phaseInfo(derived.phase);

  return (
    <header className="rounded-lg border bg-card/50 p-3 md:p-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <Crosshair className="h-4 w-4 shrink-0 text-primary" aria-hidden />
            <h1 className="truncate font-mono text-xl font-semibold tracking-tight text-foreground">
              {target}
            </h1>
            {resolvedIpBadge(resolvedIp)}
            {state && <StatusBadge state={state} />}
            <Badge variant="info" className="gap-1 font-mono text-[10px] uppercase">
              {phase.label}
            </Badge>
            <ConnectionBadge state={eventsStatus} transportLabel={transportLabel} />
          </div>

          <div className="mt-1.5 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-muted-foreground">
            <span className="inline-flex items-center gap-1 font-mono">
              {truncateId(run.id, 12, 4)}
              <CopyButton value={run.id} size="icon" label="Copy run ID" />
            </span>
            <Meta k="mode" v={String(request.mode ?? preview.mode ?? "—")} />
            <Meta k="goal" v={String(preview.goal_name ?? request.goal_name ?? "—")} />
            <Meta k="model" v={String(preview.model_alias ?? request.model_alias ?? "—")} mono />
            <Meta k="permission" v={String(preview.permission ?? "—")} />
            <span className="inline-flex items-center gap-1">
              <Clock className="h-3 w-3" aria-hidden />
              <span className="text-muted-foreground/70">created</span>{" "}
              <span className="text-foreground">{formatRelative(run.created_at)}</span>
            </span>
            {derived.elapsedSeconds != null && (
              <span className="inline-flex items-center gap-1">
                <span className="text-muted-foreground/70">elapsed</span>{" "}
                <span className="font-mono tabular-nums text-foreground">
                  {fmtElapsed(derived.elapsedSeconds)}
                </span>
              </span>
            )}
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          {active && (
            <Button variant="destructive" size="sm" onClick={onCancelRequest} disabled={cancelPending}>
              {cancelPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Square className="h-4 w-4" />}
              Cancel
            </Button>
          )}
          {terminal && (
            <Button size="sm" onClick={onResume} disabled={resumePending}>
              {resumePending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />}
              Resume
            </Button>
          )}
          <Button asChild size="sm" variant="outline">
            <Link to={`/runs/${run.id}/artifacts`}>Artifacts</Link>
          </Button>
          <Button asChild size="sm" variant="outline">
            <Link to={`/runs/${run.id}/loot`}>Loot</Link>
          </Button>
        </div>
      </div>
    </header>
  );

  function resolvedIpBadge(ip: string | null) {
    if (!ip) return null;
    return (
      <span className="hidden items-center gap-1 font-mono text-xs text-muted-foreground sm:inline-flex" title={`Resolved IP: ${ip}`}>
        <FlaskConical className="h-3 w-3" aria-hidden />
        {ip}
      </span>
    );
  }
});

function Meta({ k, v, mono }: { k: string; v: string; mono?: boolean }) {
  return (
    <span className="inline-flex items-center gap-1">
      <span className="text-muted-foreground/70">{k}</span>{" "}
      <span className={cn("text-foreground", mono && "font-mono")}>{v}</span>
    </span>
  );
}

function ConnectionBadge({
  state,
  transportLabel,
}: {
  state: WsStatus;
  transportLabel: string;
}) {
  // State is communicated by text + icon, not color alone.
  const cfg =
    state === "open"
      ? { dot: "●", label: "Live", cls: "text-emerald-400", badge: "success" }
      : state === "connecting"
        ? { dot: "○", label: "Connecting", cls: "text-muted-foreground", badge: "secondary" }
        : state === "reconnecting"
          ? { dot: "◌", label: "Reconnecting", cls: "text-yellow-300", badge: "warn" }
          : state === "closed"
            ? { dot: "●", label: "Offline", cls: "text-muted-foreground", badge: "secondary" }
            : { dot: "⚠", label: "Error", cls: "text-destructive", badge: "danger" };
  return (
    <Badge
      variant={cfg.badge as "success" | "secondary" | "warn" | "danger"}
      className="gap-1 text-[10px]"
      title={`${cfg.label}${transportLabel ? ` · ${transportLabel}` : ""}`}
    >
      <span className={cn(cfg.cls, state === "reconnecting" && "animate-pulse")} aria-hidden>
        {cfg.dot}
      </span>
      <span>{cfg.label}</span>
      {transportLabel && <span className="text-muted-foreground/60">· {transportLabel}</span>}
    </Badge>
  );
}
