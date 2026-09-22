import { AlertTriangle } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import type { BenchmarkRunState } from "./useBenchmarkRun";

export function BenchmarkRunBanners({ page }: { page: BenchmarkRunState }) {
  const {
    orphaned,
    showProvisionBanner,
    showSandboxBanner,
    summary,
    displayTrials,
    provisionFailed,
    sandboxFailed,
    infraDetail,
  } = page;
  return (
    <>
      {orphaned && (
        <Card className="border-amber-500/30 bg-amber-500/5" data-testid="benchmark-interrupted-banner">
          <CardContent className="flex flex-wrap items-center gap-3 py-3">
            <AlertTriangle className="h-4 w-4 shrink-0 text-amber-400" />
            <span className="text-sm font-medium text-amber-400">Run interrupted</span>
            <span className="min-w-0 flex-1 text-xs text-muted-foreground">
              The run's status stayed “running”, but no benchmark runner currently owns it — the daemon was most
              likely restarted mid-run. Trials completed before the interruption are kept below; the run cannot be
              resumed or cancelled.
            </span>
          </CardContent>
        </Card>
      )}

      {showProvisionBanner && (
        <Card className="border-amber-500/30 bg-amber-500/5" data-testid="benchmark-infra-banner">
          <CardContent className="flex flex-wrap items-center gap-3 py-3">
            <AlertTriangle className="h-4 w-4 shrink-0 text-amber-400" />
            <span className="text-sm font-medium text-amber-400">Lab targets were unreachable</span>
            <span className="min-w-0 flex-1 text-xs text-muted-foreground">
              This run finished in seconds without attempting any exploitation — {provisionFailed} of {summary?.trials_total ?? displayTrials.length} trial(s)
              failed as INFRASTRUCTURE_ERROR / TARGET_PROVISION_FAILED. That says the lab was down, nothing about
              exploitation ability. Start the lab suite, then run the benchmark again:
              <span className="mt-1 block rounded bg-black/30 p-1.5 font-mono text-[11px] break-all">
                docker compose -f eval_targets/docker-compose.yml up -d
              </span>
              {infraDetail && <span className="mt-1 block font-mono text-[11px] break-all">{infraDetail}</span>}
            </span>
          </CardContent>
        </Card>
      )}

      {showSandboxBanner && (
        <Card className="border-amber-500/30 bg-amber-500/5" data-testid="benchmark-sandbox-banner">
          <CardContent className="flex flex-wrap items-center gap-3 py-3">
            <AlertTriangle className="h-4 w-4 shrink-0 text-amber-400" />
            <span className="text-sm font-medium text-amber-400">Sandbox unavailable</span>
            <span className="min-w-0 flex-1 text-xs text-muted-foreground">
              {sandboxFailed} of {summary?.trials_total ?? displayTrials.length} trial(s) failed as INFRASTRUCTURE_ERROR
              / SANDBOX_FAILED — the sandbox was required but unreachable, so no exploitation was attempted (there is
              no host-execution fallback). Check <span className="font-mono">sandbox.enabled</span> and the worker
              image, then run again.
              {infraDetail && <span className="mt-1 block font-mono text-[11px] break-all">{infraDetail}</span>}
            </span>
          </CardContent>
        </Card>
      )}
    </>
  );
}

export function BenchmarkLiveStrip({ page }: { page: BenchmarkRunState }) {
  const { isActiveRun, activeTrial, liveHint, phases } = page;
  if (!isActiveRun || !(activeTrial ?? liveHint)) return null;
  return (
    <div className="flex flex-wrap items-center gap-3 rounded-md border bg-card/40 px-2.5 py-1.5 text-sm">
      <span className="font-mono text-xs font-medium">
        {activeTrial?.scenario_id ?? liveHint?.scenario_id ?? "…"}
      </span>
      <span className="text-xs text-muted-foreground">
        {activeTrial ? `trial ${activeTrial.trial_index + 1}` : "in progress"}
      </span>
      <div className="flex gap-1.5" aria-label="Phases">
        {phases.map((p) => (
          <span
            key={p.label}
            className={
              p.state === "done"
                ? "rounded bg-emerald-500/15 px-1.5 py-0.5 text-xs text-emerald-500"
                : p.state === "running"
                  ? "rounded bg-yellow-500/15 px-1.5 py-0.5 text-xs text-yellow-300"
                  : "rounded bg-muted px-1.5 py-0.5 text-xs text-muted-foreground"
            }
          >
            {p.label} {p.state === "done" ? "✓" : p.state === "running" ? "●" : "○"}
          </span>
        ))}
      </div>
      <span className="ml-auto text-xs tabular-nums text-muted-foreground">
        {activeTrial ? (
          <>
            actions: {activeTrial.tool_calls} ·{" "}
            {activeTrial.sandbox.enabled ? "sandbox healthy" : "sandbox disabled"}
          </>
        ) : (
          <>trial {liveHint?.trial_id ?? "starting…"}</>
        )}
      </span>
    </div>
  );
}
