import { memo } from "react";
import { Link } from "react-router-dom";
import { AlertTriangle, CheckCircle2, FileStack, Loader2, Play, Square } from "lucide-react";
import { formatRelative } from "@/lib/utils";
import { fmtElapsed } from "@/lib/format";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { phaseInfo, PHASE_ORDER, type DerivedRun } from "@/lib/deriveRun";
import type { RunDetail, RunState } from "@/api/types";

interface RunOutcomeCardProps {
  run: RunDetail;
  state: RunState;
  derived: DerivedRun;
  onShowSummary: () => void;
  onResume: () => void;
  resumePending: boolean;
}

/**
 * "What happened" — the hero card for terminal runs. Shifts the hierarchy
 * from live activity to outcome: result, duration, tool/artifact counts, and
 * the path back to the summary tab. Failed/cancelled runs clearly show the
 * reason and the phase where execution stopped.
 */
export const RunOutcomeCard = memo(function RunOutcomeCard({
  run,
  state,
  derived,
  onShowSummary,
  onResume,
  resumePending,
}: RunOutcomeCardProps) {
  const result = run.result ?? {};
  const ok = state === "completed";
  const failed = state === "failed";
  const cancelled = state === "cancelled";
  const interrupted = state === "interrupted";

  const finalTel = result.telemetry ?? derived.lastTelemetry ?? null;
  const finalTokens = finalTel?.total_tokens ?? null;
  const finalCalls = finalTel?.calls ?? null;
  const reachedPhase =
    derived.lastReachedIndex >= 1
      ? phaseInfo(PHASE_ORDER[derived.lastReachedIndex]).label
      : null;

  return (
    <Card
      className={
        ok
          ? "border-emerald-500/40 bg-emerald-500/[0.05]"
          : failed
            ? "border-destructive/40 bg-destructive/[0.05]"
            : "border-border"
      }
    >
      <CardHeader className="pb-2">
        <CardTitle className="flex items-center gap-2 text-base">
          {ok ? (
            <CheckCircle2 className="h-5 w-5 text-emerald-400" aria-hidden />
          ) : failed ? (
            <AlertTriangle className="h-5 w-5 text-red-400" aria-hidden />
          ) : (
            <Square className="h-4 w-4 text-muted-foreground" aria-hidden />
          )}
          <span>
            {ok
              ? "Run completed"
              : failed
                ? "Run failed"
                : cancelled
                  ? "Run cancelled"
                  : interrupted
                    ? "Run interrupted"
                    : "Run ended"}
          </span>
          {(cancelled || interrupted) && run.cancelled_at && (
            <Badge variant="outline" className="text-[10px] font-normal">
              {formatRelative(run.cancelled_at)}
            </Badge>
          )}
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-2.5 text-sm">
        {ok && result.outcome_summary && (
          <div className="whitespace-pre-wrap break-words rounded-md border border-emerald-500/30 bg-emerald-500/10 p-2.5 text-xs text-emerald-100">
            {result.outcome_summary}
          </div>
        )}
        {failed && (
          <div className="space-y-1.5">
            <div className="whitespace-pre-wrap break-words rounded-md border border-destructive/40 bg-destructive/10 p-2.5 text-xs text-red-200">
              {String(result.error ?? run.error ?? "The run ended with an unreported error.")}
            </div>
            {reachedPhase && (
              <p className="text-xs text-muted-foreground">
                Reached phase: <span className="font-mono text-foreground">{reachedPhase}</span>
              </p>
            )}
          </div>
        )}
        {(cancelled || interrupted) && (
          <p className="text-xs text-muted-foreground">
            The run stopped at the next agent boundary. Progress up to that point is preserved in the event log
            below.
          </p>
        )}

        <div className="grid grid-cols-2 gap-2 font-mono text-xs sm:grid-cols-4">
          <OutcomeStat
            label="duration"
            value={derived.elapsedSeconds != null ? fmtElapsed(derived.elapsedSeconds) : "—"}
          />
          <OutcomeStat label="actions" value={String(result.total_actions ?? derived.actions ?? "—")} />
          <OutcomeStat label="tools" value={String(derived.toolCount)} />
          <OutcomeStat label="artifacts" value={String(derived.artifacts)} />
        </div>

        <div className="flex flex-wrap items-center gap-2 pt-1">
          {(failed || cancelled || interrupted) && (
            <Button size="sm" onClick={onResume} disabled={resumePending}>
              {resumePending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />}
              Resume
            </Button>
          )}
          <Button size="sm" variant={ok ? "default" : "outline"} onClick={onShowSummary}>
            View summary
          </Button>
          <Button asChild size="sm" variant="outline">
            <Link to={`/runs/${run.id}/artifacts`}>
              <FileStack className="mr-1.5 h-3.5 w-3.5" aria-hidden />
              Artifacts
            </Link>
          </Button>
          {(finalTokens != null || finalCalls != null) && (
            <span className="ml-auto inline-flex items-center gap-1 text-[10px] text-muted-foreground">
              final: {finalTokens != null ? finalTokens.toLocaleString() : "—"} tokens
              {finalCalls != null ? ` · ${finalCalls} calls` : ""}
            </span>
          )}
        </div>
      </CardContent>
    </Card>
  );
});

function OutcomeStat({ label, value }: { label: string; value: string }) {
  return (
    <div className="space-y-0.5 rounded-md border bg-card/40 p-1.5">
      <div className="text-[10px] uppercase tracking-wide text-muted-foreground">{label}</div>
      <div className="tabular-nums text-foreground">{value}</div>
    </div>
  );
}
