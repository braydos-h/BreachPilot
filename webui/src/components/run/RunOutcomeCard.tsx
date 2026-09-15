import { memo } from "react";
import { Link } from "react-router-dom";
import { AlertTriangle, CheckCircle2, FileStack, Loader2, Play, Square } from "lucide-react";
import { formatRelative } from "@/lib/utils";
import { fmtElapsed } from "@/lib/format";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { phaseInfo, PHASE_ORDER, type DerivedRun } from "@/lib/deriveRun";
import { TELEMETRY_LABELS } from "@/lib/terminology";
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
      ? phaseInfo(PHASE_ORDER[derived.lastReachedIndex] ?? "").label
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
      <CardHeader className="px-2.5 py-2 pb-1">
        <CardTitle className="flex items-center gap-1.5 text-xs">
          {ok ? (
            <CheckCircle2 className="h-4 w-4 text-emerald-400" aria-hidden />
          ) : failed ? (
            <AlertTriangle className="h-4 w-4 text-red-400" aria-hidden />
          ) : (
            <Square className="h-3.5 w-3.5 text-muted-foreground" aria-hidden />
          )}
          <span className="text-xs">
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
            <Badge variant="outline" className="text-xs font-normal leading-none">
              {formatRelative(run.cancelled_at)}
            </Badge>
          )}
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-1.5 px-2.5 pb-2 pt-0 text-xs">
        {ok && result.outcome_summary && (
          <div className="whitespace-pre-wrap break-words rounded border border-emerald-500/30 bg-emerald-500/10 px-2 py-1.5 text-[13px] leading-snug text-emerald-100">
            {result.outcome_summary}
          </div>
        )}
        {failed && (
          <div className="space-y-1">
            <div className="whitespace-pre-wrap break-words rounded border border-destructive/40 bg-destructive/10 px-2 py-1.5 text-[13px] leading-snug text-red-200">
              {String(result.error ?? run.error ?? "The run ended with an unreported error.")}
            </div>
            {reachedPhase && (
              <p className="text-xs leading-none text-muted-foreground">
                Reached: <span className="font-mono text-foreground">{reachedPhase}</span>
              </p>
            )}
          </div>
        )}
        {(cancelled || interrupted) && (
          <p className="text-[13px] leading-snug text-muted-foreground">
            Stopped at next agent boundary. Progress preserved in log.
          </p>
        )}

        <div className="grid grid-cols-5 gap-1 font-mono text-xs">
          <OutcomeStat
            label="Findings"
            value={String((result as Record<string, unknown>).findings_count ?? derived.artifacts ?? "—")}
          />
          <OutcomeStat
            label="Verified evidence"
            value={String((result as Record<string, unknown>).verified_count ?? "—")}
          />
          <OutcomeStat
            label={TELEMETRY_LABELS.duration}
            value={derived.elapsedSeconds != null ? fmtElapsed(derived.elapsedSeconds) : "—"}
          />
          <OutcomeStat label={TELEMETRY_LABELS.actions} value={String(result.total_actions ?? derived.actions ?? "—")} />
          <OutcomeStat label={TELEMETRY_LABELS.tokens} value={finalTokens != null ? finalTokens.toLocaleString() : "—"} />
        </div>

        <div className="flex flex-wrap items-center gap-1.5 pt-0.5">
          {(failed || cancelled || interrupted) && (
            <Button size="sm" className="h-7 text-[13px]" onClick={onResume} disabled={resumePending}>
              {resumePending ? <Loader2 className="h-3.5 w-3.5" /> : <Play className="h-3.5 w-3.5" />}
              Resume
            </Button>
          )}
          <Button size="sm" className="h-7 text-[13px]" variant={ok ? "default" : "outline"} onClick={onShowSummary}>
            Review findings
          </Button>
          <Button asChild size="sm" variant="default" className="h-7 text-[13px]">
            <Link to={`/runs/${run.id}/artifacts`}>
              <FileStack className="mr-1 h-3 w-3" aria-hidden />
              View report
            </Link>
          </Button>
          <Button asChild size="sm" variant="outline" className="h-7 text-[13px]">
            <Link to={`/runs/${run.id}?tab=evidence`}>Evidence</Link>
          </Button>
          <Button asChild size="sm" variant="outline" className="h-7 text-[13px]">
            <Link to={`/runs/${run.id}/graph`}>Attack path</Link>
          </Button>
          {failed && (
            <Button asChild size="sm" variant="outline" className="h-7 text-[13px] border-destructive/40 text-red-200">
              <Link to={`/runs/${run.id}/artifacts?log=session_error.log`}>
                View error log
              </Link>
            </Button>
          )}
          {(finalTokens != null || finalCalls != null) && (
            <span className="ml-auto inline-flex items-center gap-1 text-xs leading-none text-muted-foreground">
              {finalTokens != null ? finalTokens.toLocaleString() : "—"} Tokens
              {finalCalls != null ? ` · ${finalCalls} Calls` : ""}
            </span>
          )}
        </div>
      </CardContent>
    </Card>
  );
});

function OutcomeStat({ label, value }: { label: string; value: string }) {
  return (
    <div className="space-y-0 rounded border bg-card/40 px-1.5 py-1">
      <div className="text-xs uppercase tracking-wide text-muted-foreground">{label}</div>
      <div className="tabular-nums text-foreground">{value}</div>
    </div>
  );
}
