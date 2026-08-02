import { Activity, Cpu, ShieldCheck, ShieldAlert, Zap, FileText } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import type { RunResult } from "@/api/types";

interface SessionSummaryCardProps {
  result: RunResult;
  className?: string;
}

function safeNum(v: unknown, dft = 0): number {
  const n = Number(v);
  return Number.isFinite(n) ? n : dft;
}

export function SessionSummaryCard({ result, className }: SessionSummaryCardProps) {
  const actions = safeNum(result.total_actions);
  const telemetry = result.telemetry;
  const skills = result.active_skills ?? [];
  const safety = result.safety_review;
  const swarm = result.swarm_result;
  const hasError = !!result.error;
  const outcome = result.outcome_summary;

  return (
    <Card className={cn("border-border/60", className)}>
      <CardHeader className="pb-2">
        <CardTitle className="flex items-center gap-2 text-sm">
          <Activity className="h-4 w-4" />
          Session summary
          {hasError ? (
            <Badge variant="outline" className="border-red-500/40 bg-red-500/10 text-red-300">failed</Badge>
          ) : (
            <Badge variant="outline" className="border-emerald-500/40 bg-emerald-500/10 text-emerald-300">complete</Badge>
          )}
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-3 text-sm">
        <div className="grid grid-cols-2 gap-x-4 gap-y-1 font-mono text-xs sm:grid-cols-3">
          <div>
            <span className="text-muted-foreground">Goal: </span>
            <span className="text-foreground">{result.goal_name ?? "-"}</span>
          </div>
          <div>
            <span className="text-muted-foreground">Target: </span>
            <span className="text-foreground">{result.target_ip ?? "-"}</span>
          </div>
          <div>
            <span className="text-muted-foreground">Mode: </span>
            <span className="text-foreground">{result.mode ?? "-"}</span>
          </div>
          <div>
            <span className="text-muted-foreground">Actions: </span>
            <span className="text-foreground">{actions}</span>
          </div>
        </div>

        {outcome && (
          <div className="rounded-md border bg-muted/30 p-2 text-xs">
            <span className="text-muted-foreground">Outcome: </span>
            <span>{outcome}</span>
          </div>
        )}

        {hasError && (
          <div className="rounded-md border border-destructive/40 bg-destructive/10 p-2 text-xs text-red-200">
            <span className="font-semibold">Error: </span>
            {result.error}
          </div>
        )}

        {telemetry && (
          <div className="space-y-1 rounded-md border bg-card/40 p-2 text-xs">
            <div className="flex items-center gap-1.5 text-muted-foreground">
              <Cpu className="h-3.5 w-3.5" /> Model usage
            </div>
            <div className="grid grid-cols-2 gap-x-4 gap-y-0.5 font-mono sm:grid-cols-4">
              <div><span className="text-muted-foreground">tokens: </span>{safeNum(telemetry.total_tokens).toLocaleString()}</div>
              <div><span className="text-muted-foreground">calls: </span>{safeNum(telemetry.total_calls)}</div>
              <div><span className="text-muted-foreground">avg ctx: </span>{safeNum(telemetry.avg_ctx_pct)}%</div>
              <div><span className="text-muted-foreground">max ctx: </span>{safeNum(telemetry.max_ctx_pct)}%</div>
            </div>
          </div>
        )}

        {skills.length > 0 && (
          <div className="space-y-1 rounded-md border bg-card/40 p-2 text-xs">
            <div className="flex items-center gap-1.5 text-muted-foreground">
              <Zap className="h-3.5 w-3.5" /> Active skills ({skills.length})
            </div>
            <ul className="space-y-0.5 pl-4">
              {skills.map((s, i) => (
                <li key={i} className="text-muted-foreground">
                  - <span className="text-foreground">{s.name}</span> - {s.reason}
                </li>
              ))}
            </ul>
          </div>
        )}

        {safety && (
          <div className={cn(
            "space-y-1 rounded-md border p-2 text-xs",
            safety.safe ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-200" : "border-amber-500/40 bg-amber-500/10 text-amber-200",
          )}>
            <div className="flex items-center gap-1.5 font-semibold">
              {safety.safe ? <ShieldCheck className="h-3.5 w-3.5" /> : <ShieldAlert className="h-3.5 w-3.5" />}
              Safety review
            </div>
            {safety.reasoning && <p className="text-muted-foreground">{safety.reasoning}</p>}
            {safety.concerns && safety.concerns.length > 0 && (
              <div><span className="text-muted-foreground">Concerns:</span>
                <ul className="pl-4">{safety.concerns.map((c, i) => <li key={i}>- {c}</li>)}</ul>
              </div>
            )}
            {safety.recommended && safety.recommended.length > 0 && (
              <div><span className="text-muted-foreground">Recommended:</span>
                <ul className="pl-4">{safety.recommended.map((r, i) => <li key={i}>- {r}</li>)}</ul>
              </div>
            )}
          </div>
        )}

        {swarm && Object.keys(swarm).length > 0 && (
          <div className="space-y-1 rounded-md border bg-card/40 p-2 text-xs">
            <div className="text-muted-foreground">Swarm result</div>
            <pre className="overflow-auto font-mono text-[11px] scrollbar-thin">{JSON.stringify(swarm, null, 2)}</pre>
          </div>
        )}

        {(result.reports_dir || result.summary_path || result.audit_path) && (
          <div className="space-y-0.5 rounded-md border bg-card/40 p-2 text-xs">
            <div className="flex items-center gap-1.5 text-muted-foreground">
              <FileText className="h-3.5 w-3.5" /> Artifacts
            </div>
            {result.reports_dir && <div><span className="text-muted-foreground">reports dir: </span><span className="font-mono">{result.reports_dir}</span></div>}
            {result.summary_path && <div><span className="text-muted-foreground">summary: </span><span className="font-mono">{result.summary_path}</span></div>}
            {result.audit_path && <div><span className="text-muted-foreground">audit: </span><span className="font-mono">{result.audit_path}</span></div>}
          </div>
        )}
      </CardContent>
    </Card>
  );
}