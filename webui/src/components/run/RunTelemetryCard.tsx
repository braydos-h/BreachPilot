import { memo } from "react";
import { Cpu } from "lucide-react";
import { cn } from "@/lib/utils";
import { formatTokens } from "@/lib/format";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Sparkline } from "@/components/run/Sparkline";
import type { DerivedRun } from "@/lib/deriveRun";
import type { RunResultTelemetry } from "@/api/types";

interface RunTelemetryCardProps {
  telemetry: RunResultTelemetry | null;
  derived: DerivedRun;
  className?: string;
}

type Level = "normal" | "high" | "critical";

function ctxLevel(pct: number): Level {
  if (pct < 70) return "normal";
  if (pct < 90) return "high";
  return "critical";
}

const LEVEL_META: Record<Level, { bar: string; label: string; badge: "success" | "warn" | "danger" }> = {
  normal: { bar: "bg-emerald-500", label: "Normal", badge: "success" },
  high: { bar: "bg-yellow-500", label: "Getting high", badge: "warn" },
  critical: { bar: "bg-red-500", label: "Critical", badge: "danger" },
};

/**
 * LLM usage telemetry: context fill is the headline (normal → getting high →
 * critical), token/call counts are secondary. Context % is emphasized over
 * raw token counts per the redesign spec.
 */
export const RunTelemetryCard = memo(function RunTelemetryCard({
  telemetry,
  derived,
  className,
}: RunTelemetryCardProps) {
  const ctxPct = telemetry?.last_ctx_pct ?? null;
  const ctxWindow = telemetry?.context_window_tokens ?? null;
  const ctxUsed = telemetry?.last_estimated_context_tokens ?? null;
  const remaining =
    ctxUsed != null && ctxWindow != null ? Math.max(0, ctxWindow - ctxUsed) : null;
  const calls = telemetry?.calls ?? null;
  const tokens = telemetry?.total_tokens ?? derived.tokens ?? null;
  const ctxSeries = derived.telemetrySeries.map((s) => s.ctxPct).filter((v): v is number => v != null);
  const tokenSeries = derived.telemetrySeries.map((s) => s.tokens);
  const hasSpark = derived.telemetrySeries.length >= 2;

  const level = ctxPct != null ? ctxLevel(ctxPct) : null;
  const meta = level ? LEVEL_META[level] : null;
  const barPct = ctxPct != null ? Math.max(0, Math.min(100, Math.round(ctxPct))) : null;

  return (
    <Card className={cn(className)}>
      <CardHeader className="pb-2">
        <CardTitle className="flex items-center gap-2 text-sm">
          <Cpu className="h-4 w-4 text-primary" aria-hidden />
          Telemetry
          {meta && (
            <Badge variant={meta.badge} className="ml-auto text-[10px]">
              {meta.label}
            </Badge>
          )}
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-2.5 text-xs">
        {ctxPct == null ? (
          <p className="text-muted-foreground">
            No telemetry yet — the agent reports context usage with the first heartbeat.
          </p>
        ) : (
          <div className="space-y-1.5">
            <div className="flex items-center justify-between text-[11px] text-muted-foreground">
              <span>Context window used</span>
              <span className="font-mono tabular-nums text-foreground">{ctxPct.toFixed(1)}%</span>
            </div>
            <div
              className="h-1.5 w-full overflow-hidden rounded-full bg-muted"
              role="progressbar"
              aria-valuenow={barPct ?? 0}
              aria-valuemin={0}
              aria-valuemax={100}
              aria-label="Context window usage"
            >
              <div
                className={cn("h-full rounded-full transition-all", meta?.bar)}
                style={{ width: `${barPct ?? 0}%` }}
              />
            </div>
            {ctxUsed != null && ctxWindow != null && (
              <p className="text-[11px] text-muted-foreground">
                <span className="font-mono tabular-nums text-foreground">
                  {formatTokens(ctxUsed)}
                </span>{" "}
                of <span className="font-mono tabular-nums">{formatTokens(ctxWindow)}</span>{" "}
                {remaining != null && (
                  <>
                    · <span className="font-mono tabular-nums text-foreground">{formatTokens(remaining)}</span>{" "}
                    remaining
                  </>
                )}
              </p>
            )}
          </div>
        )}

        {(tokens != null || calls != null) && (
          <div className="grid grid-cols-2 gap-2 font-mono">
            {tokens != null && (
              <StatCell label="total tokens" value={tokens.toLocaleString()} />
            )}
            {calls != null && <StatCell label="LLM calls" value={String(calls)} />}
          </div>
        )}

        {hasSpark && (
          <div className={cn("grid gap-2", ctxSeries.length >= 2 ? "grid-cols-2" : "grid-cols-1")}>
            <Sparkline
              label="tokens"
              values={tokenSeries}
              className="rounded-md border bg-card/40 p-1.5"
            />
            {ctxSeries.length >= 2 && (
              <Sparkline
                label="ctx %"
                values={ctxSeries}
                format={(v) => `${v.toFixed(1)}%`}
                className="rounded-md border bg-card/40 p-1.5"
              />
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
});

function StatCell({ label, value }: { label: string; value: string }) {
  return (
    <div className="space-y-0.5 rounded-md border bg-card/40 p-1.5">
      <div className="text-[10px] uppercase tracking-wide text-muted-foreground">{label}</div>
      <div className="tabular-nums text-foreground">{value}</div>
    </div>
  );
}
