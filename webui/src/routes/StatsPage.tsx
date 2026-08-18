import { useMemo } from "react";
import { Activity, BarChart3, CheckCircle2, Coins, XCircle } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { SkeletonRows } from "@/components/Loading";
import { useRuns, useTelemetry } from "@/api/hooks";
import { isTerminalState } from "@/api/types";
import { formatTokens } from "@/lib/format";

const DAYS = 14;

function dayKey(d: Date): string {
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
}

function lastNDays(n: number): string[] {
  const now = new Date();
  const out: string[] = [];
  for (let i = n - 1; i >= 0; i--) {
    out.push(dayKey(new Date(now.getFullYear(), now.getMonth(), now.getDate() - i)));
  }
  return out;
}

export function StatsPage() {
  const runs = useRuns(200, 0);
  const telemetry = useTelemetry();
  const rows = runs.data?.runs ?? [];
  const summary = telemetry.data?.summary;
  const recent = telemetry.data?.recent ?? [];

  const days = useMemo(() => lastNDays(DAYS), []);

  const byDay = useMemo(() => {
    const map = new Map(days.map((d) => [d, { total: 0, completed: 0, failed: 0 }]));
    for (const r of rows) {
      const b = map.get(dayKey(new Date(r.created_at)));
      if (!b) continue;
      b.total += 1;
      if (r.state === "completed") b.completed += 1;
      else if (r.state === "failed") b.failed += 1;
    }
    return map;
  }, [rows, days]);

  const tokensByDay = useMemo(() => {
    const map = new Map(days.map((d) => [d, 0]));
    for (const rec of recent) {
      const k = dayKey(new Date(rec.started_at ?? rec.ended_at ?? ""));
      if (k && map.has(k)) map.set(k, (map.get(k) ?? 0) + (rec.total_tokens ?? 0));
    }
    return map;
  }, [recent, days]);

  const stateCounts = useMemo(() => {
    const counts = new Map<string, number>();
    for (const r of rows) counts.set(r.state, (counts.get(r.state) ?? 0) + 1);
    return counts;
  }, [rows]);

  const completed = stateCounts.get("completed") ?? 0;
  const failed = stateCounts.get("failed") ?? 0;
  const terminal = rows.filter((r) => isTerminalState(r.state)).length;
  const successRate = terminal > 0 ? Math.round((completed / terminal) * 100) : null;
  const maxRuns = Math.max(1, ...days.map((d) => byDay.get(d)?.total ?? 0));
  const maxTokens = Math.max(1, ...days.map((d) => tokensByDay.get(d) ?? 0));

  return (
    <div className="space-y-4 p-4 md:p-6">
      <div className="flex items-center gap-2.5">
        <div className="flex h-9 w-9 items-center justify-center rounded-lg border bg-card">
          <BarChart3 className="h-5 w-5 text-primary" />
        </div>
        <div>
          <h1 className="text-lg font-semibold leading-tight">Stats</h1>
          <p className="text-sm text-muted-foreground">
            Activity over time — last {DAYS} days (last 200 runs, last 50 LLM calls).
          </p>
        </div>
      </div>

      {runs.isLoading && <SkeletonRows count={4} className="p-2" />}

      <div className="grid grid-cols-2 gap-2.5 lg:grid-cols-4">
        <Stat icon={Activity} label="Runs" value={String(rows.length)} sub={`${stateCounts.get("running") ?? 0} active`} />
        <Stat icon={CheckCircle2} label="Completed" value={String(completed)} sub={`${successRate ?? "—"}% of terminal`} />
        <Stat icon={XCircle} label="Failed" value={String(failed)} sub={`${stateCounts.get("cancelled") ?? 0} cancelled`} />
        <Stat icon={Coins} label="LLM tokens" value={formatTokens(summary?.total_tokens ?? 0)} sub={`${summary?.calls ?? 0} calls`} />
      </div>

      <div className="grid gap-3 lg:grid-cols-2">
        <Card>
          <CardHeader><CardTitle className="text-sm">Runs per day</CardTitle></CardHeader>
          <CardContent>
            <StackedBarChart
              days={days}
              max={maxRuns}
              series={[
                { key: "completed", className: "bg-emerald-500/80", value: (d) => byDay.get(d)?.completed ?? 0 },
                { key: "failed", className: "bg-destructive/80", value: (d) => byDay.get(d)?.failed ?? 0 },
                {
                  key: "other",
                  className: "bg-muted-foreground/40",
                  value: (d) =>
                    (byDay.get(d)?.total ?? 0) - (byDay.get(d)?.completed ?? 0) - (byDay.get(d)?.failed ?? 0),
                },
              ]}
            />
            <div className="mt-2 flex flex-wrap gap-3 text-[10px] text-muted-foreground">
              <span className="inline-flex items-center gap-1"><span className="h-2 w-2 rounded-sm bg-emerald-500/80" />completed</span>
              <span className="inline-flex items-center gap-1"><span className="h-2 w-2 rounded-sm bg-destructive/80" />failed</span>
              <span className="inline-flex items-center gap-1"><span className="h-2 w-2 rounded-sm bg-muted-foreground/40" />other</span>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader><CardTitle className="text-sm">LLM tokens per day</CardTitle></CardHeader>
          <CardContent>
            <StackedBarChart
              days={days}
              max={maxTokens}
              series={[{ key: "tokens", className: "bg-primary/70", value: (d) => tokensByDay.get(d) ?? 0 }]}
            />
            <div className="mt-2 text-[10px] text-muted-foreground">From the last 50 recorded calls.</div>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader><CardTitle className="text-sm">State distribution</CardTitle></CardHeader>
        <CardContent className="flex flex-wrap gap-2">
          {[...stateCounts.entries()].map(([state, n]) => (
            <span key={state} className="rounded-md border px-2 py-1 font-mono text-xs">
              {state} <span className="text-muted-foreground">× {n}</span>
            </span>
          ))}
          {stateCounts.size === 0 && <p className="text-sm text-muted-foreground">No runs yet.</p>}
        </CardContent>
      </Card>
    </div>
  );
}

function StackedBarChart({
  days,
  max,
  series,
}: {
  days: string[];
  max: number;
  series: Array<{ key: string; className: string; value: (day: string) => number }>;
}) {
  return (
    <div className="flex h-36 items-end gap-1.5">
      {days.map((d) => {
        const segs = series.map((s) => ({ ...s, v: s.value(d) }));
        const total = segs.reduce((sum, s) => sum + s.v, 0);
        return (
          <div key={d} className="group relative flex-1" title={`${d}: ${total}`}>
            <div
              className="flex w-full flex-col-reverse overflow-hidden rounded-t"
              style={{ height: total === 0 ? "2px" : `${Math.max(4, (total / max) * 100)}%` }}
            >
              {segs.filter((s) => s.v > 0).map((s) => (
                <div key={s.key} className={s.className} style={{ height: `${(s.v / total) * 100}%` }} />
              ))}
            </div>
            <div className="mt-1 truncate text-center text-[9px] text-muted-foreground">{d.slice(5)}</div>
          </div>
        );
      })}
    </div>
  );
}

function Stat({ icon: Icon, label, value, sub }: { icon: typeof Activity; label: string; value: string; sub: string }) {
  return (
    <div className="rounded-md border bg-card/40 p-3">
      <div className="flex items-center gap-1.5 text-[10px] uppercase tracking-wide text-muted-foreground">
        <Icon className="h-3 w-3" />
        {label}
      </div>
      <div className="mt-1 truncate font-mono text-sm">{value}</div>
      <div className="mt-0.5 truncate text-xs text-muted-foreground">{sub}</div>
    </div>
  );
}
