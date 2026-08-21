import { Check, Loader2, XCircle, Zap, Clock } from "lucide-react";
import type { RunEvent } from "@/api/types";
import { cn } from "@/lib/utils";

interface FastReconProgressProps {
  events: RunEvent[];
}

interface TaskRow {
  task: string;
  label: string;
  status: string;
  duration_ms?: number;
  completed?: number;
  total?: number;
}

export function FastReconProgress({ events }: FastReconProgressProps) {
  const fastEvents = events.filter((e) => e.type.startsWith("fast_recon") || e.type === "ai_takeover_started");
  if (fastEvents.length === 0) return null;

  const started = events.find((e) => e.type === "fast_recon_started");
  const completed = events.find((e) => e.type === "fast_recon_completed");
  const aiTakeover = events.find((e) => e.type === "ai_takeover_started");

  // Derive task rows from task_started/completed/failed/progress
  const tasks = new Map<string, TaskRow>();
  for (const ev of events) {
    const t = String(ev.payload?.task ?? ev.payload?.label ?? "");
    if (ev.type === "fast_recon_task_started") {
      tasks.set(String(ev.payload?.task ?? t), {
        task: String(ev.payload?.task ?? t),
        label: String(ev.payload?.label ?? ev.payload?.task ?? t),
        status: "running",
      });
    } else if (ev.type === "fast_recon_task_completed") {
      const key = String(ev.payload?.task ?? t);
      const prev = tasks.get(key);
      tasks.set(key, {
        task: key,
        label: String(ev.payload?.label ?? prev?.label ?? key),
        status: "completed",
        duration_ms: typeof ev.payload?.duration_ms === "number" ? ev.payload.duration_ms : prev?.duration_ms,
      });
    } else if (ev.type === "fast_recon_task_failed") {
      const key = String(ev.payload?.task ?? t);
      const prev = tasks.get(key);
      tasks.set(key, {
        task: key,
        label: String(ev.payload?.label ?? prev?.label ?? key),
        status: String(ev.payload?.status ?? "failed"),
      });
    } else if (ev.type === "fast_recon_progress") {
      const key = String(ev.payload?.task ?? t);
      const c = ev.payload?.completed;
      const tot = ev.payload?.total;
      tasks.set(key, {
        task: key,
        label: key,
        status: "running",
        completed: typeof c === "number" ? c : undefined,
        total: typeof tot === "number" ? tot : undefined,
      });
    }
  }

  // Also capture generic fast_recon_completed payload as summary
  const summary = completed?.payload as Record<string, unknown> | undefined;

  // Elapsed calculation
  const elapsedSec = (() => {
    if (!started?.timestamp) return null;
    const s = Date.parse(started.timestamp);
    const end = completed?.timestamp ? Date.parse(completed.timestamp) : Date.now();
    if (!Number.isFinite(s) || !Number.isFinite(end)) return null;
    return Math.max(0, (end - s) / 1000);
  })();

  const taskList = Array.from(tasks.values());
  const completedCount = taskList.filter((t) => t.status === "completed").length;
  const totalTracked = taskList.length;

  // If only started/completed without per-task events, show simple state
  const isCompleted = !!completed;
  const isRunning = !!started && !completed;

  return (
    <div className="rounded-md border bg-card/40 p-3">
      <div className="flex items-center gap-2">
        <span className={cn("flex h-7 w-7 items-center justify-center rounded-md border", isCompleted ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-300" : "border-cyan-500/30 bg-cyan-500/10 text-cyan-300")}>
          {isCompleted ? <Check className="h-4 w-4" /> : isRunning ? <Loader2 className="h-4 w-4 animate-spin" /> : <Zap className="h-4 w-4" />}
        </span>
        <div className="flex-1">
          <div className="flex items-center gap-2">
            <span className="text-sm font-semibold">{isCompleted ? "Fast Recon complete" : "Fast Recon"}</span>
            {elapsedSec != null && (
              <span className="flex items-center gap-1 text-xs text-muted-foreground">
                <Clock className="h-3 w-3" /> {elapsedSec.toFixed(1)}s
              </span>
            )}
            {isCompleted && summary && typeof summary.duration_seconds === "number" && (
              <span className="text-xs text-muted-foreground">· {Number(summary.duration_seconds).toFixed(1)}s wall clock</span>
            )}
          </div>
          {summary && (
            <div className="text-xs text-muted-foreground">
              {typeof summary.open_ports === "object" && Array.isArray(summary.open_ports) ? `${(summary.open_ports as unknown[]).length} TCP ports` : ""}
              {typeof summary.services === "number" ? ` · ${summary.services} services` : ""}
              {typeof summary.cves === "number" ? ` · ${summary.cves} CVE candidates` : ""}
              {(summary as Record<string, unknown>).cache_hit ? " · cache hit" : ""}
            </div>
          )}
        </div>
        {isRunning && totalTracked > 0 && (
          <span className="text-xs tabular-nums text-muted-foreground">
            {completedCount} / {totalTracked}
          </span>
        )}
      </div>

      {taskList.length > 0 && (
        <div className="mt-3 space-y-1.5">
          {taskList.map((t) => (
            <div key={t.task} className="flex items-center gap-2 text-xs">
              <span className="flex h-4 w-4 items-center justify-center">
                {t.status === "completed" ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : t.status === "running" ? <Loader2 className="h-3.5 w-3.5 animate-spin text-cyan-400" /> : <XCircle className="h-3.5 w-3.5 text-destructive" />}
              </span>
              <span className="flex-1 truncate font-mono">{t.label || t.task}</span>
              {t.completed != null && t.total != null ? (
                <span className="tabular-nums text-muted-foreground">{t.completed} / {t.total}</span>
              ) : t.duration_ms != null ? (
                <span className="tabular-nums text-muted-foreground">{(t.duration_ms / 1000).toFixed(1)}s</span>
              ) : (
                <span className="capitalize text-muted-foreground">{t.status}</span>
              )}
            </div>
          ))}
        </div>
      )}

      {isCompleted && (
        <div className="mt-2 text-xs text-muted-foreground">
          {aiTakeover ? "AI agent taking over..." : "Handing off to AI agent..."}
        </div>
      )}
      {started && !completed && (
        <div className="mt-2 text-xs text-muted-foreground">Dependency-aware parallel recon — independent tasks run concurrently, service enrichment waits for discovery.</div>
      )}
    </div>
  );
}
