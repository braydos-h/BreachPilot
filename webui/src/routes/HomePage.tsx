import { useEffect, useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import {
  Activity,
  ArrowRight,
  History,
  ListFilter,
  ScanSearch,
  ShieldAlert,
  Target,
} from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { SegmentedControl } from "@/components/RunForm";
import { StatusBadge } from "@/components/StatusBadge";
import { SkeletonRows } from "@/components/Loading";
import { useRuns } from "@/api/hooks";
import {
  isActiveState,
  isTerminalState,
  type RunListRow,
} from "@/api/types";
import { usePermissionMode, type PermissionMode } from "@/lib/permissionMode";
import { cn } from "@/lib/utils";
import { formatRelative, truncateId } from "@/lib/utils";

const PERMISSION_OPTIONS: Array<{ value: string; label: string }> = [
  { value: "read_only", label: "Read" },
  { value: "approve", label: "Approve" },
  { value: "full_access", label: "Full" },
];

const FULL_EXAMPLES: Array<{ kind: string; action: string }> = [
  { kind: "start_confirm", action: "Auto-answers \u201cyes\u201d to start the run without waiting." },
  { kind: "tool_approval", action: "Auto-sends the exact required confirmation text (e.g. \u201cI UNDERSTAND THE RISK\u201d) for destructive tool calls." },
];

const NOTICE_KEY = "netattackai.fullNotice.shown.v1";

function FullAccessNotice() {
  const { mode, setMode } = usePermissionMode();
  const [open, setOpen] = useState(false);

  useEffect(() => {
    try {
      if (mode !== "full_access") return;
      if (sessionStorage.getItem(NOTICE_KEY) === "1") return;
      sessionStorage.setItem(NOTICE_KEY, "1");
      setOpen(true);
    } catch {
      // ignore
    }
  }, [mode]);

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2 text-lg">
            <ShieldAlert className="h-5 w-5 text-red-400" />
            Permission mode: Full access
          </DialogTitle>
          <DialogDescription className="text-sm">
            The console defaults to <span className="text-red-300 font-medium">Full access</span>. The agent will auto-answer every operator decision, including destructive ones, without waiting for you. Use only on assets you own or are authorized to test.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4">
          <div>
            <div className="mb-1.5 text-xs font-medium uppercase tracking-wide text-muted-foreground">
              Change mode
            </div>
            <SegmentedControl
              value={mode}
              onChange={(v) => setMode(v as PermissionMode)}
              options={PERMISSION_OPTIONS}
            />
            <p className="mt-1.5 text-[11px] leading-tight text-muted-foreground">
              {mode === "read_only"
                ? "Every decision waits for you. Nothing is auto-answered."
                : mode === "approve"
                  ? "Non-destructive decisions auto-answered; goal selection and destructive ones still wait."
                  : "Everything auto-answered except goal selection, including destructive actions."}
            </p>
          </div>

          <div>
            <div className="mb-1.5 text-xs font-medium uppercase tracking-wide text-muted-foreground">
              What Full access does
            </div>
            <ul className="space-y-1.5">
              {FULL_EXAMPLES.map((ex) => (
                <li key={ex.kind} className="flex flex-col gap-0.5 rounded-md border border-red-500/20 bg-red-500/5 px-3 py-2">
                  <span className="font-mono text-xs text-red-300">{ex.kind}</span>
                  <span className="text-xs leading-relaxed text-muted-foreground">{ex.action}</span>
                </li>
              ))}
            </ul>
          </div>

          <div className={cn("rounded-md border px-3 py-2 text-[11px] leading-relaxed text-muted-foreground",
            mode === "full_access" ? "border-red-500/30 bg-red-500/5" : "border-border bg-card/40")}>
            The target-IP allowlist lock still applies in every mode \u2014 nothing here escapes the allowlist configured for a run.
          </div>
        </div>

        <div className="flex justify-end gap-2 pt-1">
          <Button type="button" size="sm" onClick={() => setOpen(false)}>
            {mode === "full_access" ? "Got it, keep Full" : "Done"}
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}

export function HomePage() {
  const runs = useRuns(50, 0);
  const rows = runs.data?.runs ?? [];
  const activeRun = rows.find((r) => isActiveState(r.state));
  const recent = rows.slice(0, 5);
  const doneCount = rows.filter((r) => isTerminalState(r.state)).length;
  const failedCount = rows.filter((r) => r.state === "failed").length;
  const returning = rows.length > 0 && !runs.isLoading;
  const lastRow = rows[0];
  const lastTarget = lastRow?.target || lastRow?.target_ip || "—";

  return (
    <div className="relative mx-auto max-w-5xl space-y-8 p-4 md:p-8">
      <FullAccessNotice />
      {/* Hero */}
      <section className="relative overflow-hidden rounded-xl border bg-card/30">
        <div className="absolute inset-0 bg-grid bg-radial-fade" aria-hidden />
        <div className="absolute inset-0 overflow-hidden" aria-hidden>
          <div className="absolute inset-x-0 top-0 h-px animate-scan bg-gradient-to-r from-transparent via-primary/60 to-transparent" />
        </div>
        <div
          className="absolute -top-24 left-1/2 h-48 w-[60%] -translate-x-1/2 rounded-full bg-primary/10 blur-3xl"
          aria-hidden
        />
        <div className="relative flex flex-col gap-5 p-6 md:p-10">
          <div className="space-y-2">
            <h1 className="text-3xl font-semibold leading-tight tracking-tight md:text-4xl">
              {returning ? (
                <>
                  <span className="text-gradient-primary">Welcome back</span>
                  <span className="text-foreground">.</span>
                </>
              ) : (
                <>
                  <span className="text-gradient-primary">NetAttack</span>
                  <span className="text-foreground">AI</span>
                </>
              )}
            </h1>
            <p className="max-w-2xl text-sm text-muted-foreground md:text-base">
              {returning
                ? `You have ${rows.length} run${rows.length === 1 ? "" : "s"} on record${
                    lastRow ? `, last targeting ${lastTarget} ${formatRelative(lastRow.created_at)}` : ""
                  }. Pick up where you left off or start a new assessment.`
                : "AI-driven penetration testing console. Plan, execute, and review authorized assessments against assets you own or are explicitly authorized to test."}
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <Button asChild size="sm" className="gap-1.5 glow-primary">
              <Link to="/runs/new?path=recon">
                <ScanSearch className="h-4 w-4" />
                New recon
              </Link>
            </Button>
            {activeRun && (
              <Button
                asChild
                size="sm"
                variant="outline"
                className="border-yellow-500/40 text-yellow-300 hover:bg-yellow-500/10"
              >
                <Link to={`/runs/${activeRun.id}`}>
                  <Activity className="h-4 w-4 animate-pulse" />
                  Resume active
                </Link>
              </Button>
            )}
          </div>

          {/* Stats strip */}
          <div className="grid grid-cols-2 gap-px overflow-hidden rounded-lg border bg-border sm:grid-cols-4">
            <Stat
              label="Total runs"
              value={rows.length.toString()}
              hint={runs.isLoading ? "loading" : undefined}
            />
            <Stat label="Active" value={activeRun ? "1" : "0"} accent={activeRun ? "yellow" : undefined} />
            <Stat label="Completed" value={doneCount.toString()} accent="emerald" />
            <Stat label="Failed" value={failedCount.toString()} accent={failedCount > 0 ? "red" : undefined} />
          </div>
        </div>
      </section>

      {/* Active run banner */}
      {activeRun && (
        <Card className="border-yellow-500/40 bg-yellow-500/5">
          <CardContent className="flex flex-wrap items-center gap-2 p-3 text-sm">
            <Activity className="h-4 w-4 animate-pulse text-yellow-300" />
            <Badge variant="warn">Active</Badge>
            <span className="truncate font-mono text-xs">{activeRun.target}</span>
            <StatusBadge state={activeRun.state} />
            <Button asChild size="sm" variant="outline" className="ml-auto">
              <Link to={`/runs/${activeRun.id}`}>Open run</Link>
            </Button>
          </CardContent>
        </Card>
      )}

      {/* Action cards */}
      <section className="grid gap-3 sm:grid-cols-2">
        <ActionCard
          to="/runs/new?path=recon"
          icon={<ScanSearch className="h-6 w-6" />}
          title="Recon & Suggest Goals"
          desc="Scan the target first, see what's open, then pick a goal from AI-ranked suggestions."
          accent="cyan"
        />
        <ActionCard
          to="/runs/new?path=recon"
          icon={<ScanSearch className="h-6 w-6" />}
          title="Recon"
          desc="Run a fresh recon scan against a target."
          accent="violet"
        />
      </section>

      {/* Recent sessions */}
      <section className="rounded-xl border bg-card/30">
        <header className="flex items-center justify-between gap-2 border-b px-4 py-2.5">
          <div className="flex items-center gap-2">
            <History className="h-4 w-4 text-muted-foreground" />
            <div>
              <div className="text-sm font-medium">Recent sessions</div>
              <p className="text-xs text-muted-foreground">
                Latest {recent.length || 0} of {rows.length || 0} runs.
              </p>
            </div>
          </div>
          <Button asChild size="sm" variant="outline" className="gap-1.5">
            <Link to="/sessions">
              <ListFilter className="h-3.5 w-3.5" />
              View all
            </Link>
          </Button>
        </header>

        {recent.length === 0 && !runs.isLoading && (
          <div className="flex flex-col items-center gap-2 p-6 text-center text-sm text-muted-foreground">
            <Target className="h-7 w-7 opacity-40" />
            <span>No past sessions yet. Start one above.</span>
          </div>
        )}

        {runs.isLoading && recent.length === 0 && (
          <SkeletonRows count={3} className="p-2" />
        )}

        {recent.length > 0 && (
          <ul className="divide-y">
            {recent.map((row) => (
              <RecentRow key={row.id} row={row} />
            ))}
          </ul>
        )}
      </section>

      {/* Safety footer */}
      <p className="flex items-center justify-center gap-1.5 text-center text-[11px] text-muted-foreground">
        <span className="inline-block h-1.5 w-1.5 rounded-full bg-muted-foreground/50" />
        Run only against assets you own or are explicitly authorized to test.
      </p>
    </div>
  );
}

function Stat({
  label,
  value,
  hint,
  accent,
}: {
  label: string;
  value: string;
  hint?: string;
  accent?: "yellow" | "emerald" | "red";
}) {
  const accentClass =
    accent === "yellow"
      ? "text-yellow-300"
      : accent === "emerald"
        ? "text-emerald-300"
        : accent === "red"
          ? "text-red-300"
          : "text-foreground";
  return (
    <div className="bg-card/60 px-4 py-3">
      <div className="text-[10px] uppercase tracking-wide text-muted-foreground">{label}</div>
      <div className={`font-mono text-xl tabular-nums ${accentClass}`}>{hint ?? value}</div>
    </div>
  );
}

const ACCENTS = {
  cyan: {
    ring: "hover:border-primary/50 hover:glow-primary",
    icon: "text-primary",
  },
  violet: {
    ring: "hover:border-primary/50 hover:glow-primary",
    icon: "text-primary",
  },
} as const;

function ActionCard({
  to,
  icon,
  title,
  desc,
  accent,
}: {
  to: string;
  icon: ReactNode;
  title: string;
  desc: string;
  accent: keyof typeof ACCENTS;
}) {
  const a = ACCENTS[accent];
  return (
    <Link
      to={to}
      className={`group relative flex flex-col items-start gap-2 rounded-lg border bg-card/40 p-4 text-left transition-all hover:bg-accent focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring ${a.ring}`}
    >
      <div className={`rounded-md border bg-secondary/40 p-2 ${a.icon}`}>
        {icon}
      </div>
      <div className="space-y-0.5">
        <div className="text-sm font-medium">{title}</div>
        <p className="text-xs text-muted-foreground">{desc}</p>
      </div>
      <span className="mt-0.5 inline-flex items-center gap-1 text-xs text-muted-foreground transition-transform group-hover:translate-x-0.5">
        Start <ArrowRight className="h-3 w-3" />
      </span>
    </Link>
  );
}

function RecentRow({ row }: { row: RunListRow }) {
  const target = row.target || row.target_ip || "—";
  const title = row.title || "";
  return (
    <li>
      <Link
        to={`/runs/${row.id}`}
        className="flex items-center gap-3 px-4 py-2 text-sm transition-colors hover:bg-accent/40"
      >
        <span className="font-mono text-xs text-muted-foreground" title={row.id}>
          {truncateId(row.id)}
        </span>
        <StatusBadge state={row.state} />
        {title ? (
          <span className="max-w-[16rem] truncate text-xs" title={title}>{title}</span>
        ) : (
          <span className="max-w-[16rem] truncate font-mono text-xs" title={target}>{target}</span>
        )}
        <span className="ml-auto hidden text-xs text-muted-foreground sm:inline">
          {row.mode}
        </span>
        <span
          className="text-xs text-muted-foreground"
          title={row.created_at}
        >
          {formatRelative(row.created_at)}
        </span>
      </Link>
    </li>
  );
}