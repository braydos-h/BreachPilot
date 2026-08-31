import { useEffect, useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import {
  Activity,
  ArrowRight,
  Compass,
  History,
  Info,
  ListFilter,
  ScanSearch,
  ShieldAlert,
  ShieldCheck,
  ShieldX,
  Target,
} from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { StatusBadge } from "@/components/StatusBadge";
import { SkeletonRows } from "@/components/Loading";
import { useRuns, useSandboxStatus } from "@/api/hooks";
import {
  isActiveState,
  isTerminalState,
  type RunListRow,
} from "@/api/types";
import { formatRelative, truncateId } from "@/lib/utils";

const NOTICE_KEY = "breachpilot.fullNotice.shown.v1";

function FullAccessNotice() {
  const [open, setOpen] = useState(false);

  useEffect(() => {
    try {
      if (sessionStorage.getItem(NOTICE_KEY) === "1") return;
      sessionStorage.setItem(NOTICE_KEY, "1");
      setOpen(true);
    } catch {
      // ignore
    }
  }, []);

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2 text-lg">
            <ShieldAlert className="h-5 w-5 text-red-400" />
            Read-only by default
          </DialogTitle>
          <DialogDescription className="text-sm">
            The console defaults to <span className="text-yellow-300 font-medium">Read-only</span>. Every operator decision waits for you to answer it. Use the sidebar toggle to switch to Approve (auto-answers non-destructive decisions only).
          </DialogDescription>
        </DialogHeader>
        <div className="flex justify-end gap-2 pt-1">
          <Button type="button" size="sm" onClick={() => setOpen(false)}>Got it</Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}

const FALLBACK_HINT = "Start Docker and build the sandbox image (docker build -t breachpilot-sandbox:latest docker/sandbox) to contain execution — until then commands run directly on this machine.";

/**
 * Sandbox posture banner for the home screen. Surfaced at startup so the
 * operator always knows the effective execution mode before launching a run.
 * The reported mode is the session's BOOT-TIME decision (the API's
 * sandbox_boot_state.json), not a live Docker probe — a session's posture is
 * fixed when its server boots and never flips mid-run:
 * - contained: quiet green line (worker container active).
 * - disabled: quiet muted line (legacy host mode as configured).
 * - native_fallback: amber card — Docker was unusable at boot, the session
 *   degraded to uncontained native execution (fallback_native=true default).
 * - blocked: red card — strict fail-closed mode, executions will be denied.
 */
export function SandboxBanner() {
  const sandbox = useSandboxStatus();
  if (sandbox.isLoading || sandbox.error || !sandbox.data) return null;
  const s = sandbox.data;
  const reason: string = s.fallback_reason || s.docker_error || "";
  // Old backends (no ``mode``) or future modes: say nothing rather than
  // rendering a false alarm (the cards below assert specific postures).
  const knownMode = ["contained", "disabled", "native_fallback", "blocked"].includes(s.mode ?? "");
  if (!knownMode) return null;

  if (s.mode === "contained") {
    return (
      <p className="flex items-center gap-1.5 text-xs text-muted-foreground" data-testid="sandbox-banner-contained">
        <ShieldCheck className="h-3.5 w-3.5 text-emerald-400" />
        Sandbox active — commands run inside the disposable Docker worker.
      </p>
    );
  }
  if (s.mode === "disabled") {
    return (
      <p className="flex items-center gap-1.5 text-xs text-muted-foreground" data-testid="sandbox-banner-disabled">
        <Info className="h-3.5 w-3.5" />
        Sandbox disabled — commands execute directly on the host (legacy mode). Enable it in settings for containment.
      </p>
    );
  }
  if (s.mode === "native_fallback") {
    return (
      <Card className="border-amber-500/40 bg-amber-500/5" data-testid="sandbox-banner-fallback">
        <CardContent className="space-y-1 p-3 text-sm">
          <div className="flex flex-wrap items-center gap-2">
            <ShieldAlert className="h-4 w-4 text-amber-300" />
            <Badge variant="warn">Sandbox unavailable</Badge>
            <span className="font-medium text-amber-200">
              Running natively — execution is NOT contained.
            </span>
          </div>
          {reason && <p className="text-xs text-muted-foreground">Reason: {reason}</p>}
          <p className="text-xs text-amber-200/80">{FALLBACK_HINT}</p>
        </CardContent>
      </Card>
    );
  }
  // blocked (fail closed): sandbox required by config but unusable.
  return (
    <Card className="border-red-500/40 bg-red-500/5" data-testid="sandbox-banner-blocked">
      <CardContent className="space-y-1 p-3 text-sm">
        <div className="flex flex-wrap items-center gap-2">
          <ShieldX className="h-4 w-4 text-red-300" />
          <Badge variant="danger">Sandbox required</Badge>
          <span className="font-medium text-red-200">
            Execution is blocked — the sandbox is unavailable and fallback is disabled.
          </span>
        </div>
        {reason && <p className="text-xs text-muted-foreground">Reason: {reason}</p>}
        <p className="text-xs text-red-200/80">
          Start Docker and build the sandbox image, or set sandbox.fallback_native: true in config.yaml to allow
          uncontained native execution.
        </p>
      </CardContent>
    </Card>
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
      <section className="relative overflow-hidden rounded-xl border bg-card/30 animate-fade-in-up">
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
                  <span className="text-gradient-primary">Mission Control</span>
                </>
              ) : (
                <>
                  <span className="text-gradient-primary">BreachPilot</span>
                  <span className="text-foreground">AI</span>
                  <span className="text-sm font-normal tracking-wide text-muted-foreground"> — Mission Console</span>
                </>
              )}
            </h1>
            <p className="max-w-2xl text-sm leading-relaxed text-muted-foreground md:text-[15px]">
              {returning
                ? `${rows.length} run${rows.length === 1 ? "" : "s"} on record${
                    lastRow ? ` · Last target ${lastTarget} · ${formatRelative(lastRow.created_at)}` : ""
                  } — resume an active session or initiate a new assessment.`
                : "Autonomous assessment platform for authorized security testing. Plan, execute, and review assessments against assets you own or are explicitly authorized to test."}
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
            <Button
              size="sm"
              variant="outline"
              className="gap-1.5"
              onClick={() => window.dispatchEvent(new Event("breachpilot:open-welcome"))}
            >
              <Compass className="h-4 w-4" />
              Product tour
            </Button>
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

      {/* Sandbox posture (effective execution mode for this session) */}
      <SandboxBanner />

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
      <section className="grid gap-3 sm:grid-cols-2 animate-fade-in-up" style={{ animationDelay: "0.1s" }}>
        <ActionCard
          to="/runs/new?path=recon"
          icon={<ScanSearch className="h-6 w-6" />}
          title="Recon & Suggest Goals"
          desc="Scan the target first, see what's open, then pick a goal from AI-ranked suggestions."
          accent="cyan"
        />
        <ActionCard
          to="/runs/new?path=attack"
          icon={<Target className="h-6 w-6" />}
          title="Attack"
          desc="Run a full exploitation session against a target with a preset or custom goal."
          accent="cyan"
        />
      </section>

      {/* Recent sessions */}
      <section className="rounded-xl border bg-card/30 animate-fade-in-up" style={{ animationDelay: "0.2s" }}>
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

        {runs.error && (
          <div className="flex items-center gap-2 p-4 text-sm text-destructive">
            <span>Failed to load recent sessions.</span>
            <Button size="sm" variant="outline" onClick={() => runs.refetch()}>Retry</Button>
          </div>
        )}

        {recent.length === 0 && !runs.isLoading && !runs.error && (
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
      <p className="flex items-center justify-center gap-1.5 text-center text-[11px] tracking-wide text-muted-foreground">
        <span className="inline-block h-1.5 w-1.5 rounded-full bg-muted-foreground/40" />
        Authorized use only — operate exclusively against assets you own or are explicitly authorized to test.
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