import { Link } from "react-router-dom";
import { Activity, Compass, ScanSearch } from "lucide-react";
import { Button } from "@/components/ui/button";
import { StatusBadge } from "@/components/StatusBadge";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { formatRelative } from "@/lib/utils";
import type { HomePageState } from "./useHomePage";

export function HomeHero({ page }: { page: HomePageState }) {
  const { runs, rows, activeRun, doneCount, failedCount, returning, lastTarget } = page;
  return (
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
                  rows[0] ? ` · Last target ${lastTarget} · ${formatRelative(rows[0].created_at)}` : ""
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
              className="border-amber-500/40 text-amber-100 hover:bg-amber-500/10"
            >
              <Link to={`/runs/${activeRun.id}`}>
                <Activity className="h-4 w-4" aria-hidden />
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

        {runs.isLoading && rows.length === 0 ? (
          <div className="grid grid-cols-2 gap-px overflow-hidden rounded-lg border bg-border sm:grid-cols-4" role="status" aria-label="Loading stats">
            {[0, 1, 2, 3].map((i) => (
              <div key={i} className="bg-card/60 px-4 py-3">
                <div className="text-[10px] uppercase tracking-wide text-muted-foreground">&nbsp;</div>
                <div className="mt-1 h-7 w-12 animate-pulse rounded bg-muted/60" />
              </div>
            ))}
          </div>
        ) : (
          <div className="grid grid-cols-2 gap-px overflow-hidden rounded-lg border bg-border sm:grid-cols-4">
            <Stat
              label="Total runs"
              value={rows.length.toString()}
              hint={runs.isFetching && rows.length === 0 ? "loading" : undefined}
            />
            <Stat label="Active" value={activeRun ? "1" : "0"} accent={activeRun ? "yellow" : undefined} />
            <Stat label="Completed" value={doneCount.toString()} accent="emerald" />
            <Stat label="Failed" value={failedCount.toString()} accent={failedCount > 0 ? "red" : undefined} />
          </div>
        )}
      </div>
    </section>
  );
}

export function HomeActiveBanner({ page }: { page: HomePageState }) {
  const { activeRun } = page;
  if (!activeRun) return null;
  return (
    <Card className="border-amber-500/40 bg-amber-500/5">
      <CardContent className="flex flex-wrap items-center gap-2 p-3 text-sm">
        <Activity className="h-4 w-4 text-amber-100" aria-hidden />
        <Badge variant="warn">Active</Badge>
        <span className="truncate font-mono text-[13px]">{activeRun.target}</span>
        <StatusBadge state={activeRun.state} />
        <Button asChild size="sm" variant="outline" className="ml-auto">
          <Link to={`/runs/${activeRun.id}`}>Open run</Link>
        </Button>
      </CardContent>
    </Card>
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
