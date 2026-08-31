// BreachPilot by @braydos-h — https://github.com/braydos-h/BreachPilot
// Shared shell for the Benchmarks section: title, sub-page navigation
// (Overview / New run / Past benchmarks) and the live-run pill.
import type { ReactNode } from "react";
import { Link, NavLink } from "react-router-dom";
import { BarChart3, FlaskConical, History, Play } from "lucide-react";
import { useBenchmarksOverview } from "@/features/benchmarks/useBenchmarksOverview";
import { cn } from "@/lib/utils";

const NAV_ITEMS = [
  { to: "/benchmarks", label: "Overview", icon: BarChart3, end: true },
  { to: "/benchmarks/new", label: "New run", icon: Play, end: true },
  { to: "/benchmarks/history", label: "Past benchmarks", icon: History, end: true },
];

export function BenchmarksShell({ children }: { children: ReactNode }) {
  const { active, activeBusy } = useBenchmarksOverview();

  return (
    <div className="mx-auto w-full max-w-6xl space-y-5 p-4 md:p-6">
      <header className="space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h1 className="flex items-center gap-2 text-xl font-semibold">
              <FlaskConical className="h-5 w-5 text-primary" />
              Benchmarks
            </h1>
            <p className="text-sm text-muted-foreground">
              Verified benchmark results — ground truth comes from the independent oracle, never from agent claims.
            </p>
          </div>
          {activeBusy && active.run_id ? (
            <Link
              to={`/benchmarks/${active.run_id}`}
              className="flex items-center gap-2 rounded-md border border-yellow-500/30 bg-yellow-500/10 px-3 py-2 text-sm text-yellow-300 shadow-sm"
              aria-label={`View live benchmark run ${active.run_id}`}
            >
              <span className="relative flex h-2.5 w-2.5">
                <span className="absolute inline-flex h-2.5 w-2.5 animate-ping rounded-full bg-yellow-400 opacity-75" />
                <span className="relative inline-flex h-2.5 w-2.5 rounded-full bg-yellow-400" />
              </span>
              <span className="flex flex-col leading-none">
                <span className="font-medium">Live run</span>
                <span className="font-mono text-[11px] opacity-80">{active.run_id}</span>
              </span>
            </Link>
          ) : null}
        </div>
        <nav aria-label="Benchmarks sections" className="flex flex-wrap gap-1">
          {NAV_ITEMS.map(({ to, label, icon: Icon, end }) => (
            <NavLink
              key={to}
              to={to}
              end={end}
              className={({ isActive }) =>
                cn(
                  "flex items-center gap-1.5 rounded-md px-3 py-1.5 text-sm font-medium transition-colors",
                  isActive
                    ? "bg-primary/15 text-primary"
                    : "text-muted-foreground hover:bg-accent hover:text-foreground",
                )
              }
            >
              <Icon className="h-3.5 w-3.5" aria-hidden />
              {label}
            </NavLink>
          ))}
        </nav>
      </header>
      {children}
    </div>
  );
}
