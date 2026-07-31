import { NavLink, Outlet, useLocation } from "react-router-dom";
import { Activity, Cpu, Eye, Github, List, Plus, Settings, Terminal } from "lucide-react";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { useRuns } from "@/api/hooks";
import { isActiveState } from "@/api/types";
import { clearStoredToken } from "@/api/client";
import { useNavigate } from "react-router-dom";

const NAV_ITEMS = [
  { to: "/", label: "Runs", icon: List, end: true },
  { to: "/runs/new", label: "New run", icon: Plus, end: false },
  { to: "/system", label: "System", icon: Settings, end: false },
];

export function Layout() {
  const location = useLocation();
  const navigate = useNavigate();
  const runs = useRuns(50, 0);
  const activeRun = runs.data?.runs.find((r) => isActiveState(r.state));

  const onSignOut = () => {
    clearStoredToken();
    navigate("/");
    window.location.reload();
  };

  return (
    <div className="flex min-h-dvh flex-col bg-background text-foreground md:flex-row">
      <aside className="hidden w-56 shrink-0 border-r bg-card/30 md:flex md:flex-col">
        <div className="flex items-center gap-2 border-b px-4 py-4">
          <Terminal className="h-4 w-4 text-muted-foreground" />
          <div className="flex flex-col">
            <span className="text-sm font-semibold leading-tight">NetAttackAI</span>
            <span className="text-[10px] uppercase tracking-wide text-muted-foreground">Local console</span>
          </div>
        </div>
        <nav className="flex flex-1 flex-col gap-1 p-2" aria-label="Primary">
          {NAV_ITEMS.map((item) => {
            const Icon = item.icon;
            return (
              <NavLink
                key={item.to}
                to={item.to}
                end={item.end}
                className={({ isActive }) =>
                  cn(
                    "flex items-center gap-2 rounded-md px-3 py-2 text-sm transition-colors",
                    isActive
                      ? "bg-secondary text-secondary-foreground"
                      : "text-muted-foreground hover:bg-accent hover:text-foreground",
                  )
                }
              >
                <Icon className="h-4 w-4" />
                <span>{item.label}</span>
              </NavLink>
            );
          })}
          {activeRun && (
            <NavLink
              to={`/runs/${activeRun.id}`}
              className="flex items-center gap-2 rounded-md border border-yellow-500/30 bg-yellow-500/10 px-3 py-2 text-sm text-yellow-300 transition-colors hover:bg-yellow-500/20"
            >
              <Activity className="h-4 w-4 animate-pulse" />
              <span className="truncate">Active run</span>
            </NavLink>
          )}
        </nav>
        <div className="border-t p-2">
          <Button
            variant="ghost"
            size="sm"
            className="w-full justify-start gap-2 text-muted-foreground"
            onClick={onSignOut}
          >
            <Cpu className="h-4 w-4" />
            <span>Clear token</span>
          </Button>
        </div>
      </aside>

      <header className="flex items-center justify-between gap-3 border-b bg-card/30 px-4 py-2 md:hidden">
        <div className="flex items-center gap-2">
          <Terminal className="h-4 w-4 text-muted-foreground" />
          <span className="text-sm font-semibold">NetAttackAI</span>
        </div>
        <nav className="flex items-center gap-1" aria-label="Primary mobile">
          {NAV_ITEMS.map((item) => {
            const Icon = item.icon;
            return (
              <NavLink
                key={item.to}
                to={item.to}
                end={item.end}
                className={({ isActive }) =>
                  cn(
                    "flex h-9 w-9 items-center justify-center rounded-md transition-colors",
                    isActive
                      ? "bg-secondary text-secondary-foreground"
                      : "text-muted-foreground hover:bg-accent hover:text-foreground",
                  )
                }
                aria-label={item.label}
              >
                <Icon className="h-4 w-4" />
              </NavLink>
            );
          })}
          <button
            type="button"
            className="flex h-9 w-9 items-center justify-center rounded-md text-muted-foreground transition-colors hover:bg-accent hover:text-foreground"
            onClick={onSignOut}
            aria-label="Clear token"
          >
            <Cpu className="h-4 w-4" />
          </button>
        </nav>
      </header>

      <main className="flex min-w-0 flex-1 flex-col">
        {activeRun && (
          <div className="flex items-center gap-2 border-b border-yellow-500/30 bg-yellow-500/10 px-4 py-2 text-sm text-yellow-300">
            <Activity className="h-4 w-4 animate-pulse" />
            <span className="truncate">An active run is in progress.</span>
            <NavLink to={`/runs/${activeRun.id}`} className="ml-auto underline-offset-4 hover:underline">
              Open
            </NavLink>
          </div>
        )}
        <div className="flex-1" key={location.pathname}>
          <Outlet />
        </div>
        <footer className="flex items-center justify-between gap-2 border-t px-4 py-2 text-xs text-muted-foreground">
          <span className="inline-flex items-center gap-1.5">
            <Eye className="h-3 w-3" />
            Loopback only. Run only against assets you own or are authorized to test.
          </span>
          <a
            href="https://github.com/anomalyco/opencode/issues"
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1 hover:text-foreground"
          >
            <Github className="h-3 w-3" />
            Feedback
          </a>
        </footer>
      </main>
    </div>
  );
}
