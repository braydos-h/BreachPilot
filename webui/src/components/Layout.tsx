import { useEffect, useState, type ComponentType } from "react";
import { Link, NavLink, Outlet, useLocation } from "react-router-dom";
import { Activity, Cpu, Eye, Github, HelpCircle, Menu, Settings, ShieldAlert, Terminal, X } from "lucide-react";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { PermissionControl } from "@/components/permission/PermissionControl";
import { useConnections, useHostPlatform, useRuns } from "@/api/hooks";
import { isActiveState, type DecisionListRow, type HostPlatform } from "@/api/types";
import { clearStoredToken } from "@/api/client";
import { useNavigate } from "react-router-dom";
import { autoAnswerFor, usePermissionMode, type PermissionMode } from "@/lib/permissionMode";
import { useProviderStatus } from "@/components/ProviderSetup";
import { clearStoredBaseline, useSessionTokens } from "@/lib/sessionTokens";
import { formatTokens } from "@/lib/format";
import { WindowsPerformanceWarning } from "@/components/WindowsPerformanceWarning";

import { PRODUCT_ROUTES, NAV_GROUPS, type NavGroup } from "@/lib/productRoutes";
import { APP_VERSION } from "@/lib/version";
import { CommandPalette } from "@/components/CommandPalette";
import { AttentionCentre, type AttentionItem } from "@/components/AttentionCentre";
import { humanizeEnum, DECISION_KIND_LABELS } from "@/lib/enumLabels";

// Sidebar is task-oriented (todos 04/05): Operate primary, Knowledge/Evaluate/System collapsed by default.
// Runs is canonical (todo 06); Operations lives under System (todo 39); Benchmarks under Evaluate (todo 40).

const MODE_TITLES: Record<PermissionMode, string> = {
  read_only: "Manual approvals",
  approve: "Auto-safe approvals",
  full_access: "Autonomous within scope",
};

const MODE_BLURB: Record<PermissionMode, string> = {
  read_only: "Every decision waits for you. Nothing is auto-approved. Safest — you drive.",
  approve: "Automatically handles safe start and tool approvals. Destructive confirmations, goals, and campaign checkpoints still wait for you.",
  full_access: "Automatically handles start/tool approvals, including destructive confirmations. Goals and campaign checkpoints still wait for you. The target-IP allowlist lock still applies.",
};

const DEMO_DECISIONS: Array<{ kind: string; status: "pending"; required_text?: string; options?: Array<{ name: string; compatible: boolean }> }> = [
  { kind: "goal_select", status: "pending", options: [{ name: "enumerate-then-report", compatible: true }] },
  { kind: "start_confirm", status: "pending" },
  { kind: "tool_approval", status: "pending", required_text: "I UNDERSTAND THE RISK" },
];

function demoAnswer(d: typeof DEMO_DECISIONS[number], mode: PermissionMode): string {
  return autoAnswerFor(d as DecisionListRow, mode) ?? "\u2014 waits for operator";
}

// ponytail: keyed lookup, no switch/if-chain. macOS ("darwin") falls back to
// "Local" \u2014 the sidebar label only distinguishes Linux vs Windows operators.
const PLATFORM_LABELS: Record<HostPlatform, string> = {
  windows: "Windows",
  linux: "Linux",
  darwin: "Local",
  unknown: "Local",
};

export function platformLabel(platform: HostPlatform | undefined): string {
  return platform ? (PLATFORM_LABELS[platform] ?? "Local") : "Local";
}

export function Layout() {
  const location = useLocation();
  const navigate = useNavigate();
  const runs = useRuns(50, 0);
  const connections = useConnections();
  const providerStatus = useProviderStatus();
  const { sessionTokens } = useSessionTokens();
  const { mode, setMode } = usePermissionMode();
  const activeRuns = runs.data?.runs.filter((r) => isActiveState(r.state)) ?? [];
  const activeConnections = connections.data?.active ?? 0;
  const [showHelp, setShowHelp] = useState(false);
  const [permOpen, setPermOpen] = useState(false);
  const [navOpen, setNavOpen] = useState(false);
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [collapsed, setCollapsed] = useState<Record<NavGroup, boolean>>({ operate: false, knowledge: true, evaluate: true, system: true });
  // Per-session banner dismissal: hides the notice without touching the
  // permission mode (the X must never silently downgrade to read_only).
  const [permBannerDismissed, setPermBannerDismissed] = useState<string | null>(null);

  // Global shortcuts (todo 52): Cmd/Ctrl+K palette, N new run, G R/H, ? help. Disabled in inputs.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const el = e.target as HTMLElement | null;
      const inInput = !!el && (el.tagName === "INPUT" || el.tagName === "TEXTAREA" || el.isContentEditable || el.tagName === "SELECT");
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setPaletteOpen(true);
        return;
      }
      if (inInput) return;
      if (e.key === "n" || e.key === "N") {
        navigate("/runs/new");
      } else if (e.key === "?") {
        navigate("/help");
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [navigate]);

  // Attention roll-up (todo 37): approvals, active runs, provider/connection health.
  const attentionItems: AttentionItem[] = [
    ...activeRuns.map((r) => ({
      id: `run-${r.id}`,
      kind: "approval" as const,
      title: `Active run: ${r.target || r.id.slice(0, 8)}`,
      detail: "Open the run to review pending decisions.",
      to: `/runs/${r.id}`,
    })),
    ...(providerStatus.status === "unreachable"
      ? [{ id: "provider", kind: "provider" as const, title: "Provider offline", detail: providerStatus.error ?? "Provider unreachable.", to: "/system", fixKey: "provider_offline" }]
      : []),
  ];

  // Backend OS for the sidebar badge (same source as WindowsPerformanceWarning:
  // platform.system(), never the browser UA). Falls back to "Local" while
  // loading or when the query is unavailable.
  let hostPlatform: HostPlatform | undefined;
  try {
    hostPlatform = useHostPlatform().data?.platform;
  } catch {
    hostPlatform = undefined;
  }
  const consoleLabel = `${platformLabel(hostPlatform)} console`;

  // The mobile drawer is navigation chrome — always close it when a link
  // inside it moves the user to a new route.
  useEffect(() => {
    setNavOpen(false);
  }, [location.pathname]);

  const onSignOut = () => {
    clearStoredToken();
    clearStoredBaseline();
    navigate("/");
    window.location.reload();
  };

  // Shared by the desktop <aside> and the mobile drawer — one source of truth
  // for nav links, active-run rows, and the footer controls. Grouped per
  // productRoutes registry (todos 04/05/20); mobile follows the same hierarchy.
  const renderNavLink = (to: string, label: string, Icon: ComponentType<{ className?: string }>, end?: boolean) => {
    const isConnections = to === "/connections";
    return (
      <NavLink
        key={to}
        to={to}
        end={end}
        className={({ isActive }) =>
          cn(
            "flex items-center gap-2 rounded-md px-3 py-2 text-sm transition-colors",
            isActive
              ? "bg-primary/10 text-primary"
              : "text-muted-foreground hover:bg-accent hover:text-foreground",
          )
        }
      >
        <Icon className="h-4 w-4" />
        <span className="flex-1">{label}</span>
        {isConnections && activeConnections > 0 && (
          <span className="flex h-5 min-w-[1.25rem] items-center justify-center rounded-full bg-emerald-500/15 px-1.5 text-xs font-semibold tabular-nums text-emerald-600 dark:text-emerald-300" aria-label={`${activeConnections} active connections`}>
            {activeConnections}
          </span>
        )}
      </NavLink>
    );
  };
  const navItems = (
    <>
      {NAV_GROUPS.map((g) => {
        const routes = PRODUCT_ROUTES.filter((r) => r.group === g.id);
        const isCollapsed = collapsed[g.id];
        return (
          <div key={g.id} className="space-y-1">
            <button
              type="button"
              onClick={() => setCollapsed((p) => ({ ...p, [g.id]: !p[g.id] }))}
              aria-expanded={!isCollapsed}
              className="flex w-full items-center justify-between px-3 py-1.5 text-xs font-medium uppercase tracking-wide text-muted-foreground hover:text-foreground"
            >
              <span>{g.label}</span>
              <span aria-hidden>{isCollapsed ? "+" : "–"}</span>
            </button>
            {!isCollapsed && routes.map((item) => renderNavLink(item.path, item.label, item.icon, item.end))}
            {g.id === "operate" && activeRuns.length > 0 && (
              <div className="space-y-1 pt-1" aria-label="Needs attention">
                {activeRuns.map((r) => (
                  <NavLink
                    key={r.id}
                    to={`/runs/${r.id}`}
                    className="flex items-center gap-2 rounded-md border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-sm text-amber-200 transition-colors hover:bg-amber-500/20"
                  >
                    <Activity className="h-4 w-4" aria-hidden />
                    <span className="truncate">{r.target || r.id.slice(0, 8)}</span>
                  </NavLink>
                ))}
              </div>
            )}
          </div>
        );
      })}
    </>
  );

  const providerDotClass =
    providerStatus.status === "online"
      ? "bg-emerald-500"
      : providerStatus.status === "unreachable"
        ? "bg-destructive"
        : providerStatus.status === "checking"
          ? "bg-amber-500"
          : "bg-amber-500/70";
  const sessionTokensFormatted = formatTokens(sessionTokens);
  const providerStatusTitle = `${providerStatus.label} · ${providerStatus.statusText} · ${sessionTokensFormatted} tokens this session${providerStatus.error ? ` — ${providerStatus.error}` : ""}`;

  const sidebarFooter = (
    <div className="space-y-2">
      <div className="space-y-1.5 px-1">
        <div className="flex items-center gap-1.5 text-xs uppercase tracking-wide text-muted-foreground">
          <ShieldAlert className="h-3 w-3" />
          <span>Approval policy</span>
          <button
            type="button"
            onClick={() => setShowHelp(true)}
            aria-label="What does Approval policy do?"
            className="inline-flex h-4 w-4 items-center justify-center rounded-full border border-muted-foreground/50 text-muted-foreground transition-colors hover:border-foreground hover:text-foreground"
          >
            <HelpCircle className="h-3 w-3" />
          </button>
        </div>
        <PermissionControl mode={mode} onModeChange={setMode} />
      </div>
      <Link
        to="/system"
        className="block rounded-md px-3 py-2 hover:bg-accent/40 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring transition-colors"
        aria-label={`Provider: ${providerStatus.label}, status: ${providerStatus.statusText}, ${sessionTokensFormatted} tokens this session — click to manage provider in Settings`}
        title={providerStatusTitle}
      >
        <div className="flex items-center gap-2 text-sm font-medium leading-none">
          <span className="relative flex h-2 w-2 shrink-0" aria-hidden="true">
            <span className={cn("relative inline-flex h-2 w-2 rounded-full", providerDotClass)} />
          </span>
          <span className="truncate">{providerStatus.label}</span>
          <Settings className="ml-auto h-3 w-3 shrink-0 text-muted-foreground/60" aria-hidden="true" />
        </div>
        <div className="ml-4 mt-1 text-xs text-muted-foreground">
          {providerStatus.statusText} · {sessionTokensFormatted} tokens this session
        </div>
        {providerStatus.error && providerStatus.status === "unreachable" && (
          <div className="ml-4 mt-1 truncate text-xs leading-none text-destructive" title={providerStatus.error}>
            {providerStatus.error}
          </div>
        )}
      </Link>
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
  );

  return (
    <div className="flex min-h-dvh flex-col bg-background text-foreground md:flex-row xl:h-dvh xl:overflow-hidden">
      <aside className="hidden w-56 shrink-0 border-r bg-card/30 md:flex md:flex-col">
        <div className="relative flex items-center gap-2 overflow-hidden border-b px-4 py-4">
          <div className="absolute inset-0 bg-grid-sm bg-radial-fade opacity-40" aria-hidden />
          <Terminal className="relative h-5 w-5 text-primary" />
          <div className="relative flex flex-col">
            <span className="text-sm font-semibold leading-tight">
              <span className="text-gradient-primary">BreachPilot</span>
              <span className="text-foreground">AI</span>
            </span>
            <span className="text-xs uppercase tracking-wide text-muted-foreground">
              {APP_VERSION} beta · {consoleLabel}
            </span>
          </div>
        </div>
        <nav className="flex flex-1 flex-col gap-1 p-2" aria-label="Primary">
          {navItems}
        </nav>
        <div className="space-y-2 border-t p-2">{sidebarFooter}</div>
      </aside>

      <header className="flex items-center justify-between gap-3 border-b bg-card/30 px-3 py-2 md:hidden">
        <div className="flex min-w-0 items-center gap-2">
          <button
            type="button"
            className="flex h-9 w-9 shrink-0 items-center justify-center rounded-md text-muted-foreground transition-colors hover:bg-accent hover:text-foreground"
            onClick={() => setNavOpen(true)}
            aria-label="Open navigation"
            aria-expanded={navOpen}
          >
            <Menu className="h-5 w-5" />
          </button>
          <Terminal className="h-4 w-4 shrink-0 text-primary" />
          <span className="truncate text-sm font-semibold">
            <span className="text-gradient-primary">BreachPilot</span>
            <span className="text-foreground">AI</span>
          </span>
        </div>
        <div className="flex shrink-0 items-center gap-1">
          <button
            type="button"
            className={cn(
              "flex h-9 items-center justify-center rounded-md px-2 text-xs font-medium uppercase tracking-wide transition-colors",
              mode === "read_only"
                ? "bg-muted/40 text-muted-foreground"
                : mode === "approve"
                  ? "bg-yellow-500/15 text-yellow-300"
                  : "bg-destructive/15 text-red-200",
            )}
            onClick={() => setPermOpen(true)}
            aria-label={`Approval policy: ${MODE_TITLES[mode]}`}
            title={`Approval policy: ${MODE_TITLES[mode]}`}
          >
            {mode === "read_only" ? "Manual" : mode === "approve" ? "Auto-safe" : "Autonomous"}
          </button>
          <AttentionCentre items={attentionItems} />
          <button
            type="button"
            onClick={() => setPaletteOpen(true)}
            aria-label="Global search (Ctrl+K)"
            title="Global search (Ctrl+K)"
            className="inline-flex h-9 w-9 items-center justify-center rounded-md text-muted-foreground hover:bg-accent hover:text-foreground"
          >
            <span aria-hidden className="text-sm">⌘K</span>
          </button>
        </div>
      </header>

      <Sheet open={navOpen} onOpenChange={setNavOpen}>
        <SheetContent side="left" className="w-72 gap-0 p-0">
          <SheetHeader className="relative flex items-center gap-2 overflow-hidden border-b px-4 py-4">
            <div className="absolute inset-0 bg-grid-sm bg-radial-fade opacity-40" aria-hidden />
            <Terminal className="relative h-5 w-5 text-primary" />
            <div className="relative flex flex-col">
              <SheetTitle className="text-sm font-semibold leading-tight">
                <span className="text-gradient-primary">BreachPilot</span>
                <span className="text-foreground">AI</span>
              </SheetTitle>
              <SheetDescription className="text-xs uppercase tracking-wide text-muted-foreground">
                {APP_VERSION} beta · {consoleLabel}
              </SheetDescription>
            </div>
          </SheetHeader>
          <nav className="flex flex-1 flex-col gap-1 overflow-y-auto p-2" aria-label="Primary mobile">
            {navItems}
          </nav>
          <div className="border-t p-2">{sidebarFooter}</div>
        </SheetContent>
      </Sheet>

      <main className="flex min-h-0 min-w-0 flex-1 flex-col xl:overflow-hidden">
        <WindowsPerformanceWarning />
        <div className="flex items-center gap-2 border-b px-4 py-1.5">
          <div className="ml-auto flex items-center gap-1">
            <AttentionCentre items={attentionItems} />
            <button
              type="button"
              onClick={() => setPaletteOpen(true)}
              className="hidden h-8 items-center gap-1.5 rounded-md border px-2.5 text-xs text-muted-foreground hover:bg-accent hover:text-foreground md:inline-flex"
              aria-label="Global search (Ctrl+K)"
            >
              Search… <kbd className="rounded border px-1 text-xs">Ctrl K</kbd>
            </button>
          </div>
        </div>
        {mode === "approve" && permBannerDismissed !== "approve" && (
          <div
            className="flex items-center gap-2 border-b border-yellow-500/30 bg-yellow-500/10 px-4 py-1.5 text-[13px] text-yellow-200"
            role="status"
          >
            <ShieldAlert className="h-3.5 w-3.5" />
            <span>Auto-safe approvals: safe decisions auto-handled. Destructive, goals, and campaign checkpoints still wait for you.</span>
            <button
              type="button"
              onClick={() => setPermBannerDismissed("approve")}
              aria-label="Dismiss banner"
              className="ml-auto inline-flex h-4 w-4 items-center justify-center rounded transition-colors hover:bg-foreground/10"
            >
              <X className="h-3.5 w-3.5" />
            </button>
          </div>
        )}
        {mode === "full_access" && permBannerDismissed !== "full_access" && (
          <div
            className="flex items-center gap-2 border-b border-destructive/40 bg-destructive/10 px-4 py-1.5 text-[13px] text-red-200"
            role="status"
          >
            <ShieldAlert className="h-3.5 w-3.5" />
            <span>Autonomous within scope: start/tool approvals auto-handled, including destructive confirmations. Goals and campaign checkpoints still wait for you.</span>
            <button
              type="button"
              onClick={() => setPermBannerDismissed("full_access")}
              aria-label="Dismiss banner"
              className="ml-auto inline-flex h-4 w-4 items-center justify-center rounded transition-colors hover:bg-foreground/10"
            >
              <X className="h-3.5 w-3.5" />
            </button>
          </div>
        )}
        {activeRuns.length > 0 && (
          <div className="relative flex flex-wrap items-center gap-2 overflow-hidden border-b border-yellow-500/30 bg-yellow-500/10 px-4 py-2 text-sm text-yellow-200">
            <Activity className="h-4 w-4" aria-hidden />
            <span className="truncate">{activeRuns.length === 1 ? "An active run is in progress." : `${activeRuns.length} active runs in progress.`}</span>
            {activeRuns.slice(0, 3).map((r) => (
              <NavLink key={r.id} to={`/runs/${r.id}`} className="underline-offset-4 hover:underline">
                {r.target || r.id.slice(0, 8)}
              </NavLink>
            ))}
            {activeRuns.length > 3 && (
              <NavLink to="/runs" className="underline-offset-4 hover:underline">+{activeRuns.length - 3} more</NavLink>
            )}
          </div>
        )}
        {/* No key on the route wrapper: keying by pathname remounts the
            whole subtree (losing tab state, refetching) on every navigation.
            The entrance animation plays once on mount. */}
        <div className="flex min-h-0 flex-1 flex-col overflow-auto min-w-0">
          <Outlet />
        </div>
        <footer className="flex items-center justify-between gap-2 border-t px-4 py-2 text-[13px] text-muted-foreground">
          <span className="inline-flex items-center gap-1.5">
            <Eye className="h-3 w-3" />
            Loopback-only · Authorized use only — operate exclusively against owned or explicitly authorized assets.
          </span>
          <a
            href="https://github.com/braydos-h/BreachPilot"
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1 hover:text-foreground"
          >
            <Github className="h-3 w-3" />
            GitHub
          </a>
        </footer>
      </main>

      <Dialog open={permOpen} onOpenChange={setPermOpen}>
        <DialogContent className="max-w-sm">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <ShieldAlert className="h-4 w-4 text-primary" />
              Approval policy
            </DialogTitle>
            <DialogDescription className="text-sm">
              When should BreachPilot ask you before acting? One policy — permission mode + launch confirmation mapped internally.
            </DialogDescription>
          </DialogHeader>
          <PermissionControl mode={mode} onModeChange={setMode} />
        </DialogContent>
      </Dialog>

      <Dialog open={showHelp} onOpenChange={setShowHelp}>
        <DialogContent className="max-w-3xl">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2 text-xl">
              <ShieldAlert className="h-5 w-5 text-primary" />
              Approval policy
            </DialogTitle>
            <DialogDescription className="text-sm">
              When should BreachPilot ask you before acting? Three levels, one allowlist lock.
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-5">
            <div className="grid gap-2.5 sm:grid-cols-2">
              {(Object.keys(MODE_TITLES) as PermissionMode[]).map((m) => (
                <div
                  key={m}
                  className={cn(
                    "rounded-lg border p-3.5",
                    mode === m ? "border-primary/60 bg-primary/5 ring-1 ring-primary/30" : "border-border bg-card/40",
                  )}
                >
                  <div className="flex items-center justify-between">
                    <span className="text-sm font-semibold">{MODE_TITLES[m]}</span>
                    {mode === m && (
                      <span className="rounded-full bg-primary/15 px-2 py-0.5 text-xs font-medium uppercase tracking-wide text-primary">
                        active
                      </span>
                    )}
                  </div>
                  <p className="mt-1.5 text-[13px] leading-relaxed text-muted-foreground">{MODE_BLURB[m]}</p>
                </div>
              ))}
            </div>

            <div>
              <div className="mb-2 text-[13px] font-medium uppercase tracking-wide text-muted-foreground">
                Demo — what the agent sends for each decision kind
              </div>
              <div className="overflow-hidden rounded-lg border">
                <table className="w-full text-left text-sm">
                  <thead className="bg-muted/40 text-[13px] uppercase tracking-wide text-muted-foreground">
                    <tr>
                      <th className="px-3 py-2.5 font-medium">Decision</th>
                      <th className="px-3 py-2.5 font-medium">Manual approvals</th>
                      <th className="px-3 py-2.5 font-medium">Auto-safe approvals</th>
                      <th className="px-3 py-2.5 font-medium">Autonomous within scope</th>
                    </tr>
                  </thead>
                  <tbody>
                    {DEMO_DECISIONS.map((d) => (
                      <tr key={d.kind} className="border-t">
                        <td className="px-3 py-2.5 text-foreground">{humanizeEnum(d.kind, DECISION_KIND_LABELS)}</td>
                        <td className="px-3 py-2.5 text-muted-foreground">{demoAnswer(d, "read_only")}</td>
                        <td className="px-3 py-2.5 text-yellow-200">{demoAnswer(d, "approve")}</td>
                        <td className="px-3 py-2.5 text-red-300">{demoAnswer(d, "full_access")}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <p className="mt-2 text-[13px] leading-relaxed text-muted-foreground">
                <span className="text-yellow-200">Auto-safe approvals</span> leaves destructive confirmations, goals, and campaign checkpoints to you.
                <span className="text-red-300"> Autonomous within scope</span> auto-submits the exact
                <span className="font-mono"> required_text</span> for destructive confirmations. Goals and campaign checkpoints still wait for you.
              </p>
            </div>

            <DialogDescription asChild>
              <p className="text-[13px] leading-relaxed text-muted-foreground">
                The target-IP allowlist lock still applies in every mode — nothing here escapes the allowlist configured for
                this run.
              </p>
            </DialogDescription>
          </div>
        </DialogContent>
      </Dialog>
      <CommandPalette open={paletteOpen} onOpenChange={setPaletteOpen} />
    </div>
  );
}