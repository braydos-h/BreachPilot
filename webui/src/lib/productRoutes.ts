// Declarative product route registry (todo 20).
// Single source of truth driving: route table, sidebar labels/groups,
// Help directory entries, breadcrumbs. Adding a route without a help entry
// must fail CI (see productRegistry.test).

import {
  BarChart3,
  BookOpen,
  Brain,
  Crosshair,
  FlaskConical,
  GitBranch,
  Home,
  List,
  PlugZap,
  Settings,
  ShieldAlert,
  Sparkles,
  Target,
  type LucideIcon,
} from "lucide-react";

export type NavGroup = "operate" | "knowledge" | "evaluate" | "system";

export interface ProductRoute {
  path: string;
  label: string;
  icon: LucideIcon;
  group: NavGroup;
  helpId: string;
  helpTitle: string;
  helpDescription: string;
  end?: boolean;
}

export const NAV_GROUPS: Array<{ id: NavGroup; label: string; defaultCollapsed: boolean }> = [
  { id: "operate", label: "Operate", defaultCollapsed: false },
  { id: "knowledge", label: "Knowledge", defaultCollapsed: true },
  { id: "evaluate", label: "Evaluate", defaultCollapsed: true },
  { id: "system", label: "System", defaultCollapsed: true },
];

export const PRODUCT_ROUTES: ProductRoute[] = [
  { path: "/", label: "Home", icon: Home, group: "operate", helpId: "home", helpTitle: "Home", helpDescription: "Operator launchpad: resume, needs attention, new run.", end: true },
  { path: "/runs", label: "Runs", icon: List, group: "operate", helpId: "runs", helpTitle: "Runs", helpDescription: "All assessment runs: state, outcome, recency." },
  { path: "/connections", label: "Connections", icon: PlugZap, group: "operate", helpId: "connections", helpTitle: "Connections", helpDescription: "Persisted access channels created during authorized runs." },
  { path: "/graph", label: "Attack Graph", icon: GitBranch, group: "knowledge", helpId: "graph", helpTitle: "Attack Graph", helpDescription: "Attack-path knowledge across runs." },
  { path: "/goals", label: "Goals", icon: Target, group: "knowledge", helpId: "goals", helpTitle: "Goals", helpDescription: "Run objectives and presets." },
  { path: "/modules", label: "Modules", icon: Crosshair, group: "knowledge", helpId: "modules", helpTitle: "Modules", helpDescription: "Attack modules catalogue." },
  { path: "/skills", label: "Skills", icon: Sparkles, group: "knowledge", helpId: "skills", helpTitle: "Skills", helpDescription: "Agent skills catalogue." },
  { path: "/memory", label: "Memory", icon: Brain, group: "knowledge", helpId: "memory", helpTitle: "Memory", helpDescription: "Operator memory and notes." },
  { path: "/benchmarks", label: "Benchmarks", icon: FlaskConical, group: "evaluate", helpId: "benchmarks", helpTitle: "Benchmarks", helpDescription: "Evaluation workspace: runs, history, comparisons." },
  { path: "/stats", label: "Stats", icon: BarChart3, group: "evaluate", helpId: "stats", helpTitle: "Stats", helpDescription: "Usage and outcome statistics." },
  { path: "/ops", label: "Operations", icon: ShieldAlert, group: "system", helpId: "ops", helpTitle: "Operations", helpDescription: "System status rollup (read-only)." },
  { path: "/system", label: "Settings", icon: Settings, group: "system", helpId: "system", helpTitle: "Settings", helpDescription: "Provider, runs, features, integrations, advanced." },
  { path: "/help", label: "Help", icon: BookOpen, group: "system", helpId: "help", helpTitle: "Help", helpDescription: "Operator help and reference." },
];

// Run-scoped satellite pages (todo 32): always render run title + back-to-run.
export const RUN_SATELLITE_ROUTES: Array<{ path: string; label: string; helpId: string }> = [
  { path: "/runs/new", label: "New run", helpId: "new-run" },
  { path: "/runs/:runId", label: "Run detail", helpId: "run-detail" },
  { path: "/runs/:runId/artifacts", label: "Run artifacts", helpId: "run-artifacts" },
  { path: "/runs/:runId/loot", label: "Run credentials", helpId: "run-loot" },
  { path: "/runs/:runId/graph", label: "Run attack path", helpId: "run-graph" },
];

export function breadcrumbsForPath(pathname: string): Array<{ label: string; to?: string }> {
  if (pathname.startsWith("/runs/new")) return [{ label: "Runs", to: "/runs" }, { label: "New run" }];
  const runMatch = pathname.match(/^\/runs\/([^/]+)(?:\/(artifacts|loot|graph))?/);
  if (runMatch) {
    const crumbs: Array<{ label: string; to?: string }> = [
      { label: "Runs", to: "/runs" },
      { label: "Run detail", to: `/runs/${runMatch[1]}` },
    ];
    if (runMatch[2]) crumbs.push({ label: runMatch[2] === "artifacts" ? "Artifacts" : runMatch[2] === "loot" ? "Credentials" : "Attack path" });
    return crumbs;
  }
  const found = PRODUCT_ROUTES.find((r) => r.path === pathname);
  if (found) return [{ label: found.label }];
  if (pathname.startsWith("/benchmarks")) return [{ label: "Benchmarks", to: "/benchmarks" }, { label: "Evaluate" }];
  return [{ label: "Home", to: "/" }];
}
