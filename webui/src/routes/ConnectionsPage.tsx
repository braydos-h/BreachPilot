import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Link } from "react-router-dom";
import {
  Activity,
  AlertTriangle,
  Archive,
  ArrowDown,
  ArrowUp,
  ArrowUpDown,
  CheckCircle2,
  Clock3,
  Eye,
  Layers,
  Loader2,
  PlugZap,
  Radio,
  RefreshCw,
  Search,
  ShieldAlert,
  Trash2,
  Wifi,
  X,
} from "lucide-react";
import { ApiError } from "@/api/client";
import {
  useCheckConnection,
  useConnection,
  useConnectionListener,
  useConnections,
  useRemoveConnection,
} from "@/api/hooks";
import type { ConnectionStatus } from "@/api/types";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { CopyButton } from "@/components/CopyButton";
import { cn } from "@/lib/utils";
import { useToast } from "@/hooks/use-toast";

// ── helpers ───────────────────────────────────────────────────────────────

function humanizeMethod(raw: string): string {
  if (!raw) return "—";
  return raw
    .split("_")
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

const STATUS_RANK: Record<ConnectionStatus, number> = {
  error: 0,
  stale: 1,
  active: 2,
  removed: 3,
};

const STATUS_META: Record<
  ConnectionStatus,
  { label: string; variant: "success" | "warn" | "danger" | "muted"; Icon: typeof CheckCircle2; dot: string }
> = {
  active: { label: "ACTIVE", variant: "success", Icon: CheckCircle2, dot: "bg-emerald-500" },
  stale: { label: "STALE", variant: "warn", Icon: Clock3, dot: "bg-amber-500" },
  removed: { label: "REMOVED", variant: "muted", Icon: Archive, dot: "bg-zinc-400" },
  error: { label: "ERROR", variant: "danger", Icon: AlertTriangle, dot: "bg-red-500" },
};

function formatBeacon(lastBeacon: number | null): string {
  if (lastBeacon == null || lastBeacon === 0) return "Never";
  const diff = Date.now() / 1000 - lastBeacon;
  if (diff < 0) return "just now";
  if (diff < 5) return "just now";
  if (diff < 60) return `${Math.round(diff)}s ago`;
  if (diff < 3600) return `${Math.round(diff / 60)}m ago`;
  if (diff < 86400) {
    const h = Math.floor(diff / 3600);
    const m = Math.round((diff % 3600) / 60);
    return m > 0 ? `${h}h ${m}m ago` : `${h}h ago`;
  }
  const d = Math.round(diff / 86400);
  return `${d}d ago`;
}

function formatAge(createdAt: number): string {
  if (!createdAt) return "—";
  const diff = Date.now() / 1000 - createdAt;
  if (diff < 0) return "just now";
  if (diff < 60) return `${Math.round(diff)}s`;
  if (diff < 3600) {
    const m = Math.floor(diff / 60);
    return `${m}m`;
  }
  if (diff < 86400) {
    const h = Math.floor(diff / 3600);
    const m = Math.floor((diff % 3600) / 60);
    return m > 0 ? `${h}h ${m}m` : `${h}h`;
  }
  const d = Math.floor(diff / 86400);
  if (d < 30) return `${d}d`;
  const mo = Math.floor(d / 30);
  return `${mo}mo`;
}

function formatLastCheck(lastCheck: number | null): string {
  if (lastCheck == null || lastCheck === 0) return "Never checked";
  const diff = Date.now() / 1000 - lastCheck;
  if (diff < 5) return "just now";
  if (diff < 60) return `${Math.round(diff)}s ago`;
  if (diff < 3600) return `${Math.round(diff / 60)}m ago`;
  return `${Math.round(diff / 3600)}h ago`;
}

function formatIsoOrRelative(epoch: number | null, iso?: string): string {
  if (iso) {
    const d = new Date(iso);
    if (!Number.isNaN(d.getTime())) return d.toLocaleString();
  }
  if (epoch == null || epoch === 0) return "—";
  const d = new Date(epoch * 1000);
  return d.toLocaleString();
}

function beaconDotClass(lastBeacon: number | null, status: ConnectionStatus): string {
  if (status === "removed") return "bg-zinc-400";
  if (status === "error") return "bg-red-500";
  if (lastBeacon == null || lastBeacon === 0) return "bg-zinc-400";
  const diff = Date.now() / 1000 - lastBeacon;
  if (diff < 90) return "bg-emerald-500";
  if (diff < 3600) return "bg-amber-500";
  return "bg-zinc-400";
}

// ── status badge ─────────────────────────────────────────────────────────

function ConnectionStatusBadge({ status }: { status: ConnectionStatus }) {
  const meta = STATUS_META[status];
  if (!meta) {
    return (
      <Badge variant="muted" className="gap-1.5 font-mono text-[10px] uppercase tracking-wide">
        <span className="h-1.5 w-1.5 rounded-full bg-zinc-400" aria-hidden />
        {status?.toUpperCase() ?? "UNKNOWN"}
      </Badge>
    );
  }
  const Icon = meta.Icon;
  return (
    <Badge variant={meta.variant} className="gap-1.5 font-mono text-[10px] uppercase tracking-wide">
      <span className={cn("h-1.5 w-1.5 rounded-full", meta.dot)} aria-hidden />
      <Icon className="h-3 w-3" aria-hidden />
      {meta.label}
    </Badge>
  );
}

// ── main page ─────────────────────────────────────────────────────────────

type FilterKey = "all" | ConnectionStatus;
type SortKey = "status" | "target" | "created" | "beacon" | "method";
type SortDir = "asc" | "desc";

const FILTER_OPTIONS: { key: FilterKey; label: string; Icon: typeof Layers }[] = [
  { key: "all", label: "All", Icon: Layers },
  { key: "active", label: "Active", Icon: CheckCircle2 },
  { key: "stale", label: "Stale", Icon: Clock3 },
  { key: "removed", label: "Removed", Icon: Archive },
  { key: "error", label: "Error", Icon: AlertTriangle },
];

export function ConnectionsPage() {
  const { toast } = useToast();
  const connectionsQuery = useConnections();
  const [filter, setFilter] = useState<FilterKey>("all");
  const [search, setSearch] = useState("");
  const [debouncedSearch, setDebouncedSearch] = useState("");
  const [sortKey, setSortKey] = useState<SortKey>("status");
  const [sortDir, setSortDir] = useState<SortDir>("asc");
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [drawerOpen, setDrawerOpen] = useState(false);

  useEffect(() => {
    const t = setTimeout(() => setDebouncedSearch(search.trim().toLowerCase()), 250);
    return () => clearTimeout(t);
  }, [search]);

  const raw = connectionsQuery.data?.connections ?? [];
  const counts = useMemo(() => {
    const c = connectionsQuery.data;
    if (c) return { total: c.total, active: c.active, stale: c.stale, removed: c.removed, error: c.error };
    return {
      total: raw.length,
      active: raw.filter((r) => r.status === "active").length,
      stale: raw.filter((r) => r.status === "stale").length,
      removed: raw.filter((r) => r.status === "removed").length,
      error: raw.filter((r) => r.status === "error").length,
    };
  }, [raw, connectionsQuery.data]);

  const filtered = useMemo(() => {
    let out = [...raw];
    if (filter !== "all") out = out.filter((r) => r.status === filter);
    if (debouncedSearch) {
      const q = debouncedSearch;
      out = out.filter((r) => {
        const hay = [
          r.target_ip,
          r.connection_id,
          r.method,
          r.listener_name,
          r.os_family,
          r.mitre_technique,
          r.notes,
          r.callback_host,
        ]
          .join(" ")
          .toLowerCase();
        return hay.includes(q);
      });
    }
    return out;
  }, [raw, filter, debouncedSearch]);

  const sorted = useMemo(() => {
    const arr = [...filtered];
    const rank = (s: string) => STATUS_RANK[s as ConnectionStatus] ?? 99;
    arr.sort((a, b) => {
      let cmp = 0;
      if (sortKey === "status") {
        cmp = rank(a.status) - rank(b.status);
        if (cmp === 0) cmp = b.created_at - a.created_at;
      } else if (sortKey === "target") {
        cmp = a.target_ip.localeCompare(b.target_ip);
      } else if (sortKey === "created") {
        cmp = a.created_at - b.created_at;
      } else if (sortKey === "beacon") {
        const av = a.last_beacon ?? 0;
        const bv = b.last_beacon ?? 0;
        cmp = av - bv;
      } else if (sortKey === "method") {
        cmp = a.method.localeCompare(b.method);
      }
      if (cmp === 0) cmp = b.created_at - a.created_at;
      return sortDir === "asc" ? cmp : -cmp;
    });
    return arr;
  }, [filtered, sortKey, sortDir]);

  const onSort = (key: SortKey) => {
    if (sortKey === key) setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    else {
      setSortKey(key);
      setSortDir(key === "status" ? "asc" : "asc");
    }
  };

  const openDrawer = (id: string) => {
    setSelectedId(id);
    setDrawerOpen(true);
  };

  const isLoading = connectionsQuery.isLoading;
  const isError = !!connectionsQuery.error;
  const isEmpty = !isLoading && !isError && raw.length === 0;
  const hasActiveFilters = filter !== "all" || debouncedSearch.length > 0;
  const clearFilters = () => {
    setFilter("all");
    setSearch("");
  };

  return (
    <TooltipProvider delayDuration={150}>
      <div className="mx-auto flex max-w-[1600px] flex-col gap-4 p-4 md:p-6">
        {/* Header */}
        <header className="flex flex-col gap-4">
          <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
            <div className="flex min-w-0 items-start gap-3">
              <div
                className="hidden h-10 w-10 shrink-0 items-center justify-center rounded-xl border bg-card shadow-sm sm:flex"
                aria-hidden
              >
                <PlugZap className="h-5 w-5 text-foreground" />
              </div>
              <div className="min-w-0">
                <h1 className="text-xl font-semibold leading-tight tracking-tight">Connections</h1>
                <p className="mt-1 max-w-2xl text-sm leading-relaxed text-muted-foreground">
                  Persisted operator access channels created during authorized runs. Monitor beacon health and manage
                  lifecycle — creations are automatic after successful persistence.
                </p>
              </div>
            </div>
            <div className="flex shrink-0 items-center gap-2">
              <Button
                size="sm"
                variant="outline"
                onClick={() => void connectionsQuery.refetch()}
                disabled={connectionsQuery.isFetching}
                aria-label="Refresh connections"
                className="h-8 gap-1.5"
              >
                <RefreshCw className={cn("h-3.5 w-3.5", connectionsQuery.isFetching && "animate-spin")} />
                Refresh
              </Button>
            </div>
          </div>

          {/* Stat strip — mirrors Skills/Goals pattern */}
          <div className="grid grid-cols-2 gap-px overflow-hidden rounded-xl border bg-border sm:grid-cols-4">
            <HeaderStat label="Active" value={counts.active} accent="emerald" Icon={CheckCircle2} loading={isLoading} />
            <HeaderStat label="Stale" value={counts.stale} accent="amber" Icon={Clock3} loading={isLoading} />
            <HeaderStat label="Error" value={counts.error} accent="red" Icon={AlertTriangle} loading={isLoading} />
            <HeaderStat label="Total" value={counts.total} Icon={Layers} loading={isLoading} />
          </div>
        </header>

        {/* Toolbar: filters + search */}
        <div className="flex flex-col gap-3">
          <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
            <div className="flex flex-wrap items-center gap-1.5" role="tablist" aria-label="Filter by status">
              {FILTER_OPTIONS.map((opt) => {
                const count =
                  opt.key === "all"
                    ? counts.total
                    : opt.key === "active"
                      ? counts.active
                      : opt.key === "stale"
                        ? counts.stale
                        : opt.key === "removed"
                          ? counts.removed
                          : counts.error;
                const active = filter === opt.key;
                const Icon = opt.Icon;
                return (
                  <button
                    key={opt.key}
                    type="button"
                    role="tab"
                    aria-selected={active}
                    onClick={() => setFilter(opt.key)}
                    className={cn(
                      "inline-flex items-center gap-1.5 rounded-full border px-3 py-1.5 text-xs font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-1",
                      active
                        ? "border-primary/60 bg-primary text-primary-foreground shadow-sm"
                        : "border-border bg-card text-muted-foreground hover:bg-accent hover:text-foreground",
                    )}
                  >
                    <Icon className="h-3.5 w-3.5" aria-hidden />
                    {opt.label}
                    <span
                      className={cn(
                        "ml-0.5 rounded-full px-1.5 py-0 text-[10px] tabular-nums",
                        active ? "bg-primary-foreground/15 text-primary-foreground" : "bg-muted text-muted-foreground",
                      )}
                    >
                      {count}
                    </span>
                  </button>
                );
              })}
            </div>

            <div className="flex items-center gap-2">
              <div className="relative w-full sm:w-72">
                <Search
                  className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground"
                  aria-hidden
                />
                <Input
                  placeholder="Search target, listener, method, MITRE..."
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  className="h-8 pl-8 pr-8 text-sm"
                  aria-label="Search connections"
                />
                {search && (
                  <button
                    type="button"
                    onClick={() => setSearch("")}
                    aria-label="Clear search"
                    className="absolute right-1 top-1/2 -translate-y-1/2 rounded p-1.5 text-muted-foreground transition-colors hover:bg-accent hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                  >
                    <X className="h-3.5 w-3.5" />
                  </button>
                )}
              </div>
              {/* Mobile sort */}
              <div className="hidden items-center gap-1.5 sm:flex lg:hidden">
                <span className="text-xs text-muted-foreground">Sort</span>
                <select
                  value={`${sortKey}:${sortDir}`}
                  onChange={(e) => {
                    const [k, d] = e.target.value.split(":") as [SortKey, SortDir];
                    setSortKey(k);
                    setSortDir(d);
                  }}
                  className="h-8 rounded-md border border-input bg-background px-2 text-xs"
                  aria-label="Sort connections"
                >
                  <option value="status:asc">Status</option>
                  <option value="target:asc">Target A→Z</option>
                  <option value="target:desc">Target Z→A</option>
                  <option value="beacon:desc">Recent beacon</option>
                  <option value="beacon:asc">Oldest beacon</option>
                  <option value="created:desc">Newest</option>
                  <option value="method:asc">Method</option>
                </select>
              </div>
            </div>
          </div>

          {/* Active filter footer */}
          {(hasActiveFilters || sorted.length !== raw.length) && !isLoading && !isError && !isEmpty && (
            <div className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
              <span>
                Showing <span className="font-medium tabular-nums text-foreground">{sorted.length}</span> of{" "}
                <span className="tabular-nums">{raw.length}</span> connection{raw.length !== 1 ? "s" : ""}
                {filter !== "all" && (
                  <>
                    {" "}
                    · filtered to <span className="font-medium text-foreground">{filter}</span>
                  </>
                )}
                {debouncedSearch && (
                  <>
                    {" "}
                    · search <span className="font-mono text-foreground">“{debouncedSearch}”</span>
                  </>
                )}
              </span>
              {hasActiveFilters && (
                <Button variant="ghost" size="sm" className="h-6 px-2 text-xs" onClick={clearFilters}>
                  Clear filters
                </Button>
              )}
            </div>
          )}
        </div>

        {/* States */}
        {isLoading && <ConnectionsSkeleton />}

        {isError && (
          <div className="flex flex-wrap items-center gap-2 rounded-md border border-destructive/40 bg-destructive/10 p-3 text-sm">
            <AlertTriangle className="h-4 w-4 shrink-0 text-destructive" aria-hidden />
            <span className="flex-1 text-destructive">
              {connectionsQuery.error instanceof ApiError ? connectionsQuery.error.message : "Failed to load connections."}
            </span>
            <Button size="sm" variant="outline" onClick={() => void connectionsQuery.refetch()}>
              Retry
            </Button>
          </div>
        )}

        {isEmpty && !isLoading && !isError && (
          <Card className="border-dashed">
            <CardContent className="flex flex-col items-center justify-center gap-3 p-8 text-center">
              <span className="flex h-10 w-10 items-center justify-center rounded-full bg-primary/10 text-primary">
                <Radio className="h-5 w-5" />
              </span>
              <div className="space-y-1">
                <h2 className="font-medium">No persisted connections</h2>
                <p className="mx-auto max-w-md text-sm leading-relaxed text-muted-foreground">
                  Channels appear here automatically after the persistence phase succeeds in an authorized assessment run.
                  No manual setup is required — check sessions for recent activity.
                </p>
              </div>
              <Button asChild size="sm" variant="outline">
                <Link to="/sessions">View sessions</Link>
              </Button>
            </CardContent>
          </Card>
        )}

        {!isLoading && !isError && !isEmpty && filtered.length === 0 && (
          <div className="flex flex-col items-center gap-2 rounded-lg border border-dashed p-8 text-center">
            <Search className="h-6 w-6 text-muted-foreground/40" aria-hidden />
            <p className="text-sm font-medium">No connections match your filters</p>
            <p className="text-xs text-muted-foreground">
              {debouncedSearch ? `No results for “${debouncedSearch}”` : `No ${filter} connections found.`} Try adjusting filters or
              search.
            </p>
            <Button size="sm" variant="outline" className="mt-1" onClick={clearFilters}>
              Clear filters
            </Button>
          </div>
        )}

        {!isLoading && !isError && sorted.length > 0 && (
          <>
            {/* Desktop table */}
            <div className="hidden overflow-hidden rounded-lg border md:block">
              <div className="overflow-x-auto">
                <table className="w-full border-collapse text-sm">
                  <caption className="sr-only">Operator connections</caption>
                  <thead>
                    <tr>
                      <SortTh label="Target" sortKey="target" activeKey={sortKey} dir={sortDir} onSort={onSort} />
                      <SortTh label="Method" sortKey="method" activeKey={sortKey} dir={sortDir} onSort={onSort} />
                      <SortTh label="Status" sortKey="status" activeKey={sortKey} dir={sortDir} onSort={onSort} />
                      <th scope="col" className="whitespace-nowrap px-3 py-2.5 text-left text-[11px] font-medium uppercase tracking-wide">
                        Callback
                      </th>
                      <th scope="col" className="whitespace-nowrap px-3 py-2.5 text-left text-[11px] font-medium uppercase tracking-wide">
                        Listener
                      </th>
                      <SortTh label="Last beacon" sortKey="beacon" activeKey={sortKey} dir={sortDir} onSort={onSort} />
                      <SortTh label="Age" sortKey="created" activeKey={sortKey} dir={sortDir} onSort={onSort} />
                      <th scope="col" className="px-3 py-2.5 text-right text-[11px] font-medium uppercase tracking-wide">
                        <span className="sr-only">Actions</span>
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    {sorted.map((conn) => (
                      <tr
                        key={conn.connection_id}
                        onClick={() => openDrawer(conn.connection_id)}
                        onKeyDown={(e) => {
                          if (e.key === "Enter" || e.key === " ") {
                            e.preventDefault();
                            openDrawer(conn.connection_id);
                          }
                        }}
                        tabIndex={0}
                        role="button"
                        aria-label={`Open details for ${conn.target_ip} ${conn.connection_id}`}
                        className="group cursor-pointer focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-inset"
                      >
                        <td className="whitespace-nowrap px-3 py-2.5">
                          <span className="font-mono text-xs font-medium">{conn.target_ip}</span>
                        </td>
                        <td className="px-3 py-2.5">
                          <div className="flex flex-col gap-1">
                            <span className="text-xs font-medium leading-none">{humanizeMethod(conn.method)}</span>
                            <span className="flex items-center gap-1.5 text-[10px] text-muted-foreground">
                              {conn.os_family && (
                                <span className="inline-flex items-center rounded bg-muted px-1 py-0 font-medium capitalize">
                                  {conn.os_family}
                                </span>
                              )}
                              {conn.mitre_technique && (
                                <span className="font-mono">{conn.mitre_technique}</span>
                              )}
                              {!conn.os_family && !conn.mitre_technique && (
                                <span className="font-mono opacity-60">{conn.method}</span>
                              )}
                            </span>
                          </div>
                        </td>
                        <td className="px-3 py-2.5">
                          <ConnectionStatusBadge status={conn.status} />
                        </td>
                        <td className="whitespace-nowrap px-3 py-2.5 font-mono text-xs">
                          {conn.callback_host}:{conn.callback_port}
                        </td>
                        <td className="max-w-[14rem] px-3 py-2.5">
                          <Tooltip>
                            <TooltipTrigger asChild>
                              <span className="block truncate font-mono text-xs" title={conn.listener_name}>
                                {conn.listener_name || "—"}
                              </span>
                            </TooltipTrigger>
                            {conn.listener_name && conn.listener_name.length > 18 && (
                              <TooltipContent className="max-w-xs break-all font-mono text-xs">
                                {conn.listener_name}
                              </TooltipContent>
                            )}
                          </Tooltip>
                        </td>
                        <td className="whitespace-nowrap px-3 py-2.5">
                          <span className="inline-flex items-center gap-1.5 text-xs tabular-nums">
                            <span className={cn("h-1.5 w-1.5 rounded-full", beaconDotClass(conn.last_beacon, conn.status))} aria-hidden />
                            {formatBeacon(conn.last_beacon)}
                          </span>
                        </td>
                        <td className="whitespace-nowrap px-3 py-2.5 text-xs tabular-nums text-muted-foreground">
                          {formatAge(conn.created_at)}
                        </td>
                        <td className="px-3 py-2.5 text-right">
                          <Button
                            size="sm"
                            variant="ghost"
                            className="h-7 gap-1 px-2 text-xs opacity-60 group-hover:opacity-100 group-focus-within:opacity-100"
                            onClick={(e) => {
                              e.stopPropagation();
                              openDrawer(conn.connection_id);
                            }}
                            aria-label={`View ${conn.target_ip}`}
                          >
                            <Eye className="h-3.5 w-3.5" />
                            View
                          </Button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            {/* Mobile cards */}
            <div className="grid gap-3 md:hidden">
              {sorted.map((conn) => (
                <Card
                  key={conn.connection_id}
                  className="group cursor-pointer overflow-hidden bg-card/40 transition-colors hover:border-primary/20 focus-within:ring-2 focus-within:ring-ring"
                  onClick={() => openDrawer(conn.connection_id)}
                  role="button"
                  tabIndex={0}
                  onKeyDown={(e) => {
                    if (e.key === "Enter" || e.key === " ") {
                      e.preventDefault();
                      openDrawer(conn.connection_id);
                    }
                  }}
                  aria-label={`Open details for ${conn.target_ip}`}
                >
                  <CardContent className="space-y-2.5 p-3">
                    <div className="flex items-start justify-between gap-2">
                      <div className="min-w-0">
                        <div className="flex items-center gap-1.5">
                          <span className={cn("h-1.5 w-1.5 rounded-full", beaconDotClass(conn.last_beacon, conn.status))} aria-hidden />
                          <span className="truncate font-mono text-sm font-semibold">{conn.target_ip}</span>
                        </div>
                        <div className="mt-0.5 flex flex-wrap items-center gap-1.5 text-xs text-muted-foreground">
                          <span className="font-medium text-foreground">{humanizeMethod(conn.method)}</span>
                          {conn.os_family && (
                            <>
                              <span>·</span>
                              <span className="capitalize">{conn.os_family}</span>
                            </>
                          )}
                          {conn.mitre_technique && (
                            <>
                              <span>·</span>
                              <span className="font-mono text-[11px]">{conn.mitre_technique}</span>
                            </>
                          )}
                        </div>
                      </div>
                      <ConnectionStatusBadge status={conn.status} />
                    </div>

                    <div className="grid gap-1.5 rounded-md border bg-muted/20 p-2">
                      <div className="flex items-center justify-between gap-2 text-xs">
                        <span className="text-[10px] uppercase tracking-wide text-muted-foreground">Callback</span>
                        <span className="truncate font-mono text-xs">{conn.callback_host}:{conn.callback_port}</span>
                      </div>
                      <div className="flex items-center justify-between gap-2 text-xs">
                        <span className="text-[10px] uppercase tracking-wide text-muted-foreground">Listener</span>
                        <span className="max-w-[10rem] truncate font-mono text-xs" title={conn.listener_name}>
                          {conn.listener_name || "—"}
                        </span>
                      </div>
                    </div>

                    <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs">
                      <span className="inline-flex items-center gap-1.5 tabular-nums">
                        <Activity className="h-3 w-3 text-muted-foreground" aria-hidden />
                        {formatBeacon(conn.last_beacon)}
                      </span>
                      <span className="text-muted-foreground">·</span>
                      <span className="tabular-nums text-muted-foreground">{formatAge(conn.created_at)} ago</span>
                      <span className="ml-auto inline-flex items-center gap-1 text-muted-foreground">
                        <Eye className="h-3 w-3" />
                        View details
                      </span>
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          </>
        )}

        {/* Details drawer */}
        {selectedId && (
          <ConnectionDetailsDrawer
            connectionId={selectedId}
            open={drawerOpen}
            onOpenChange={(open) => {
              setDrawerOpen(open);
              if (!open) setSelectedId(null);
            }}
            onRemoveSuccess={() => {
              setDrawerOpen(false);
              setSelectedId(null);
            }}
            toast={toast}
          />
        )}
      </div>
    </TooltipProvider>
  );
}

function SortTh({
  label,
  sortKey,
  activeKey,
  dir,
  onSort,
}: {
  label: string;
  sortKey: SortKey;
  activeKey: SortKey;
  dir: SortDir;
  onSort: (k: SortKey) => void;
}) {
  const active = activeKey === sortKey;
  return (
    <th scope="col" className="whitespace-nowrap px-3 py-2.5 text-left">
      <button
        type="button"
        onClick={() => onSort(sortKey)}
        className={cn(
          "inline-flex items-center gap-1 text-[11px] font-medium uppercase tracking-wide transition-colors hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-1",
          active ? "text-foreground" : "text-muted-foreground",
        )}
        aria-label={`Sort by ${label} ${active && dir === "asc" ? "descending" : "ascending"}`}
      >
        {label}
        <span aria-hidden className={cn("ml-0.5", active ? "opacity-100" : "opacity-40")}>
          {active ? dir === "asc" ? <ArrowUp className="h-3 w-3" /> : <ArrowDown className="h-3 w-3" /> : <ArrowUpDown className="h-3 w-3" />}
        </span>
      </button>
    </th>
  );
}

function HeaderStat({
  label,
  value,
  accent,
  Icon,
  loading,
}: {
  label: string;
  value: number;
  accent?: "emerald" | "amber" | "red";
  Icon: typeof Layers;
  loading: boolean;
}) {
  const accentClass =
    accent === "emerald"
      ? "text-emerald-600 dark:text-emerald-300"
      : accent === "amber"
        ? "text-amber-600 dark:text-amber-300"
        : accent === "red"
          ? "text-red-600 dark:text-red-300"
          : "text-foreground";
  return (
    <div className="flex items-center gap-2.5 bg-card px-4 py-3">
      <Icon className={cn("h-4 w-4 shrink-0", accent ? accentClass : "text-muted-foreground")} aria-hidden />
      <div className="min-w-0">
        <div className={cn("font-mono text-xl font-semibold leading-none tabular-nums", accentClass)}>
          {loading ? <Skeleton className="h-6 w-10" /> : value}
        </div>
        <div className="text-[10px] uppercase tracking-wide text-muted-foreground">{label}</div>
      </div>
    </div>
  );
}

function ConnectionsSkeleton() {
  return (
    <div className="space-y-3" role="status" aria-label="Loading connections">
      <div className="overflow-hidden rounded-lg border">
        <div className="divide-y">
          <div className="flex items-center gap-3 bg-muted/20 px-3 py-2.5">
            {Array.from({ length: 7 }).map((_, i) => (
              <Skeleton key={i} className="h-3 flex-1" />
            ))}
          </div>
          {Array.from({ length: 5 }).map((_, i) => (
            <div key={i} className="flex items-center gap-3 px-3 py-3">
              <Skeleton className="h-4 w-24" />
              <Skeleton className="h-4 w-28" />
              <Skeleton className="h-5 w-16" />
              <Skeleton className="h-4 w-32" />
              <Skeleton className="h-4 flex-1" />
              <Skeleton className="h-4 w-20" />
              <Skeleton className="h-4 w-12" />
            </div>
          ))}
        </div>
      </div>
      <div className="grid gap-3 md:hidden">
        {Array.from({ length: 3 }).map((_, i) => (
          <Card key={i} className="p-3">
            <div className="space-y-2">
              <div className="flex justify-between">
                <Skeleton className="h-4 w-24" />
                <Skeleton className="h-5 w-14" />
              </div>
              <Skeleton className="h-3 w-full" />
              <Skeleton className="h-12 w-full" />
            </div>
          </Card>
        ))}
      </div>
    </div>
  );
}

// ── Details drawer ───────────────────────────────────────────────────────

function ConnectionDetailsDrawer({
  connectionId,
  open,
  onOpenChange,
  onRemoveSuccess,
  toast,
}: {
  connectionId: string;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onRemoveSuccess: () => void;
  toast: ReturnType<typeof useToast>["toast"];
}) {
  const connQuery = useConnection(open ? connectionId : null, open);
  const listenerEnabled = open && connQuery.data?.status !== "removed";
  const listenerQuery = useConnectionListener(open ? connectionId : null, listenerEnabled);
  const checkMutation = useCheckConnection();
  const removeMutation = useRemoveConnection();
  const [showRemoveDialog, setShowRemoveDialog] = useState(false);
  const [listenerAutoScroll, setListenerAutoScroll] = useState(true);
  const outputRef = useRef<HTMLPreElement>(null);
  const conn = connQuery.data;

  useEffect(() => {
    if (!listenerAutoScroll) return;
    const el = outputRef.current;
    if (!el) return;
    el.scrollTop = el.scrollHeight;
  }, [listenerQuery.data?.output, listenerAutoScroll]);

  const handleScroll = useCallback(() => {
    const el = outputRef.current;
    if (!el) return;
    const nearBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 40;
    setListenerAutoScroll(nearBottom);
  }, []);

  const onCheck = () => {
    if (checkMutation.isPending) return;
    checkMutation.mutate(connectionId, {
      onSuccess: () => {
        toast({ title: "Health check complete", description: "Connection status updated." });
      },
      onError: (err) => {
        toast({
          title: "Health check failed",
          description: err instanceof ApiError ? err.message : "Could not check connection.",
          variant: "destructive" as unknown as string,
        } as unknown as Parameters<typeof toast>[0]);
      },
    });
  };

  const onRemove = () => {
    if (removeMutation.isPending) return;
    removeMutation.mutate(connectionId, {
      onSuccess: () => {
        toast({ title: "Connection removed", description: `${conn?.target_ip ?? connectionId} marked as removed.` });
        setShowRemoveDialog(false);
        onRemoveSuccess();
      },
      onError: (err) => {
        toast({
          title: "Removal failed",
          description: err instanceof ApiError ? err.message : "Could not remove connection.",
          variant: "destructive" as unknown as string,
        } as unknown as Parameters<typeof toast>[0]);
      },
    });
  };

  const guidance = useMemo(() => {
    if (!conn) return null;
    if (conn.status === "active") {
      const diff = conn.last_beacon ? Date.now() / 1000 - conn.last_beacon : Infinity;
      if (diff < 120) return { text: "Healthy — recent beacon. No action needed.", tone: "emerald" as const };
      if (diff < 3600) return { text: "Beacon recent but not immediate. Monitor or Check if needed.", tone: "muted" as const };
      return { text: "No recent beacon despite active status — consider running Check.", tone: "amber" as const };
    }
    if (conn.status === "stale") return { text: "Degraded — no recent beacon. Run Check to verify, then Remove if decommissioned.", tone: "amber" as const };
    if (conn.status === "error") return { text: "Failing — last health check reported an error. Verify listener and run Check again.", tone: "red" as const };
    if (conn.status === "removed") return { text: "Disabled — this record is retained for audit but no longer active. Listener cleanup was attempted.", tone: "muted" as const };
    return null;
  }, [conn]);

  return (
    <>
      <Dialog open={open} onOpenChange={onOpenChange}>
        <DialogContent
          className={cn(
            "flex max-h-[90vh] max-w-[560px] flex-col gap-0 overflow-hidden p-0",
            "data-[state=open]:animate-in data-[state=closed]:animate-out",
            "sm:max-w-[560px]",
            "md:fixed md:inset-y-0 md:right-0 md:left-auto md:top-0 md:h-dvh md:max-h-dvh md:w-[520px] md:max-w-[92vw] md:translate-x-0 md:translate-y-0 md:rounded-l-lg md:rounded-r-none md:border-l",
          )}
          aria-describedby={undefined}
        >
          <div className="flex min-h-0 flex-1 flex-col overflow-hidden">
            {/* Header */}
            <div className="shrink-0 border-b px-5 py-4">
              <div className="flex items-start justify-between gap-3 pr-6">
                <div className="min-w-0">
                  <h2 className="text-sm font-semibold tracking-tight">Connection Details</h2>
                  <p className="mt-0.5 truncate font-mono text-xs text-muted-foreground" title={connectionId}>
                    {connectionId}
                  </p>
                  {conn && (
                    <div className="mt-2 flex flex-wrap items-center gap-2 text-xs">
                      <span className="font-mono font-medium">{conn.target_ip}</span>
                      <span className="text-muted-foreground">·</span>
                      <span>{humanizeMethod(conn.method)}</span>
                    </div>
                  )}
                </div>
                {conn && <ConnectionStatusBadge status={conn.status} />}
              </div>
              {guidance && (
                <div
                  className={cn(
                    "mt-3 rounded-md border px-3 py-2 text-xs leading-relaxed",
                    guidance.tone === "emerald" && "border-emerald-500/20 bg-emerald-500/5 text-emerald-700 dark:text-emerald-300",
                    guidance.tone === "amber" && "border-amber-500/20 bg-amber-500/5 text-amber-700 dark:text-amber-300",
                    guidance.tone === "red" && "border-destructive/20 bg-destructive/5 text-destructive",
                    guidance.tone === "muted" && "border-border bg-muted/30 text-muted-foreground",
                  )}
                >
                  {guidance.text}
                </div>
              )}
            </div>

            {/* Body */}
            <div className="min-h-0 flex-1 overflow-y-auto scrollbar-thin">
              {connQuery.isLoading && (
                <div className="space-y-3 p-5" role="status" aria-label="Loading connection">
                  <Skeleton className="h-4 w-3/4" />
                  <Skeleton className="h-4 w-1/2" />
                  <Skeleton className="h-20 w-full" />
                  <Skeleton className="h-32 w-full" />
                </div>
              )}
              {connQuery.error && (
                <div className="p-5">
                  <div className="flex items-center gap-2 text-sm text-destructive">
                    <AlertTriangle className="h-4 w-4" />
                    <span>{connQuery.error instanceof ApiError ? connQuery.error.message : "Failed to load connection."}</span>
                  </div>
                  <Button size="sm" variant="outline" className="mt-3" onClick={() => void connQuery.refetch()}>
                    Retry
                  </Button>
                </div>
              )}
              {conn && (
                <div className="space-y-5 p-5">
                  {/* Identity */}
                  <section className="space-y-3">
                    <h3 className="text-[11px] font-semibold uppercase tracking-wide text-muted-foreground">Identity</h3>
                    <div className="grid gap-px overflow-hidden rounded-lg border bg-border">
                      <DetailRow label="Target" value={conn.target_ip} mono copyValue={conn.target_ip} />
                      <DetailRow label="Connection" value={conn.connection_id} mono copyValue={conn.connection_id} />
                      <DetailRow label="Method" value={humanizeMethod(conn.method)} sub={conn.method} />
                      <DetailRow label="OS" value={conn.os_family || "Unknown"} />
                      <DetailRow label="MITRE Technique" value={conn.mitre_technique || "—"} mono={!!conn.mitre_technique} />
                      <DetailRow label="Implant Path" value={conn.implant_path || "—"} mono copyValue={conn.implant_path || undefined} />
                      {conn.notes && <DetailRow label="Notes" value={conn.notes} />}
                    </div>
                  </section>

                  {/* Network */}
                  <section className="space-y-3">
                    <h3 className="text-[11px] font-semibold uppercase tracking-wide text-muted-foreground">Network</h3>
                    <div className="grid gap-px overflow-hidden rounded-lg border bg-border">
                      <DetailRow
                        label="Callback"
                        value={`${conn.callback_host}:${conn.callback_port}`}
                        mono
                        copyValue={`${conn.callback_host}:${conn.callback_port}`}
                      />
                      <DetailRow label="Listener" value={conn.listener_name || "—"} mono copyValue={conn.listener_name} />
                    </div>
                  </section>

                  {/* Timeline */}
                  <section className="space-y-3">
                    <h3 className="text-[11px] font-semibold uppercase tracking-wide text-muted-foreground">Timeline</h3>
                    <div className="grid gap-px overflow-hidden rounded-lg border bg-border">
                      <DetailRow label="Created" value={formatIsoOrRelative(conn.created_at, conn.created_at_iso)} sub={`${formatAge(conn.created_at)} ago`} />
                      <DetailRow
                        label="Last Beacon"
                        value={conn.last_beacon ? formatIsoOrRelative(conn.last_beacon, conn.last_beacon_iso) : "Never"}
                        sub={formatBeacon(conn.last_beacon)}
                      />
                      <DetailRow
                        label="Last Health Check"
                        value={conn.last_check ? formatIsoOrRelative(conn.last_check, conn.last_check_iso) : "Never"}
                        sub={conn.last_check ? formatLastCheck(conn.last_check) : undefined}
                      />
                    </div>
                    {conn.check_output && (
                      <div className="space-y-1">
                        <span className="text-[10px] font-medium uppercase tracking-wide text-muted-foreground">
                          Last check output
                        </span>
                        <pre className="max-h-28 overflow-auto rounded-md border bg-muted/40 p-2 font-mono text-xs leading-relaxed whitespace-pre-wrap break-words scrollbar-thin">
                          {conn.check_output}
                        </pre>
                      </div>
                    )}
                  </section>

                  {/* Health check */}
                  <section className="space-y-2 rounded-lg border bg-card/40 p-3">
                    <h3 className="text-xs font-semibold">Health Check</h3>
                    <p className="text-xs leading-relaxed text-muted-foreground">
                      Probes the listener process and updates status to <span className="font-medium">active</span> or{" "}
                      <span className="font-medium">stale</span>. Uses the existing check endpoint — no new credentials are exposed.
                    </p>
                    <div className="flex flex-wrap items-center gap-2">
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={onCheck}
                        disabled={checkMutation.isPending || conn.status === "removed"}
                        aria-label="Check connection"
                        className="gap-1.5"
                      >
                        {checkMutation.isPending ? (
                          <>
                            <Loader2 className="h-3.5 w-3.5 animate-spin" />
                            Checking...
                          </>
                        ) : (
                          <>
                            <ShieldAlert className="h-3.5 w-3.5" />
                            Check connection
                          </>
                        )}
                      </Button>
                      {conn.last_check != null && conn.last_check !== 0 && (
                        <span className="text-xs text-muted-foreground">Last checked {formatLastCheck(conn.last_check)}</span>
                      )}
                    </div>
                    {checkMutation.isError && (
                      <p className="text-xs text-destructive">
                        {checkMutation.error instanceof ApiError ? checkMutation.error.message : "Health check failed."}
                      </p>
                    )}
                  </section>

                  {/* Listener output */}
                  <section className="space-y-2">
                    <div className="flex items-center justify-between gap-2">
                      <h3 className="text-[11px] font-semibold uppercase tracking-wide text-muted-foreground">Listener Output</h3>
                      <div className="flex items-center gap-1.5">
                        {listenerQuery.isFetching && conn.status === "active" && (
                          <span className="inline-flex items-center gap-1 text-[10px] font-medium uppercase tracking-wide text-emerald-600 dark:text-emerald-300">
                            <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-emerald-500" aria-hidden />
                            Live
                          </span>
                        )}
                        <Button
                          size="sm"
                          variant="ghost"
                          className="h-7 px-2 text-xs"
                          onClick={() => void listenerQuery.refetch()}
                          disabled={listenerQuery.isFetching}
                          aria-label="Refresh listener output"
                        >
                          <RefreshCw className={cn("h-3 w-3", listenerQuery.isFetching && "animate-spin")} />
                          Refresh
                        </Button>
                      </div>
                    </div>

                    {listenerQuery.isLoading && (
                      <div className="rounded-md border bg-muted/20 p-3" role="status" aria-label="Loading listener output">
                        <div className="flex items-center gap-2 text-xs text-muted-foreground">
                          <Loader2 className="h-3.5 w-3.5 animate-spin" />
                          Loading listener output...
                        </div>
                      </div>
                    )}

                    {listenerQuery.error && (
                      <div className="rounded-md border border-destructive/30 bg-destructive/5 p-3 text-xs text-destructive">
                        {listenerQuery.error instanceof ApiError ? listenerQuery.error.message : "Failed to load listener output."}
                        <Button size="sm" variant="outline" className="ml-2 h-6 text-xs" onClick={() => void listenerQuery.refetch()}>
                          Retry
                        </Button>
                      </div>
                    )}

                    {!listenerQuery.isLoading && !listenerQuery.error && listenerQuery.data && (
                      <>
                        {listenerQuery.data.status === "not_found" || listenerQuery.data.output.startsWith("LOG_NOT_FOUND") ? (
                          <div className="rounded-md border border-dashed p-4 text-center text-xs text-muted-foreground">
                            <Wifi className="mx-auto h-5 w-5 opacity-50" aria-hidden />
                            <p className="mt-1">Listener unavailable or stopped</p>
                            <p className="mt-1 font-mono text-[10px]">{listenerQuery.data.listener_name}</p>
                          </div>
                        ) : (
                          <pre
                            ref={outputRef}
                            onScroll={handleScroll}
                            className="max-h-[260px] overflow-auto rounded-md border bg-zinc-950 p-3 font-mono text-xs leading-relaxed text-zinc-100 whitespace-pre-wrap break-words scrollbar-thin"
                            style={{ overflowX: "auto", whiteSpace: "pre-wrap", wordBreak: "break-word" }}
                            aria-label="Listener output"
                          >
                            {listenerQuery.data.output || "(no output yet)"}
                          </pre>
                        )}
                        <div className="flex items-center justify-between text-[10px] text-muted-foreground">
                          <span>
                            {listenerQuery.data.running ? "Listener running" : "Listener stopped"} · updated{" "}
                            {formatLastCheck(listenerQuery.data.updated_at ? Date.parse(listenerQuery.data.updated_at) / 1000 : null)}
                          </span>
                          {!listenerAutoScroll && (
                            <button type="button" className="underline-offset-4 hover:underline" onClick={() => setListenerAutoScroll(true)}>
                              Resume autoscroll
                            </button>
                          )}
                        </div>
                      </>
                    )}
                  </section>

                  {/* Danger zone */}
                  <section className="space-y-2 rounded-lg border border-destructive/20 bg-destructive/5 p-3">
                    <h3 className="flex items-center gap-1.5 text-xs font-semibold text-destructive">
                      <Trash2 className="h-3.5 w-3.5" />
                      Danger Zone
                    </h3>
                    <p className="text-xs leading-relaxed text-muted-foreground">
                      Mark this connection as removed and attempt to stop the associated listener. The record is retained for
                      audit.
                    </p>
                    <Button
                      size="sm"
                      variant="destructive"
                      onClick={() => setShowRemoveDialog(true)}
                      disabled={removeMutation.isPending || conn.status === "removed"}
                      aria-label="Remove connection"
                      className="gap-1.5"
                    >
                      {removeMutation.isPending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Trash2 className="h-3.5 w-3.5" />}
                      Remove connection
                    </Button>
                    {conn.status === "removed" && <p className="text-xs text-muted-foreground">This connection is already marked removed.</p>}
                  </section>
                </div>
              )}
            </div>

            <div className="shrink-0 border-t bg-card px-5 py-3">
              <Button variant="outline" size="sm" className="w-full" onClick={() => onOpenChange(false)}>
                Close
              </Button>
            </div>
          </div>
        </DialogContent>
      </Dialog>

      {/* Removal confirmation */}
      <Dialog open={showRemoveDialog} onOpenChange={setShowRemoveDialog}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2 text-destructive">
              <Trash2 className="h-4 w-4" />
              Remove connection?
            </DialogTitle>
            <DialogDescription className="text-left">
              This will mark the persisted record as removed and attempt listener cleanup via the existing manager. The
              record remains for audit and can be inspected afterwards.
            </DialogDescription>
          </DialogHeader>
          {conn && (
            <div className="space-y-1 rounded-md bg-muted/40 p-3 font-mono text-xs">
              <div>
                Target: <span className="font-medium">{conn.target_ip}</span>
              </div>
              <div className="truncate">Listener: {conn.listener_name || "—"}</div>
              <div className="truncate">ID: {conn.connection_id}</div>
            </div>
          )}
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowRemoveDialog(false)} disabled={removeMutation.isPending}>
              Cancel
            </Button>
            <Button variant="destructive" onClick={onRemove} disabled={removeMutation.isPending} className="gap-1.5">
              {removeMutation.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : null}
              Remove
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}

function DetailRow({
  label,
  value,
  sub,
  mono,
  copyValue,
}: {
  label: string;
  value: string;
  sub?: string;
  mono?: boolean;
  copyValue?: string;
}) {
  return (
    <div className="flex items-start justify-between gap-3 bg-card px-3 py-2.5 last:rounded-b-lg">
      <div className="min-w-0 flex-1">
        <div className="text-[10px] font-medium uppercase tracking-wide text-muted-foreground">{label}</div>
        <div className={cn("mt-0.5 break-all text-sm", mono && "font-mono text-xs")}>{value}</div>
        {sub && <div className="mt-0.5 font-mono text-[10px] text-muted-foreground">{sub}</div>}
      </div>
      {copyValue && <CopyButton value={copyValue} size="icon" label={`Copy ${label}`} className="h-7 w-7 shrink-0" />}
    </div>
  );
}
