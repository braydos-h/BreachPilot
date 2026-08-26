import { useEffect, useMemo, useRef, useState, useCallback } from "react";
import { Link } from "react-router-dom";
import {
  AlertTriangle,
  CheckCircle2,
  Clock3,
  Copy,
  Loader2,
  PlugZap,
  RefreshCw,
  Search,
  ShieldAlert,
  Trash2,
  Wifi,
  Radio,
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
import type { ConnectionStatus, OperatorConnection } from "@/api/types";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { CopyButton } from "@/components/CopyButton";
import { cn } from "@/lib/utils";
import { useToast } from "@/hooks/use-toast";

// ── Helpers ────────────────────────────────────────────────────────────

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

const STATUS_VARIANT: Record<ConnectionStatus, "success" | "warn" | "danger" | "muted" | "secondary"> = {
  active: "success",
  stale: "warn",
  removed: "muted",
  error: "danger",
};

const STATUS_LABEL: Record<ConnectionStatus, string> = {
  active: "ACTIVE",
  stale: "STALE",
  removed: "REMOVED",
  error: "ERROR",
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

// ── Status badge ──────────────────────────────────────────────────────

function ConnectionStatusBadge({ status }: { status: ConnectionStatus }) {
  const variant = STATUS_VARIANT[status] ?? "muted";
  return (
    <Badge variant={variant} className="font-mono text-[10px] uppercase tracking-wide">
      {STATUS_LABEL[status] ?? status.toUpperCase()}
    </Badge>
  );
}

// ── Main page ─────────────────────────────────────────────────────────

type FilterKey = "all" | ConnectionStatus;
type SortKey = "status" | "target" | "created" | "beacon" | "method";
type SortDir = "asc" | "desc";

const FILTER_OPTIONS: { key: FilterKey; label: string }[] = [
  { key: "all", label: "All" },
  { key: "active", label: "Active" },
  { key: "stale", label: "Stale" },
  { key: "removed", label: "Removed" },
  { key: "error", label: "Error" },
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
    // Fallback compute
    return {
      total: raw.length,
      active: raw.filter((r) => r.status === "active").length,
      stale: raw.filter((r) => r.status === "stale").length,
      removed: raw.filter((r) => r.status === "removed").length,
      error: raw.filter((r) => r.status === "error").length,
    };
  }, [raw, connectionsQuery.data]);

  // Filtering and search (local)
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
        ]
          .join(" ")
          .toLowerCase();
        return hay.includes(q);
      });
    }
    return out;
  }, [raw, filter, debouncedSearch]);

  // Sorting
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
      // Default secondary: newest first within same primary
      if (cmp === 0) cmp = b.created_at - a.created_at;
      return sortDir === "asc" ? cmp : -cmp;
    });
    // When sortKey is status, we want default ordering error→stale→active→removed
    // That's already rank asc. If user toggled dir, respect it.
    // For initial load with sortKey=status and asc, we mimic spec default:
    // error(0), stale(1), active(2), removed(3) then newest within group.
    // Our comparator above does rank asc + created desc secondary when sortKey status.
    // To make secondary newest within group independent of dir, keep desc for that case.
    // But we already handle dir toggle - keep as is for explicit user sorting.
    return arr;
  }, [filtered, sortKey, sortDir]);

  // Default ordering should prioritize operator attention when not explicitly sorted?
  // We'll apply special default when sortKey status asc (initial) — ensure that ordering
  // matches spec. Already done. If user hasn't touched sort, keep that.

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

  return (
    <TooltipProvider delayDuration={150}>
      <div className="mx-auto flex max-w-[1600px] flex-col gap-5 p-4 md:p-6">
        {/* Header */}
        <header className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
          <div className="flex min-w-0 items-start gap-3">
            <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border bg-card">
              <PlugZap className="h-5 w-5 text-primary" aria-hidden />
            </div>
            <div className="min-w-0">
              <h1 className="text-lg font-semibold leading-tight">Connections</h1>
              <p className="mt-0.5 max-w-[60ch] text-sm text-muted-foreground">
                Persisted operator access channels across assessment runs.
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
            >
              <RefreshCw className={cn("h-3.5 w-3.5", connectionsQuery.isFetching && "animate-spin")} />
              Refresh
            </Button>
          </div>
        </header>

        {/* KPI cards */}
        <section aria-label="Connection summary" className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          <KpiCard label="Active" value={counts.active} tone="success" loading={isLoading} />
          <KpiCard label="Stale" value={counts.stale} tone="warning" loading={isLoading} />
          <KpiCard label="Error" value={counts.error} tone="danger" loading={isLoading} />
          <KpiCard label="Total" value={counts.total} tone="neutral" loading={isLoading} />
        </section>

        {/* Filters + search */}
        <div className="flex flex-col gap-3">
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
              return (
                <button
                  key={opt.key}
                  type="button"
                  role="tab"
                  aria-selected={active}
                  onClick={() => setFilter(opt.key)}
                  className={cn(
                    "inline-flex items-center gap-1.5 rounded-md border px-3 py-1.5 text-xs font-medium transition-colors",
                    active
                      ? "border-primary bg-primary text-primary-foreground"
                      : "border-border bg-card hover:bg-accent hover:text-accent-foreground",
                  )}
                >
                  <span>{opt.label}</span>
                  <span
                    className={cn(
                      "rounded px-1 py-0 text-[10px] tabular-nums",
                      active ? "bg-primary-foreground/15 text-primary-foreground" : "bg-muted text-muted-foreground",
                    )}
                  >
                    {count}
                  </span>
                </button>
              );
            })}
          </div>

          <div className="relative max-w-md">
            <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" aria-hidden />
            <Input
              placeholder="Search target, listener, method, MITRE..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="h-9 pl-8 text-sm"
              aria-label="Search connections"
            />
          </div>
        </div>

        {/* Table / cards */}
        {isLoading && <ConnectionsSkeleton />}

        {isError && (
          <Card className="border-destructive/30">
            <CardContent className="flex items-center gap-3 p-4 text-sm">
              <AlertTriangle className="h-4 w-4 shrink-0 text-destructive" />
              <span className="flex-1 text-destructive">
                {connectionsQuery.error instanceof ApiError ? connectionsQuery.error.message : "Failed to load connections."}
              </span>
              <Button size="sm" variant="outline" onClick={() => void connectionsQuery.refetch()}>
                Retry
              </Button>
            </CardContent>
          </Card>
        )}

        {isEmpty && !isLoading && !isError && (
          <Card className="border-dashed">
            <CardContent className="flex flex-col items-center justify-center gap-3 p-8 text-center">
              <span className="flex h-10 w-10 items-center justify-center rounded-full bg-primary/10 text-primary">
                <Radio className="h-5 w-5" />
              </span>
              <div>
                <h2 className="font-medium">No persisted connections</h2>
                <p className="mx-auto mt-1 max-w-md text-sm text-muted-foreground">
                  Connections established during authorized assessment runs will appear here automatically.
                </p>
              </div>
              <Button asChild size="sm" variant="outline">
                <Link to="/sessions">View sessions</Link>
              </Button>
            </CardContent>
          </Card>
        )}

        {!isLoading && !isError && !isEmpty && filtered.length === 0 && (
          <div className="rounded-md border border-dashed p-6 text-center text-sm text-muted-foreground">
            No connections match your filters.
          </div>
        )}

        {!isLoading && !isError && sorted.length > 0 && (
          <>
            {/* Desktop table */}
            <div className="hidden overflow-x-auto rounded-lg border md:block">
              <table className="w-full border-collapse text-sm">
                <caption className="sr-only">Operator connections</caption>
                <thead>
                  <tr>
                    <SortTh label="Target" sortKey="target" activeKey={sortKey} dir={sortDir} onSort={onSort} />
                    <SortTh label="Method" sortKey="method" activeKey={sortKey} dir={sortDir} onSort={onSort} />
                    <SortTh label="Status" sortKey="status" activeKey={sortKey} dir={sortDir} onSort={onSort} />
                    <th scope="col" className="whitespace-nowrap px-3 py-2 text-left">
                      Listener
                    </th>
                    <SortTh label="Last beacon" sortKey="beacon" activeKey={sortKey} dir={sortDir} onSort={onSort} />
                    <SortTh label="Age" sortKey="created" activeKey={sortKey} dir={sortDir} onSort={onSort} />
                    <th scope="col" className="px-3 py-2 text-left">
                      OS
                    </th>
                    <th scope="col" className="px-3 py-2 text-left">
                      MITRE
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
                      className="cursor-pointer focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-1"
                    >
                      <td className="whitespace-nowrap px-3 py-2 font-mono text-xs">{conn.target_ip}</td>
                      <td className="whitespace-nowrap px-3 py-2 text-xs">{humanizeMethod(conn.method)}</td>
                      <td className="px-3 py-2">
                        <ConnectionStatusBadge status={conn.status} />
                      </td>
                      <td className="max-w-[14rem] px-3 py-2">
                        <Tooltip>
                          <TooltipTrigger asChild>
                            <span className="block truncate font-mono text-xs" title={conn.listener_name}>
                              {conn.listener_name || "—"}
                            </span>
                          </TooltipTrigger>
                          {conn.listener_name && conn.listener_name.length > 18 && (
                            <TooltipContent className="max-w-xs break-all font-mono text-xs">{conn.listener_name}</TooltipContent>
                          )}
                        </Tooltip>
                      </td>
                      <td className="whitespace-nowrap px-3 py-2 text-xs tabular-nums">{formatBeacon(conn.last_beacon)}</td>
                      <td className="whitespace-nowrap px-3 py-2 text-xs tabular-nums">{formatAge(conn.created_at)}</td>
                      <td className="whitespace-nowrap px-3 py-2 text-xs capitalize">{conn.os_family || "Unknown"}</td>
                      <td className="whitespace-nowrap px-3 py-2 font-mono text-xs">{conn.mitre_technique || "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {/* Mobile cards */}
            <div className="grid gap-3 md:hidden">
              {sorted.map((conn) => (
                <Card
                  key={conn.connection_id}
                  className="cursor-pointer focus-within:ring-2 focus-within:ring-ring"
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
                  <CardContent className="space-y-2 p-3">
                    <div className="flex items-center justify-between gap-2">
                      <span className="font-mono text-sm font-medium">{conn.target_ip}</span>
                      <ConnectionStatusBadge status={conn.status} />
                    </div>
                    <div className="flex flex-wrap gap-x-3 gap-y-1 text-xs text-muted-foreground">
                      <span>{humanizeMethod(conn.method)}</span>
                      <span>·</span>
                      <span>{formatBeacon(conn.last_beacon)}</span>
                    </div>
                    <div className="truncate font-mono text-xs text-muted-foreground" title={conn.listener_name}>
                      {conn.listener_name || "—"}
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>

            <div className="text-xs text-muted-foreground">
              Showing {sorted.length} of {raw.length} connection{raw.length !== 1 ? "s" : ""} {filter !== "all" ? `· filtered to ${filter}` : ""}{debouncedSearch ? ` · search "${debouncedSearch}"` : ""}
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
    <th scope="col" className="whitespace-nowrap px-3 py-2 text-left">
      <button
        type="button"
        onClick={() => onSort(sortKey)}
        className={cn(
          "inline-flex items-center gap-1 text-xs font-medium uppercase tracking-wide hover:text-foreground",
          active ? "text-foreground" : "text-muted-foreground",
        )}
        aria-label={`Sort by ${label} ${active && dir === "asc" ? "descending" : "ascending"}`}
      >
        {label}
        <span aria-hidden className={cn("text-[10px]", active ? "opacity-100" : "opacity-40")}>
          {active ? (dir === "asc" ? "▲" : "▼") : "↕"}
        </span>
      </button>
    </th>
  );
}

function KpiCard({
  label,
  value,
  tone,
  loading,
}: {
  label: string;
  value: number;
  tone: "success" | "warning" | "danger" | "neutral";
  loading: boolean;
}) {
  const toneClasses: Record<string, string> = {
    success: "border-emerald-500/20 bg-emerald-500/5",
    warning: "border-yellow-500/20 bg-yellow-500/5",
    danger: "border-destructive/20 bg-destructive/5",
    neutral: "border-border bg-card/40",
  };
  return (
    <Card className={cn("h-full", toneClasses[tone])}>
      <CardContent className="flex flex-col gap-1 p-4">
        <span className="text-[10px] font-medium uppercase tracking-wide text-muted-foreground">{label}</span>
        {loading ? <Skeleton className="h-7 w-10" /> : <span className="font-mono text-2xl font-semibold tabular-nums">{value}</span>}
      </CardContent>
    </Card>
  );
}

function ConnectionsSkeleton() {
  return (
    <div className="space-y-2" role="status" aria-label="Loading connections">
      <div className="overflow-hidden rounded-lg border">
        <div className="space-y-2 p-3">
          {Array.from({ length: 5 }).map((_, i) => (
            <div key={i} className="flex items-center gap-3">
              <Skeleton className="h-4 w-20" />
              <Skeleton className="h-4 w-24" />
              <Skeleton className="h-5 w-14" />
              <Skeleton className="h-4 flex-1" />
              <Skeleton className="h-4 w-14" />
              <Skeleton className="h-4 w-10" />
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// ── Details drawer ────────────────────────────────────────────────────

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

  // Auto-scroll listener output to bottom when new data arrives if user hasn't scrolled up
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

  return (
    <>
      <Dialog open={open} onOpenChange={onOpenChange}>
        <DialogContent
          className={cn(
            "flex max-h-[90vh] max-w-[480px] flex-col gap-0 overflow-hidden p-0",
            "data-[state=open]:animate-in data-[state=closed]:animate-out",
            "sm:max-w-[480px]",
            // Right-side sheet feel on larger screens
            "md:fixed md:inset-y-0 md:right-0 md:left-auto md:top-0 md:h-dvh md:max-h-dvh md:w-[480px] md:max-w-[92vw] md:translate-x-0 md:translate-y-0 md:rounded-l-lg md:rounded-r-none md:border-l",
          )}
          aria-describedby={undefined}
        >
          <div className="flex min-h-0 flex-1 flex-col overflow-hidden">
            {/* Header */}
            <div className="shrink-0 border-b px-5 py-4">
              <div className="flex items-start justify-between gap-3">
                <div className="min-w-0">
                  <h2 className="text-sm font-semibold">Connection Details</h2>
                  <p className="mt-0.5 truncate font-mono text-xs text-muted-foreground">{connectionId}</p>
                </div>
                {conn && <ConnectionStatusBadge status={conn.status} />}
              </div>
            </div>

            {/* Body */}
            <div className="min-h-0 flex-1 overflow-y-auto scrollbar-thin">
              {connQuery.isLoading && (
                <div className="space-y-3 p-5" role="status" aria-label="Loading connection">
                  <Skeleton className="h-4 w-3/4" />
                  <Skeleton className="h-4 w-1/2" />
                  <Skeleton className="h-20 w-full" />
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
                  {/* Primary fields */}
                  <div className="grid gap-3">
                    <DetailRow label="Target" value={conn.target_ip} mono copyValue={conn.target_ip} />
                    <DetailRow label="Connection" value={conn.connection_id} mono copyValue={conn.connection_id} />
                    <DetailRow label="Method" value={`${humanizeMethod(conn.method)}`} sub={conn.method} />
                    <DetailRow label="OS" value={conn.os_family || "Unknown"} />
                    <DetailRow label="MITRE Technique" value={conn.mitre_technique || "—"} mono={!!conn.mitre_technique} />
                    <DetailRow
                      label="Callback"
                      value={`${conn.callback_host}:${conn.callback_port}`}
                      mono
                      copyValue={`${conn.callback_host}:${conn.callback_port}`}
                    />
                    <DetailRow label="Listener" value={conn.listener_name || "—"} mono copyValue={conn.listener_name} />
                    <DetailRow label="Created" value={formatIsoOrRelative(conn.created_at, conn.created_at_iso)} />
                    <DetailRow label="Last Beacon" value={conn.last_beacon ? formatIsoOrRelative(conn.last_beacon, conn.last_beacon_iso) : "Never"} sub={formatBeacon(conn.last_beacon)} />
                    <DetailRow label="Last Health Check" value={conn.last_check ? formatIsoOrRelative(conn.last_check, conn.last_check_iso) : "Never"} sub={conn.last_check ? formatLastCheck(conn.last_check) : undefined} />
                    <DetailRow label="Implant Path" value={conn.implant_path || "—"} mono copyValue={conn.implant_path || undefined} />
                    {conn.notes && <DetailRow label="Notes" value={conn.notes} />}
                    {conn.check_output && (
                      <div className="space-y-1">
                        <span className="text-[10px] font-medium uppercase tracking-wide text-muted-foreground">Last check output</span>
                        <pre className="max-h-28 overflow-auto rounded-md border bg-muted/40 p-2 font-mono text-xs whitespace-pre-wrap break-words scrollbar-thin">
                          {conn.check_output}
                        </pre>
                      </div>
                    )}
                  </div>

                  {/* Listener output */}
                  <div className="space-y-2">
                    <div className="flex items-center justify-between gap-2">
                      <h3 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">Listener Output</h3>
                      <div className="flex items-center gap-1.5">
                        {listenerQuery.isFetching && conn.status === "active" && (
                          <span className="inline-flex items-center gap-1 text-[10px] font-medium uppercase tracking-wide text-emerald-500">
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
                            {listenerQuery.data.running ? "Listener running" : "Listener stopped"} · updated {formatLastCheck(listenerQuery.data.updated_at ? Date.parse(listenerQuery.data.updated_at) / 1000 : null)}
                          </span>
                          {!listenerAutoScroll && (
                            <button type="button" className="underline-offset-4 hover:underline" onClick={() => setListenerAutoScroll(true)}>
                              Resume autoscroll
                            </button>
                          )}
                        </div>
                      </>
                    )}
                  </div>

                  {/* Health check control */}
                  <div className="space-y-2 rounded-lg border bg-card/40 p-3">
                    <h3 className="text-xs font-semibold">Health Check</h3>
                    <div className="flex flex-wrap items-center gap-2">
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={onCheck}
                        disabled={checkMutation.isPending || conn.status === "removed"}
                        aria-label="Check connection"
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
                    {conn.check_output && <p className="text-xs text-muted-foreground line-clamp-3">{conn.check_output}</p>}
                  </div>

                  {/* Danger zone */}
                  <div className="space-y-2 rounded-lg border border-destructive/30 bg-destructive/5 p-3">
                    <h3 className="text-xs font-semibold text-destructive">Danger Zone</h3>
                    <p className="text-xs text-muted-foreground">Remove the persisted connection record and perform cleanup.</p>
                    <Button
                      size="sm"
                      variant="destructive"
                      onClick={() => setShowRemoveDialog(true)}
                      disabled={removeMutation.isPending || conn.status === "removed"}
                      aria-label="Remove connection"
                    >
                      {removeMutation.isPending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Trash2 className="h-3.5 w-3.5" />}
                      Remove connection
                    </Button>
                    {conn.status === "removed" && <p className="text-xs text-muted-foreground">This connection is already marked removed.</p>}
                  </div>
                </div>
              )}
            </div>

            <div className="shrink-0 border-t px-5 py-3">
              <Button variant="outline" size="sm" className="w-full" onClick={() => onOpenChange(false)}>
                Close
              </Button>
            </div>
          </div>
        </DialogContent>
      </Dialog>

      {/* Removal confirmation dialog */}
      <Dialog open={showRemoveDialog} onOpenChange={setShowRemoveDialog}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2 text-destructive">
              <Trash2 className="h-4 w-4" />
              Remove connection?
            </DialogTitle>
            <DialogDescription className="text-left">
              This will remove the persisted connection record and perform the existing cleanup behaviour associated with this connection.
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
            <Button variant="destructive" onClick={onRemove} disabled={removeMutation.isPending}>
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
    <div className="flex items-start justify-between gap-3 border-b border-border/60 py-2 last:border-0">
      <div className="min-w-0 flex-1">
        <div className="text-[10px] font-medium uppercase tracking-wide text-muted-foreground">{label}</div>
        <div className={cn("mt-0.5 break-all text-sm", mono && "font-mono text-xs")}>{value}</div>
        {sub && <div className="mt-0.5 font-mono text-[10px] text-muted-foreground">{sub}</div>}
      </div>
      {copyValue && (
        <CopyButton value={copyValue} size="icon" label={`Copy ${label}`} className="h-7 w-7 shrink-0" />
      )}
    </div>
  );
}
