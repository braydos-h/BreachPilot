import { useEffect, useMemo, useState } from "react";
import { useConnections } from "@/api/hooks";
import type { ConnectionStatus } from "@/api/types";
import { STATUS_RANK, type FilterKey, type SortDir, type SortKey } from "./connectionFormat";

/** Connections list state: filters, debounced search, sorting, drawer selection. */
export function useConnectionsPage() {
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
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [connectionsQuery.data]);

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
      setSortDir("asc");
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

  return {
    connectionsQuery,
    filter,
    setFilter,
    search,
    setSearch,
    debouncedSearch,
    sortKey,
    setSortKey,
    sortDir,
    setSortDir,
    selectedId,
    setSelectedId,
    drawerOpen,
    setDrawerOpen,
    raw,
    counts,
    filtered,
    sorted,
    onSort,
    openDrawer,
    isLoading,
    isError,
    isEmpty,
    hasActiveFilters,
    clearFilters,
  };
}

export type ConnectionsPageState = ReturnType<typeof useConnectionsPage>;
