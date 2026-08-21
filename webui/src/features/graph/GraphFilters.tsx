import { useEffect, useMemo, useState } from "react";
import { Search, X } from "lucide-react";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import {
  NODE_STATUS_ORDER,
  NODE_TYPE_CATEGORIES,
  nodeTypeMeta,
  statusMeta,
} from "@/features/graph/graphTransforms";
import type { GraphSummaryResponse } from "@/features/graph/graphTypes";

export interface GraphFilterState {
  runId: string;
  nodeTypes: string[];
  statuses: string[];
  q: string;
  minConfidence: number;
}

export interface GraphFiltersProps {
  filters: GraphFilterState;
  onChange: (patch: Partial<GraphFilterState>) => void;
  /** Real per-type counts from the run summary — shown when available, never invented. */
  summary?: GraphSummaryResponse | undefined;
}

const ALL_TYPES = NODE_TYPE_CATEGORIES.flatMap((c) => c.types);

// Server-side filters: value search, node types (with real counts from the
// summary), status, and a client-side minimum-confidence threshold. The run
// scope selector lives in the page header, not here.
export function GraphFilters({ filters, onChange, summary }: GraphFiltersProps) {
  const [searchDraft, setSearchDraft] = useState(filters.q);
  useEffect(() => {
    const timer = setTimeout(() => onChange({ q: searchDraft.trim() }), 350);
    return () => clearTimeout(timer);
  }, [searchDraft, onChange]);

  const [typeQuery, setTypeQuery] = useState("");
  const typeCounts = summary?.summary.nodes;
  const allSelected = ALL_TYPES.every((t) => filters.nodeTypes.includes(t));

  const toggleType = (t: string) =>
    onChange({
      nodeTypes: filters.nodeTypes.includes(t)
        ? filters.nodeTypes.filter((x) => x !== t)
        : [...filters.nodeTypes, t],
    });
  const toggleStatus = (s: string) =>
    onChange({
      statuses: filters.statuses.includes(s)
        ? filters.statuses.filter((x) => x !== s)
        : [...filters.statuses, s],
    });

  const visibleCategories = useMemo(() => {
    const needle = typeQuery.trim().toLowerCase();
    return NODE_TYPE_CATEGORIES.map((cat) => ({
      ...cat,
      types: cat.types.filter((t) => {
        if (!needle) return true;
        const meta = nodeTypeMeta(t);
        return meta.label.toLowerCase().includes(needle) || t.toLowerCase().includes(needle);
      }),
    })).filter((cat) => cat.types.length > 0);
  }, [typeQuery]);

  return (
    <div className="space-y-4">
      {/* Server-side search by value */}
      <div className="space-y-1.5">
        <Label htmlFor="graph-search" className="text-xs">Search</Label>
        <div className="relative">
          <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
          <Input
            id="graph-search"
            value={searchDraft}
            onChange={(e) => setSearchDraft(e.target.value)}
            placeholder="IP, host, service, CVE, finding…"
            className="pl-8"
          />
          {searchDraft && (
            <Button
              type="button"
              variant="ghost"
              size="sm"
              className="absolute right-1 top-1/2 h-6 w-6 -translate-y-1/2 p-0"
              onClick={() => setSearchDraft("")}
              aria-label="Clear search"
            >
              <X className="h-3.5 w-3.5" />
            </Button>
          )}
        </div>
        <p className="text-[10px] text-muted-foreground">Refines the graph server-side by node value.</p>
      </div>

      {/* Node types: searchable, grouped, with real counts */}
      <fieldset className="space-y-1.5">
        <legend className="text-xs font-medium text-foreground">Node types</legend>
        <div className="flex items-center gap-1">
          <div className="relative min-w-0 flex-1">
            <Search className="pointer-events-none absolute left-2 top-1/2 h-3 w-3 -translate-y-1/2 text-muted-foreground" />
            <Input
              value={typeQuery}
              onChange={(e) => setTypeQuery(e.target.value)}
              placeholder="Filter types…"
              aria-label="Filter node types"
              className="h-7 pl-6 text-xs"
            />
          </div>
          <Button variant="ghost" size="sm" className="h-7 shrink-0 px-2 text-[11px]" onClick={() => onChange({ nodeTypes: ALL_TYPES })}>
            All
          </Button>
          <Button
            variant="ghost"
            size="sm"
            className="h-7 shrink-0 px-2 text-[11px]"
            onClick={() => onChange({ nodeTypes: [] })}
            disabled={filters.nodeTypes.length === 0}
          >
            None
          </Button>
        </div>
        <div className="max-h-56 space-y-2 overflow-y-auto pr-1">
          {visibleCategories.map((cat) => (
            <div key={cat.key}>
              <div className="text-[9px] uppercase tracking-wide text-muted-foreground/70">{cat.label}</div>
              {cat.types.map((t) => {
                const meta = nodeTypeMeta(t);
                const count = typeCounts?.[t] ?? 0;
                const selected = filters.nodeTypes.includes(t);
                return (
                  <label
                    key={t}
                    className={cn(
                      "flex cursor-pointer items-center gap-2 rounded px-1 py-0.5 text-xs hover:bg-accent",
                      selected && "bg-accent/50",
                    )}
                  >
                    <Checkbox checked={selected} onCheckedChange={() => toggleType(t)} />
                    <span className="h-2 w-2 shrink-0 rounded-full" style={{ background: meta.color }} aria-hidden />
                    <span className="truncate">{meta.label}</span>
                    {count > 0 && (
                      <span className="ml-auto shrink-0 font-mono text-[10px] tabular-nums text-muted-foreground">{count}</span>
                    )}
                  </label>
                );
              })}
            </div>
          ))}
        </div>
      </fieldset>

      {/* Statuses */}
      <fieldset className="space-y-1.5">
        <legend className="text-xs font-medium text-foreground">Status</legend>
        <div className="grid grid-cols-2 gap-1">
          {NODE_STATUS_ORDER.map((s) => {
            const meta = statusMeta(s);
            const selected = filters.statuses.includes(s);
            return (
              <label key={s} className={cn("flex cursor-pointer items-center gap-2 rounded px-1 py-0.5 text-xs hover:bg-accent", selected && "bg-accent/50")}>
                <Checkbox checked={selected} onCheckedChange={() => toggleStatus(s)} />
                <span className="h-1.5 w-1.5 shrink-0 rounded-full" style={{ background: meta.color }} aria-hidden />
                <span className="truncate">{meta.label}</span>
              </label>
            );
          })}
        </div>
      </fieldset>

      {/* Confidence */}
      <div className="space-y-1.5">
        <div className="flex items-center justify-between">
          <Label htmlFor="graph-conf" className="text-xs">Min confidence</Label>
          <span className="font-mono text-xs tabular-nums text-muted-foreground">{filters.minConfidence.toFixed(2)}</span>
        </div>
        <input
          id="graph-conf"
          type="range"
          min={0}
          max={1}
          step={0.05}
          value={filters.minConfidence}
          onChange={(e) => onChange({ minConfidence: Number(e.target.value) })}
          className="w-full accent-primary"
          aria-label="Minimum confidence"
        />
      </div>
    </div>
  );
}
