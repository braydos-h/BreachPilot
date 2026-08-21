import { useEffect, useMemo, useState } from "react";
import { Search, X } from "lucide-react";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Button } from "@/components/ui/button";
import { useRuns } from "@/api/hooks";
import { isActiveState } from "@/api/types";
import type { RunListRow } from "@/api/types";
import {
  NODE_STATUS_ORDER,
  NODE_TYPE_ORDER,
  nodeTypeMeta,
  statusMeta,
} from "@/features/graph/graphTransforms";

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
}

export function GraphFilters({ filters, onChange }: GraphFiltersProps) {
  const runs = useRuns(50, 0);
  const rows = runs.data?.runs ?? [];
  // Runs with graphs (any run may have one) — sort active first, then newest.
  const sorted = useMemo(
    () => [...rows].sort((a, b) => (isActiveState(a.state) ? -1 : isActiveState(b.state) ? 1 : 0)),
    [rows],
  );
  const [searchDraft, setSearchDraft] = useState(filters.q);
  useEffect(() => {
    const timer = setTimeout(() => onChange({ q: searchDraft.trim() }), 350);
    return () => clearTimeout(timer);
  }, [searchDraft, onChange]);

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

  return (
    <div className="space-y-4">
      {/* Run / scope / target filter */}
      <div className="space-y-1.5">
        <Label htmlFor="graph-run-select" className="text-xs">Run (scope)</Label>
        <select
          id="graph-run-select"
          className="h-9 w-full rounded-md border border-input bg-background px-3 text-sm focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-1"
          value={filters.runId}
          onChange={(e) => onChange({ runId: e.target.value })}
        >
          <option value="">Select a run…</option>
          {sorted.map((r) => (
            <option key={r.id} value={r.id}>
              {runLabel(r)} — {r.id.slice(0, 8)}
            </option>
          ))}
        </select>
      </div>

      {/* Search by IP / host / domain / service / CVE / finding */}
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

      {/* Node types */}
      <fieldset className="space-y-1.5">
        <legend className="text-xs font-medium text-foreground">Node types</legend>
        <div className="grid max-h-56 grid-cols-1 gap-1 overflow-y-auto pr-1">
          {NODE_TYPE_ORDER.map((t) => {
            const meta = nodeTypeMeta(t);
            return (
              <label
                key={t}
                className="flex cursor-pointer items-center gap-2 rounded px-1 py-0.5 text-xs hover:bg-accent"
              >
                <Checkbox checked={filters.nodeTypes.includes(t)} onCheckedChange={() => toggleType(t)} />
                <span className="h-2 w-2 shrink-0 rounded-full" style={{ background: meta.color }} aria-hidden />
                <span className="truncate">{meta.label}</span>
                <span className="ml-auto font-mono text-[10px] text-muted-foreground">{t}</span>
              </label>
            );
          })}
        </div>
      </fieldset>

      {/* Statuses */}
      <fieldset className="space-y-1.5">
        <legend className="text-xs font-medium text-foreground">Status</legend>
        <div className="grid grid-cols-2 gap-1">
          {NODE_STATUS_ORDER.map((s) => {
            const meta = statusMeta(s);
            return (
              <label key={s} className="flex cursor-pointer items-center gap-2 rounded px-1 py-0.5 text-xs hover:bg-accent">
                <Checkbox checked={filters.statuses.includes(s)} onCheckedChange={() => toggleStatus(s)} />
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

function runLabel(r: RunListRow): string {
  const target = r.target || r.target_ip || "";
  const title = r.title || target || "";
  return title ? `${title} (${target})` : (r.target_ip || r.id.slice(0, 8));
}
