import { X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { nodeTypeMeta, statusMeta } from "@/features/graph/graphTransforms";
import type { GraphFilterState } from "@/features/graph/GraphFilters";

export interface GraphActiveFiltersProps {
  filters: GraphFilterState;
  onChange: (patch: Partial<GraphFilterState>) => void;
}

interface ActiveFilter {
  key: string;
  label: string;
  clear: () => void;
  tint?: string;
}

// Compact chips explaining why some nodes are missing, visible without opening
// the filters panel. Every chip maps back to a real GraphFilterState field.
export function GraphActiveFilters({ filters, onChange }: GraphActiveFiltersProps) {
  const active: ActiveFilter[] = [];

  for (const t of filters.nodeTypes) {
    const meta = nodeTypeMeta(t as Parameters<typeof nodeTypeMeta>[0]);
    active.push({
      key: `type:${t}`,
      label: meta.label,
      tint: meta.color,
      clear: () => onChange({ nodeTypes: filters.nodeTypes.filter((x) => x !== t) }),
    });
  }
  for (const s of filters.statuses) {
    const meta = statusMeta(s as Parameters<typeof statusMeta>[0]);
    active.push({
      key: `status:${s}`,
      label: meta.label,
      tint: meta.color,
      clear: () => onChange({ statuses: filters.statuses.filter((x) => x !== s) }),
    });
  }
  if (filters.q.trim()) {
    active.push({
      key: "search",
      label: `Search: ${filters.q.trim().length > 18 ? `${filters.q.trim().slice(0, 18)}…` : filters.q.trim()}`,
      clear: () => onChange({ q: "" }),
    });
  }
  if (filters.minConfidence > 0) {
    active.push({
      key: "conf",
      label: `Confidence ≥ ${filters.minConfidence.toFixed(2)}`,
      clear: () => onChange({ minConfidence: 0 }),
    });
  }

  if (active.length === 0) return null;

  const resetAll = () => onChange({ nodeTypes: [], statuses: [], q: "", minConfidence: 0 });

  return (
    <div className="flex flex-wrap items-center gap-1.5" role="list" aria-label="Active graph filters">
      {active.map((f) => (
        <span
          key={f.key}
          role="listitem"
          className="inline-flex items-center gap-1 rounded-md border border-border/70 bg-accent/40 px-1.5 py-0.5 text-[11px]"
        >
          {f.tint && <span className="h-1.5 w-1.5 shrink-0 rounded-full" style={{ background: f.tint }} aria-hidden />}
          <span className="text-foreground/90">{f.label}</span>
          <button
            type="button"
            onClick={f.clear}
            aria-label={`Remove filter ${f.label}`}
            className="rounded-sm p-0.5 text-muted-foreground transition-colors hover:bg-foreground/10 hover:text-foreground"
          >
            <X className="h-3 w-3" />
          </button>
        </span>
      ))}
      <Button variant="ghost" size="sm" className="h-6 px-1.5 text-[11px] text-muted-foreground" onClick={resetAll}>
        Reset filters
      </Button>
    </div>
  );
}
