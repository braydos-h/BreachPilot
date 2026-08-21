import { Badge } from "@/components/ui/badge";
import { summaryChips } from "@/features/graph/graphTransforms";
import type { GraphSummaryStats } from "@/features/graph/graphTypes";

export function GraphStats({ stats }: { stats: GraphSummaryStats | undefined }) {
  const chips = summaryChips(stats);
  if (chips.length === 0) return null;
  return (
    <div className="flex flex-wrap items-center gap-1.5" role="list" aria-label="Graph statistics">
      {chips.map((c) => (
        <Badge key={c.key} variant="outline" className="gap-1.5 font-mono text-[11px] tabular-nums" role="listitem">
          <span className="text-muted-foreground">{c.label}</span>
          <span className="text-foreground">{c.value}</span>
        </Badge>
      ))}
      {stats?.conflict_count !== undefined && stats.conflict_count > 0 && (
        <Badge variant="destructive" className="gap-1.5 font-mono text-[11px] tabular-nums">
          <span>Conflicts</span>
          <span>{stats.conflict_count}</span>
        </Badge>
      )}
      {stats?.highest_degree_node && (
        <span className="hidden text-[10px] text-muted-foreground xl:inline" title="Highest-degree node">
          hub: <span className="font-mono">{stats.highest_degree_node.value}</span> (deg {stats.highest_degree_node.degree})
        </span>
      )}
    </div>
  );
}
