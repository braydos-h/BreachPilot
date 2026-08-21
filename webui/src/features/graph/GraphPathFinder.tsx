import { useMemo, useState } from "react";
import { Loader2, Route } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { useGraphPaths } from "@/features/graph/graphApi";
import type { GraphExplorerNode } from "@/features/graph/graphTypes";

export interface GraphPathFinderProps {
  runId: string;
  nodes: GraphExplorerNode[];
  onShowPath: (nodeIds: Set<string>, edgeIds: Set<string>) => void;
  onClose: () => void;
}

// Bounded attack-path mode: pick start/end nodes, request a bounded path
// (backend clamps max_length to 8 / max_paths to 8). Results are rendered as
// steps and can be highlighted on the canvas.
export function GraphPathFinder({ runId, nodes, onShowPath, onClose }: GraphPathFinderProps) {
  const [start, setStart] = useState("");
  const [end, setEnd] = useState("");
  const [maxLength, setMaxLength] = useState(4);
  const [maxPaths, setMaxPaths] = useState(5);

  const options = useMemo(() => {
    const byValue = new Map<string, GraphExplorerNode>();
    for (const n of nodes) {
      if (!byValue.has(n.node_id)) byValue.set(n.node_id, n);
    }
    return [...byValue.values()];
  }, [nodes]);

  const paths = useGraphPaths(runId, start || null, end || null, maxLength, maxPaths, !!start && !!end);

  const showPath = (path: Array<{ distance: number; node: GraphExplorerNode; edge: { edge_id: string } }>) => {
    // The backend path omits the start node; include it so the overlay shows
    // the full route (start → first hop is step 1's edge).
    onShowPath(
      new Set([start, ...path.map((s) => s.node.node_id)]),
      new Set(path.filter((s) => s.edge).map((s) => s.edge.edge_id)),
    );
  };

  return (
    <div className="space-y-3 border-t p-3">
      <div className="flex items-center justify-between">
        <h3 className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
          <Route className="h-3.5 w-3.5" />
          Attack path
        </h3>
        <Button variant="ghost" size="sm" className="h-6 px-2 text-xs" onClick={onClose}>Close</Button>
      </div>

      <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
        <NodeSelect label="Start" value={start} options={options} onChange={setStart} />
        <NodeSelect label="End" value={end} options={options} onChange={setEnd} />
      </div>

      <div className="flex flex-wrap items-center gap-3 text-xs">
        <label className="flex items-center gap-1.5">
          <span className="text-muted-foreground">Max length</span>
          <select
            className="h-7 rounded border border-input bg-background px-1.5 text-xs"
            value={maxLength}
            onChange={(e) => setMaxLength(Number(e.target.value))}
          >
            {[2, 3, 4, 5, 6, 7, 8].map((n) => <option key={n} value={n}>{n}</option>)}
          </select>
        </label>
        <label className="flex items-center gap-1.5">
          <span className="text-muted-foreground">Max paths</span>
          <select
            className="h-7 rounded border border-input bg-background px-1.5 text-xs"
            value={maxPaths}
            onChange={(e) => setMaxPaths(Number(e.target.value))}
          >
            {[1, 2, 3, 5, 8].map((n) => <option key={n} value={n}>{n}</option>)}
          </select>
        </label>
      </div>

      {paths.isLoading && (
        <div className="flex items-center gap-2 text-xs text-muted-foreground">
          <Loader2 className="h-3.5 w-3.5 animate-spin" /> Searching paths…
        </div>
      )}
      {!paths.isLoading && !paths.error && paths.data && paths.data.paths.length === 0 && (
        <p className="text-xs text-muted-foreground">No paths within the chosen bounds.</p>
      )}
      {!paths.isLoading && paths.error && (
        <p className="text-xs text-destructive">Path search failed. Try different bounds.</p>
      )}
      {paths.data && paths.data.paths.length > 0 && (
        <ul className="space-y-1.5">
          {paths.data.paths.map((path, i) => (
            <li key={i} className="rounded border border-border/60 bg-card/40 px-2 py-1.5">
              <div className="mb-1 flex items-center justify-between">
                <Badge variant="outline" className="font-mono text-[10px]">path {i + 1} · {path.length} steps</Badge>
                <Button size="sm" variant="ghost" className="h-5 px-1.5 text-[10px]" onClick={() => showPath(path)}>
                  Show on graph
                </Button>
              </div>
              <ol className="space-y-0.5">
                {path.map((step, j) => (
                  <li key={j} className="flex items-center gap-1.5 text-[11px]">
                    <span className="w-4 shrink-0 text-right font-mono text-muted-foreground">{step.distance}</span>
                    <span className="w-px shrink-0 self-stretch bg-border" aria-hidden />
                    <span className="truncate font-mono" title={step.node.value}>{step.node.value}</span>
                    <span className="ml-auto shrink-0 font-mono text-[9px] text-muted-foreground">{step.node.node_type}</span>
                  </li>
                ))}
              </ol>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function NodeSelect({
  label,
  value,
  options,
  onChange,
}: {
  label: string;
  value: string;
  options: GraphExplorerNode[];
  onChange: (v: string) => void;
}) {
  return (
    <label className="block space-y-1">
      <span className="text-[10px] uppercase tracking-wide text-muted-foreground">{label}</span>
      <select
        className="h-8 w-full truncate rounded border border-input bg-background px-2 text-xs"
        value={value}
        onChange={(e) => onChange(e.target.value)}
      >
        <option value="">Select…</option>
        {options.map((n) => (
          <option key={n.node_id} value={n.node_id} title={n.value}>
            [{n.node_type}] {n.value}
          </option>
        ))}
      </select>
    </label>
  );
}
