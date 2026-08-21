import { useMemo, useState } from "react";
import { Check, Flag, Loader2, MapPin, Route, X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import { useGraphPaths } from "@/features/graph/graphApi";
import { edgeMeta, nodeTypeMeta } from "@/features/graph/graphTransforms";
import type { GraphExplorerNode, GraphPathStep } from "@/features/graph/graphTypes";

export interface GraphPathFinderProps {
  runId: string;
  nodes: GraphExplorerNode[];
  /** currently selected node — offered as "set as start/end" */
  selectedNodeId: string | null;
  onShowPath: (nodeIds: Set<string>, edgeIds: Set<string>) => void;
  onClose: () => void;
  /** an attack-path overlay is currently shown on the canvas */
  active: boolean;
  onClearPath: () => void;
}

// Bounded attack-path mode: pick start/end (from the graph selection or the
// dropdowns), request a bounded path (backend clamps length to 8 / count to 8).
// Results render as "start → edge → node → … → destination" chains; the active
// result is highlighted and re-shown on the canvas when clicked.
export function GraphPathFinder({
  runId,
  nodes,
  selectedNodeId,
  onShowPath,
  onClose,
  active,
  onClearPath,
}: GraphPathFinderProps) {
  const [start, setStart] = useState("");
  const [end, setEnd] = useState("");
  const [maxLength, setMaxLength] = useState(4);
  const [maxPaths, setMaxPaths] = useState(5);
  const [activeIndex, setActiveIndex] = useState<number | null>(null);

  const options = useMemo(() => {
    const byValue = new Map<string, GraphExplorerNode>();
    for (const n of nodes) {
      if (!byValue.has(n.node_id)) byValue.set(n.node_id, n);
    }
    return [...byValue.values()];
  }, [nodes]);

  const selected = nodes.find((n) => n.node_id === selectedNodeId) ?? null;

  const paths = useGraphPaths(runId, start || null, end || null, maxLength, maxPaths, !!start && !!end);

  const showPath = (path: GraphPathStep[], i: number) => {
    setActiveIndex(i);
    // The backend path omits the start node; include it so the overlay shows
    // the full route (start → first hop is step 1's edge).
    onShowPath(
      new Set([start, ...path.map((s) => s.node.node_id)]),
      new Set(path.filter((s) => s.edge).map((s) => s.edge.edge_id)),
    );
  };

  const startNode = options.find((n) => n.node_id === start);

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <h3 className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
          <Route className="h-3.5 w-3.5" />
          Attack path
        </h3>
        <div className="flex items-center gap-1">
          {active && (
            <Button variant="ghost" size="sm" className="h-6 gap-1 px-2 text-[11px] text-emerald-300" onClick={onClearPath}>
              <X className="h-3 w-3" /> Clear path
            </Button>
          )}
          <Button variant="ghost" size="sm" className="h-6 px-2 text-xs" onClick={onClose}>Close</Button>
        </div>
      </div>

      {/* Set endpoints from the selected graph node */}
      <div className="grid grid-cols-1 gap-1.5 sm:grid-cols-2">
        <Button
          variant="outline"
          size="sm"
          className="h-7 justify-start gap-1.5 px-2 text-[11px]"
          disabled={!selectedNodeId}
          onClick={() => selected && setStart(selected.node_id)}
        >
          <Flag className="h-3 w-3 text-amber-300" aria-hidden />
          Set selected as start
        </Button>
        <Button
          variant="outline"
          size="sm"
          className="h-7 justify-start gap-1.5 px-2 text-[11px]"
          disabled={!selectedNodeId}
          onClick={() => selected && setEnd(selected.node_id)}
        >
          <MapPin className="h-3 w-3 text-rose-300" aria-hidden />
          Set selected as destination
        </Button>
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
            <li key={i}>
              <button
                type="button"
                onClick={() => showPath(path, i)}
                aria-pressed={i === activeIndex}
                className={cn(
                  "w-full rounded-md border px-2 py-1.5 text-left transition-colors",
                  i === activeIndex
                    ? "border-emerald-500/50 bg-emerald-500/10"
                    : "border-border/60 bg-card/40 hover:border-emerald-500/30",
                )}
              >
                <div className="mb-1 flex items-center justify-between gap-2">
                  <Badge variant="outline" className="font-mono text-[10px]">
                    path {i + 1} · {path.length} {path.length === 1 ? "hop" : "hops"}
                  </Badge>
                  <span className="flex items-center gap-1 text-[10px] text-muted-foreground">
                    {i === activeIndex && (
                      <span className="inline-flex items-center gap-0.5 text-emerald-300">
                        <Check className="h-3 w-3" /> on graph
                      </span>
                    )}
                    Click to show
                  </span>
                </div>
                <PathChain start={startNode} steps={path} />
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function PathChain({ start, steps }: { start: GraphExplorerNode | undefined; steps: GraphPathStep[] }) {
  const edges = steps.filter((s) => s.edge).map((s) => edgeMeta(s.edge.edge_type));
  return (
    <div className="flex flex-wrap items-center gap-x-1 gap-y-0.5 text-[11px]">
      {start && <NodeName node={start} />}
      {steps.map((step, j) => (
        <span key={j} className="flex items-center gap-1">
          <span className="text-emerald-400" aria-hidden>→</span>
          {edges[j] && (
            <span className="text-[9px] text-muted-foreground" title={edges[j].label}>
              {edges[j].label}
            </span>
          )}
          <span className="text-emerald-400" aria-hidden>→</span>
          <NodeName node={step.node} />
        </span>
      ))}
    </div>
  );
}

function NodeName({ node }: { node: GraphExplorerNode }) {
  const meta = nodeTypeMeta(node.node_type);
  return (
    <span className="inline-flex max-w-full items-center gap-1">
      <span className="truncate font-mono" title={node.value}>{node.value}</span>
      <span className="shrink-0 font-mono text-[8px] uppercase text-muted-foreground" style={{ color: meta.color }}>
        {meta.label}
      </span>
    </span>
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
