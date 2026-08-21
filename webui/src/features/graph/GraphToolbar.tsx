import { useMemo, useState } from "react";
import { AlertTriangle, Crosshair, Expand, LayoutGrid, Maximize, Route, Search } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { nodeMatchesQuery } from "@/features/graph/graphTransforms";
import type { GraphExplorerNode } from "@/features/graph/graphTypes";

export interface GraphToolbarProps {
  nodes: GraphExplorerNode[];
  selectedNodeId: string | null;
  onFit: () => void;
  onReset: () => void;
  onExpand: (hops: number) => void;
  canExpand: boolean;
  expanding: boolean;
  onTogglePath: () => void;
  pathMode: boolean;
  onToggleConflicts: () => void;
  conflictsOpen: boolean;
  conflictCount: number;
  onFocusNode: (id: string) => void;
}

export function GraphToolbar(props: GraphToolbarProps) {
  const [q, setQ] = useState("");
  const match = useMemo(() => {
    if (!q.trim()) return null;
    return props.nodes.find((n) => nodeMatchesQuery(n, q)) ?? null;
  }, [q, props.nodes]);

  return (
    <div className="flex flex-wrap items-center gap-1.5">
      <TooltipProvider delayDuration={300}>
        <Tooltip>
          <TooltipTrigger asChild>
            <Button variant="outline" size="sm" className="h-8 w-8 p-0" onClick={props.onFit} aria-label="Fit to screen">
              <Maximize className="h-3.5 w-3.5" />
            </Button>
          </TooltipTrigger>
          <TooltipContent>Fit graph to screen</TooltipContent>
        </Tooltip>
        <Tooltip>
          <TooltipTrigger asChild>
            <Button variant="outline" size="sm" className="h-8 w-8 p-0" onClick={props.onReset} aria-label="Reset layout">
              <LayoutGrid className="h-3.5 w-3.5" />
            </Button>
          </TooltipTrigger>
          <TooltipContent>Reset to auto layout</TooltipContent>
        </Tooltip>

        <Tooltip>
          <TooltipTrigger asChild>
            <Button
              variant="outline"
              size="sm"
              className="h-8 gap-1 px-2 text-xs"
              onClick={() => props.onExpand(1)}
              disabled={!props.canExpand || props.expanding}
              aria-label="Expand neighborhood by one hop"
            >
              <Expand className="h-3.5 w-3.5" />
              +1 hop
            </Button>
          </TooltipTrigger>
          <TooltipContent>Expand neighborhood of selected node by 1 hop</TooltipContent>
        </Tooltip>
        <Tooltip>
          <TooltipTrigger asChild>
            <Button
              variant="outline"
              size="sm"
              className="h-8 gap-1 px-2 text-xs"
              onClick={() => props.onExpand(2)}
              disabled={!props.canExpand || props.expanding}
              aria-label="Expand neighborhood by two hops"
            >
              <Expand className="h-3.5 w-3.5" />
              +2 hops
            </Button>
          </TooltipTrigger>
          <TooltipContent>Expand neighborhood of selected node by 2 hops</TooltipContent>
        </Tooltip>

        <Button
          variant={props.pathMode ? "default" : "outline"}
          size="sm"
          className="h-8 gap-1 px-2 text-xs"
          onClick={props.onTogglePath}
          aria-pressed={props.pathMode}
        >
          <Route className="h-3.5 w-3.5" />
          Path
        </Button>

        <Tooltip>
          <TooltipTrigger asChild>
            <Button
              variant={props.conflictsOpen ? "warn" : "outline"}
              size="sm"
              className="h-8 gap-1 px-2 text-xs"
              onClick={props.onToggleConflicts}
              aria-pressed={props.conflictsOpen}
              aria-label={`Merge conflicts${props.conflictCount ? `: ${props.conflictCount}` : ""}`}
            >
              <AlertTriangle className="h-3.5 w-3.5" />
              {props.conflictCount > 0 && <span className="font-mono tabular-nums">{props.conflictCount}</span>}
            </Button>
          </TooltipTrigger>
          <TooltipContent>
            {props.conflictCount > 0
              ? `${props.conflictCount} merge conflicts during ingestion — click to inspect`
              : "No merge conflicts"}
          </TooltipContent>
        </Tooltip>
      </TooltipProvider>

      {/* Focus search: find a node already loaded and jump to it */}
      <div className="relative ml-auto min-w-0 flex-1 sm:max-w-xs">
        <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
        <input
          value={q}
          onChange={(e) => setQ(e.target.value)}
          placeholder="Focus node (value, CVE, severity…)"
          aria-label="Find node in graph"
          className="h-8 w-full rounded-md border border-input bg-background pl-8 pr-8 text-xs placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-1"
        />
        {match && (
          <Button
            variant="ghost"
            size="sm"
            className="absolute right-1 top-1/2 h-6 -translate-y-1/2 px-1.5 text-[10px]"
            onClick={() => props.onFocusNode(match.node_id)}
            aria-label={`Focus ${match.value}`}
          >
            <Crosshair className="mr-1 h-3 w-3" />Jump
          </Button>
        )}
        {q && !match && (
          <span className="absolute right-2 top-1/2 -translate-y-1/2 text-[10px] text-muted-foreground">no match</span>
        )}
      </div>
    </div>
  );
}
