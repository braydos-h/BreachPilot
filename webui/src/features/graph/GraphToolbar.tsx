import type { ReactNode } from "react";
import {
  AlertTriangle,
  Expand,
  Info,
  LayoutGrid,
  ListFilter,
  LocateFixed,
  Map,
  Maximize,
  PanelRight,
  Route,
  X,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { GraphSearch } from "@/features/graph/GraphSearch";
import type { GraphExplorerNode } from "@/features/graph/graphTypes";

export interface GraphToolbarProps {
  nodes: GraphExplorerNode[];
  selectedNodeId: string | null;
  onFit: () => void;
  onReset: () => void;
  onCenterSelected: () => void;
  onExpand: (hops: number) => void;
  canExpand: boolean;
  expanding: boolean;
  onOpenPath: () => void;
  pathOpen: boolean;
  pathActive: boolean;
  onClearPath: () => void;
  onToggleFilters: () => void;
  filtersOpen: boolean;
  onToggleDetails: () => void;
  detailsOpen: boolean;
  onToggleLegend: () => void;
  legendOpen: boolean;
  onToggleMinimap: () => void;
  minimapOpen: boolean;
  onToggleConflicts: () => void;
  conflictsOpen: boolean;
  conflictCount: number;
  onFocusNode: (id: string) => void;
}

// Investigation toolbar, grouped into Navigation / Investigation / Display.
// The local find-node search sits on the right and never filters the graph
// server-side — it only focuses a node already in the view.
export function GraphToolbar(props: GraphToolbarProps) {
  return (
    <div className="flex flex-wrap items-center gap-1.5 border-b px-3 py-1.5">
      <TooltipProvider delayDuration={300}>
        <ToolbarGroup label="Navigate">
          <Tooltip>
            <TooltipTrigger asChild>
              <Button variant="outline" size="sm" className="h-8 w-8 p-0" onClick={props.onFit} aria-label="Fit graph to screen">
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
                className="h-8 w-8 p-0"
                onClick={props.onCenterSelected}
                disabled={!props.selectedNodeId}
                aria-label="Center selected node"
              >
                <LocateFixed className="h-3.5 w-3.5" />
              </Button>
            </TooltipTrigger>
            <TooltipContent>Center the selected node</TooltipContent>
          </Tooltip>
        </ToolbarGroup>

        <Separator orientation="vertical" className="h-6" />

        <ToolbarGroup label="Investigate">
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
            variant={props.pathOpen ? "default" : "outline"}
            size="sm"
            className="h-8 gap-1 px-2 text-xs"
            onClick={props.onOpenPath}
            aria-pressed={props.pathOpen}
          >
            <Route className="h-3.5 w-3.5" />
            Path
          </Button>
          {props.pathActive && (
            <Button
              variant="outline"
              size="sm"
              className="h-8 gap-1 border-emerald-500/40 bg-emerald-500/10 px-2 text-xs text-emerald-300"
              onClick={props.onClearPath}
              aria-label="Clear attack path"
            >
              <X className="h-3.5 w-3.5" />
              Clear path
            </Button>
          )}
        </ToolbarGroup>

        <Separator orientation="vertical" className="h-6" />

        <ToolbarGroup label="Display">
          <Tooltip>
            <TooltipTrigger asChild>
              <Button
                variant="outline"
                size="sm"
                className={cn("h-8 w-8 p-0", props.filtersOpen && "bg-accent text-accent-foreground")}
                onClick={props.onToggleFilters}
                aria-pressed={props.filtersOpen}
                aria-label="Toggle filters panel"
              >
                <ListFilter className="h-3.5 w-3.5" />
              </Button>
            </TooltipTrigger>
            <TooltipContent>{props.filtersOpen ? "Hide filters" : "Show filters"}</TooltipContent>
          </Tooltip>
          <Tooltip>
            <TooltipTrigger asChild>
              <Button
                variant="outline"
                size="sm"
                className={cn("h-8 w-8 p-0", props.detailsOpen && "bg-accent text-accent-foreground")}
                onClick={props.onToggleDetails}
                aria-pressed={props.detailsOpen}
                aria-label="Toggle details panel"
              >
                <PanelRight className="h-3.5 w-3.5" />
              </Button>
            </TooltipTrigger>
            <TooltipContent>{props.detailsOpen ? "Hide details" : "Show details"}</TooltipContent>
          </Tooltip>
          <Tooltip>
            <TooltipTrigger asChild>
              <Button
                variant="outline"
                size="sm"
                className={cn("h-8 w-8 p-0", props.legendOpen && "bg-accent text-accent-foreground")}
                onClick={props.onToggleLegend}
                aria-pressed={props.legendOpen}
                aria-label="Toggle legend"
              >
                <Info className="h-3.5 w-3.5" />
              </Button>
            </TooltipTrigger>
            <TooltipContent>{props.legendOpen ? "Hide legend" : "Show legend"}</TooltipContent>
          </Tooltip>
          <Tooltip>
            <TooltipTrigger asChild>
              <Button
                variant="outline"
                size="sm"
                className={cn("h-8 w-8 p-0", props.minimapOpen && "bg-accent text-accent-foreground")}
                onClick={props.onToggleMinimap}
                aria-pressed={props.minimapOpen}
                aria-label="Toggle minimap"
              >
                <Map className="h-3.5 w-3.5" />
              </Button>
            </TooltipTrigger>
            <TooltipContent>{props.minimapOpen ? "Hide minimap" : "Show minimap"}</TooltipContent>
          </Tooltip>
          <Tooltip>
            <TooltipTrigger asChild>
              <Button
                variant="outline"
                size="sm"
                className={cn(
                  "h-8 w-8 p-0",
                  props.conflictsOpen && "border-yellow-500/50 bg-yellow-500/10 text-yellow-300",
                )}
                onClick={props.onToggleConflicts}
                aria-pressed={props.conflictsOpen}
                aria-label={`Merge conflicts${props.conflictCount ? `: ${props.conflictCount}` : ""}`}
              >
                <AlertTriangle className="h-3.5 w-3.5" />
              </Button>
            </TooltipTrigger>
            <TooltipContent>
              {props.conflictCount > 0
                ? `${props.conflictCount} merge conflicts during ingestion — click to inspect`
                : "No merge conflicts"}
            </TooltipContent>
          </Tooltip>
        </ToolbarGroup>
      </TooltipProvider>

      <div className="ml-auto mt-1.5 w-full min-w-0 sm:mt-0 sm:w-72">
        <GraphSearch nodes={props.nodes} onFocusNode={props.onFocusNode} disabled={props.nodes.length === 0} />
      </div>
    </div>
  );
}

function ToolbarGroup({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div role="group" aria-label={label} className="flex items-center gap-1">
      <span className="mr-1 hidden text-[9px] font-semibold uppercase tracking-wide text-muted-foreground xl:inline">
        {label}
      </span>
      {children}
    </div>
  );
}
