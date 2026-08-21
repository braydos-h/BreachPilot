import { memo } from "react";
import type { NodeProps } from "reactflow";
import { cn } from "@/lib/utils";
import type { GraphExplorerNode } from "@/features/graph/graphTypes";
import { nodeTypeMeta, statusMeta } from "@/features/graph/graphTransforms";

export interface GraphFlowNodeData {
  label: string;
  node: GraphExplorerNode;
  path?: boolean;
  focus?: boolean;
}

// Custom node for the explorer canvas. Selected state is shown with both a
// color ring AND a solid outline + dot (non-color-only). Path-emphasis nodes
// get a dashed outer ring; the focus (search-result) node pulses.
export const GraphFlowNode = memo(function GraphFlowNode({ data, selected }: NodeProps<GraphFlowNodeData>) {
  const meta = nodeTypeMeta(data.node.node_type);
  const status = statusMeta(data.node.status);
  const props = data.node.properties;
  const cvss = typeof props.cvss_score === "number" ? props.cvss_score : null;
  const severity = typeof props.severity === "string" ? (props.severity as string) : null;

  return (
    <div
      className={cn(
        "rounded-md px-2 py-1.5 font-mono text-[11px] leading-tight transition-shadow",
        selected && "ring-2 ring-foreground shadow-lg",
        data.focus && "animate-pulse",
      )}
      style={{
        background: meta.bg,
        border: `1.5px solid ${meta.color}`,
        outline: selected
          ? "1px solid color-mix(in srgb, currentColor 60%, transparent)"
          : data.path
            ? "1.5px dashed rgb(52,211,153)"
            : undefined,
      }}
    >
      <div className="flex items-center gap-1">
        <span className="h-1.5 w-1.5 shrink-0 rounded-full" style={{ background: meta.color }} aria-hidden />
        <span className="truncate font-medium" title={data.node.value}>{data.label}</span>
      </div>
      <div className="mt-0.5 flex flex-wrap items-center gap-1">
        <span className="rounded bg-black/20 px-1 text-[9px] uppercase tracking-wide dark:bg-white/10">
          {meta.label}
        </span>
        {status.label !== "Unknown" && (
          <span className="rounded bg-black/20 px-1 text-[9px] uppercase tracking-wide dark:bg-white/10">
            {status.label}
          </span>
        )}
        {cvss !== null && (
          <span className="rounded bg-black/20 px-1 text-[9px] tabular-nums dark:bg-white/10">
            CVSS {cvss.toFixed(1)}
          </span>
        )}
        {severity !== null && (
          <span className="rounded bg-black/20 px-1 text-[9px] uppercase dark:bg-white/10">{severity}</span>
        )}
      </div>
    </div>
  );
});
