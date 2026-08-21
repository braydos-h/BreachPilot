import { useMemo } from "react";
import { Copy, Crosshair, Expand, X } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { cn } from "@/lib/utils";
import { useGraphNode } from "@/features/graph/graphApi";
import { edgeMeta, nodeTypeMeta, parseEvidenceRef, severityMeta, statusMeta } from "@/features/graph/graphTransforms";
import type { GraphEdgeType, GraphExplorerEdge, GraphExplorerNode } from "@/features/graph/graphTypes";

export interface GraphDetailsPanelProps {
  runId: string;
  nodeId: string | null;
  onSelect: (id: string | null) => void;
  onClose: () => void;
  /** focus this node on the graph (jump the canvas) */
  onFocus?: (id: string) => void;
  /** expand the node's neighborhood by N hops */
  onExpand?: (id: string, hops: number) => void;
}

// Right-hand inspector. Renders only real backend metadata — severity/CVSS/
// CVE/vuln-class rows appear only when the backend produced them. Relationships
// are grouped by edge type and each neighbor jumps on click. Utility actions
// are optional so the panel can be used standalone (tests) or wired to the page.
export function GraphDetailsPanel({ runId, nodeId, onSelect, onClose, onFocus, onExpand }: GraphDetailsPanelProps) {
  const { data, isLoading, error } = useGraphNode(runId, nodeId, !!nodeId);

  if (!nodeId) {
    return (
      <div className="flex h-full items-center justify-center p-6 text-center text-sm text-muted-foreground">
        <p>Select a node in the graph to inspect it. The panel also works on its own: use Search to jump to a node.</p>
      </div>
    );
  }
  if (isLoading) {
    return (
      <div className="space-y-3 p-4">
        <Skeleton className="h-4 w-2/3" />
        <Skeleton className="h-20 w-full" />
        <Skeleton className="h-20 w-full" />
      </div>
    );
  }
  if (error) {
    return (
      <div className="p-4 text-sm text-destructive">
        <p>Failed to load node.</p>
        <Button variant="outline" size="sm" className="mt-2" onClick={onClose}>Close</Button>
      </div>
    );
  }
  if (!data) return null;

  const node = data.node;
  const status = statusMeta(node.status);
  const type = nodeTypeMeta(node.node_type);
  const props = node.properties;
  const hasCvss = typeof props.cvss_score === "number";
  const hasSeverity = typeof props.severity === "string" && !!props.severity;
  const severity = hasSeverity ? severityMeta(String(props.severity)) : null;
  const hasVulnClass = typeof props.vuln_class === "string" && !!props.vuln_class;
  const hasExploitation = typeof props.exploitation_result === "string" && !!props.exploitation_result;
  const hasPrivilege = typeof props.privilege_level_gained === "string" && !!props.privilege_level_gained;

  return (
    <div className="flex h-full flex-col">
      <div className="flex items-center justify-between gap-2 border-b px-3 py-2">
        <h2 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">Node details</h2>
        <Button variant="ghost" size="sm" className="h-6 w-6 p-0" onClick={onClose} aria-label="Close details">
          <X className="h-3.5 w-3.5" />
        </Button>
      </div>

      <div className="flex-1 space-y-4 overflow-y-auto p-3">
        {/* Overview */}
        <section>
          <p className="break-all font-mono text-sm font-medium leading-snug">{node.value}</p>
          <div className="mt-1.5 flex flex-wrap items-center gap-1.5">
            <Badge variant="outline" className="font-mono text-[10px]" style={{ borderColor: type.color, color: type.color }}>
              {type.label}
            </Badge>
            <Badge variant="outline" className="font-mono text-[10px]" style={{ borderColor: status.color, color: status.color }}>
              {status.label}
            </Badge>
            {hasSeverity && severity && (
              <Badge variant="outline" className="text-[10px] uppercase" style={{ borderColor: severity.color, color: severity.color }}>
                {String(props.severity)}
              </Badge>
            )}
            {hasCvss && (
              <Badge variant="outline" className="font-mono text-[10px] tabular-nums">
                CVSS {Number(props.cvss_score).toFixed(1)}
              </Badge>
            )}
          </div>
          {(onFocus || onExpand) && (
            <div className="mt-2 flex flex-wrap items-center gap-1">
              {onFocus && (
                <Button variant="outline" size="sm" className="h-6 gap-1 px-1.5 text-[11px]" onClick={() => onFocus(node.node_id)}>
                  <Crosshair className="h-3 w-3" aria-hidden /> Focus on graph
                </Button>
              )}
              {onExpand && (
                <>
                  <Button variant="outline" size="sm" className="h-6 gap-1 px-1.5 text-[11px]" onClick={() => onExpand(node.node_id, 1)}>
                    <Expand className="h-3 w-3" aria-hidden /> +1 hop
                  </Button>
                  <Button variant="outline" size="sm" className="h-6 gap-1 px-1.5 text-[11px]" onClick={() => onExpand(node.node_id, 2)}>
                    <Expand className="h-3 w-3" aria-hidden /> +2 hops
                  </Button>
                </>
              )}
            </div>
          )}
          <div className="mt-2 flex flex-wrap items-center gap-1">
            <CopyButton label="Copy value" value={node.value} />
            <CopyButton label="Copy ID" value={node.node_id} />
          </div>
        </section>

        <section className="space-y-1">
          <PropertyRow label="Node ID" value={node.node_id} mono />
          <PropertyRow label="Run ID" value={runId} mono />
          <PropertyRow label="Scope" value={node.scope} mono />
          <PropertyRow label="Source" value={node.source || "—"} />
          <PropertyRow label="Confidence" value={String(node.confidence.toFixed(2))} mono />
          <PropertyRow label="First seen" value={node.first_seen || "—"} mono />
          <PropertyRow label="Last seen" value={node.last_seen || "—"} mono />
          {node.observation_count > 0 && <PropertyRow label="Observations" value={String(node.observation_count)} mono />}
          {node.contradiction_count > 0 && <PropertyRow label="Contradictions" value={String(node.contradiction_count)} mono />}
        </section>

        {(hasVulnClass || hasExploitation || hasPrivilege) && (
          <SecuritySection
            vulnClass={hasVulnClass ? String(props.vuln_class) : undefined}
            exploitation={hasExploitation ? String(props.exploitation_result) : undefined}
            privilege={hasPrivilege ? String(props.privilege_level_gained) : undefined}
          />
        )}

        <RelationshipsSection nodeId={node.node_id} edges={data.edges} neighbors={data.neighbors} onSelect={onSelect} />

        <EvidenceSection evidenceRefs={node.evidence_refs} />

        <MetadataSection properties={props} />
      </div>
    </div>
  );
}

function CopyButton({ label, value }: { label: string; value: string }) {
  const copy = () => void navigator.clipboard?.writeText(value).catch(() => {});
  return (
    <Button variant="ghost" size="sm" className="h-6 gap-1 px-1.5 text-[11px] text-muted-foreground" onClick={copy}>
      <Copy className="h-3 w-3" aria-hidden /> {label}
    </Button>
  );
}

function PropertyRow({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="grid grid-cols-[7.5rem_1fr] gap-2 text-xs">
      <dt className="text-muted-foreground">{label}</dt>
      <dd className={cn("break-all text-foreground", mono && "font-mono")}>{value}</dd>
    </div>
  );
}

// Security context is shown only when the backend produced it — never
// fabricated for a node that has no vuln findings.
function SecuritySection({ vulnClass, exploitation, privilege }: { vulnClass?: string; exploitation?: string; privilege?: string }) {
  return (
    <section className="rounded-md border border-amber-500/20 bg-amber-500/5 p-2">
      <h3 className="mb-1.5 text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">Security context</h3>
      <dl className="space-y-1">
        {vulnClass && <PropertyRow label="Vuln class" value={vulnClass} />}
        {exploitation && <PropertyRow label="Exploitation" value={exploitation} />}
        {privilege && <PropertyRow label="Privilege gained" value={privilege} />}
      </dl>
    </section>
  );
}

// Properties already surfaced in dedicated rows/badges above — don't repeat
// them here. This is de-duplication, not fabrication.
const HANDLED_PROP_KEYS = new Set([
  "cvss_score",
  "severity",
  "vuln_class",
  "exploitation_result",
  "privilege_level_gained",
]);

function MetadataSection({ properties }: { properties: Record<string, unknown> }) {
  const entries = useMemo(
    () =>
      Object.entries(properties).filter(
        ([k, v]) => !HANDLED_PROP_KEYS.has(k) && v !== undefined && v !== null && v !== "",
      ),
    [properties],
  );
  if (entries.length === 0) return null;
  return (
    <section>
      <h3 className="mb-1.5 text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">Metadata</h3>
      <dl className="space-y-1">
        {entries.map(([k, v]) => (
          <div key={k} className="grid grid-cols-[7.5rem_1fr] gap-2 text-xs">
            <dt className="text-muted-foreground">{k}</dt>
            <dd className="break-all font-mono text-foreground">
              {typeof v === "object" ? JSON.stringify(v) : String(v)}
            </dd>
          </div>
        ))}
      </dl>
    </section>
  );
}

function EvidenceSection({ evidenceRefs }: { evidenceRefs: string[] }) {
  if (!evidenceRefs.length) return null;
  return (
    <section>
      <h3 className="mb-1.5 text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">
        Evidence / provenance
      </h3>
      <ul className="space-y-1">
        {evidenceRefs.map((ref) => {
          const p = parseEvidenceRef(ref);
          return (
            <li key={ref} className="rounded border border-border/60 bg-card/40 px-2 py-1.5 text-xs">
              <div className="flex items-center gap-1.5">
                {p.tool && <Badge variant="outline" className="font-mono text-[10px]">{p.tool}</Badge>}
                {p.target && <span className="font-mono text-foreground">{p.target}</span>}
              </div>
              <div className="mt-0.5 break-all font-mono text-[10px] text-muted-foreground">{ref}</div>
              {p.timestamp && <div className="text-[10px] text-muted-foreground">{p.timestamp}</div>}
            </li>
          );
        })}
      </ul>
    </section>
  );
}

function RelationshipsSection({
  nodeId,
  edges,
  neighbors,
  onSelect,
}: {
  nodeId: string;
  edges: GraphExplorerEdge[];
  neighbors: GraphExplorerNode[];
  onSelect: (id: string) => void;
}) {
  const grouped = useMemo(() => {
    const byType = new Map<string, GraphExplorerEdge[]>();
    for (const e of edges) {
      const list = byType.get(e.edge_type) ?? [];
      list.push(e);
      byType.set(e.edge_type, list);
    }
    return [...byType.entries()];
  }, [edges]);

  if (edges.length === 0) return null;
  return (
    <section>
      <h3 className="mb-1.5 text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">
        Relationships ({edges.length})
      </h3>
      <div className="space-y-2">
        {grouped.map(([edgeType, es]) => {
          const meta = edgeMeta(edgeType as GraphEdgeType);
          return (
            <div key={edgeType}>
              <div className="mb-0.5 flex items-center gap-1 text-[10px] font-mono uppercase" style={{ color: meta.color }}>
                <span className="h-1 w-3 rounded-full" style={{ background: meta.color }} aria-hidden />
                {edgeType}
              </div>
              <ul className="space-y-0.5">
                {es.slice(0, 24).map((e) => {
                  const otherId = e.source_node_id === nodeId ? e.target_node_id : e.source_node_id;
                  const neighbor = neighbors.find((n) => n.node_id === otherId);
                  const dir = e.source_node_id === nodeId ? "→" : "←";
                  return (
                    <li key={e.edge_id}>
                      <button
                        type="button"
                        className="flex w-full items-center gap-1 rounded px-1 py-0.5 text-left text-xs hover:bg-accent"
                        onClick={() => neighbor && onSelect(neighbor.node_id)}
                        title={otherId}
                      >
                        <span className="shrink-0 text-muted-foreground" aria-hidden>{dir}</span>
                        <span className="truncate font-mono">{neighbor ? neighbor.value : otherId}</span>
                        {neighbor && (
                          <span className="ml-auto shrink-0 font-mono text-[9px] text-muted-foreground">{neighbor.node_type}</span>
                        )}
                      </button>
                    </li>
                  );
                })}
              </ul>
            </div>
          );
        })}
      </div>
    </section>
  );
}
