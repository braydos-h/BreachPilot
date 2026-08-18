import { useEffect, useMemo, useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Loader2, Network } from "lucide-react";
import { cn } from "@/lib/utils";
import { useFetchArtifactBlob } from "@/api/hooks";
import { ApiError } from "@/api/client";
import type { EnhancedReport, ExploitationChain, TechnicalFinding } from "@/api/types";

// B2: attack-graph view. Renders exploitation_chains[] from the enhanced
// report JSON (Flow A writes reports/<run_id>/enhanced/enhanced_report.json).
// Pure SVG — no graph library. Chains are short (3-10 nodes) so a hand-rolled
// left-to-right column layout reads better than a force-directed graph.

interface AttackGraphProps {
  runId: string;
  className?: string;
  ready?: boolean;
}

export function AttackGraph({ runId, className, ready = true }: AttackGraphProps) {
  const fetchArtifact = useFetchArtifactBlob(runId);
  const [report, setReport] = useState<EnhancedReport | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string>("");
  const mutate = fetchArtifact.mutate;

  useEffect(() => {
    // Don't fetch the enhanced report until the run is terminal or the artifact
    // list confirms it exists -- otherwise an in-progress run 404s on every
    // mount (StrictMode double-mount + tab remounts).
    if (!ready) {
      setLoading(false);
      setReport(null);
      setError("");
      return;
    }
    setLoading(true);
    setError("");
    setReport(null);
    mutate("enhanced/enhanced_report.json", {
      onSuccess: async (blob) => {
        try {
          const text = await blob.text();
          setReport(JSON.parse(text) as EnhancedReport);
        } catch {
          setError("enhanced_report.json is not valid JSON.");
        }
        setLoading(false);
      },
      onError: (err) => {
        setError(
          err instanceof ApiError && err.isNotFound
            ? "No enhanced report yet for this run."
            : "Failed to load enhanced report.",
        );
        setReport(null);
        setLoading(false);
      },
    });
  }, [mutate, runId, ready]);

  if (loading) {
    return (
      <div className="flex items-center gap-2 p-4 text-sm text-muted-foreground">
        <Loader2 className="h-4 w-4 animate-spin" />
        Loading attack graph...
      </div>
    );
  }
  if (!ready && !report && !error) {
    return (
      <div className="rounded-md border border-dashed p-4 text-sm text-muted-foreground">
        Attack path report is generated when the run completes.
      </div>
    );
  }
  if (error) {
    return (
      <div className="rounded-md border border-dashed p-4 text-sm text-muted-foreground">
        {error}
      </div>
    );
  }
  if (!report) return null;

  const chains = report.exploitation_chains ?? [];
  const findings = report.technical_findings ?? [];

  if (chains.length === 0 && findings.length === 0) {
    return (
      <div className="rounded-md border border-dashed p-4 text-sm text-muted-foreground">
        No exploitation chains or findings in this report.
      </div>
    );
  }

  return (
    <div className={cn("space-y-4", className)}>
      <div className="flex flex-wrap items-center gap-3">
        <Badge variant="outline" className="tabular-nums">{chains.length} chains</Badge>
        <Badge variant="outline" className="tabular-nums">{findings.length} findings</Badge>
        {report.report_metadata && (
          <span className="text-xs text-muted-foreground">
            generated: {String(report.report_metadata.generated_at ?? "—")}
          </span>
        )}
      </div>

      {chains.map((chain) => (
        <ChainCard key={chain.chain_id} chain={chain} />
      ))}

      {findings.length > 0 && <FindingsTable findings={findings} />}
    </div>
  );
}

// ── Chain SVG ──────────────────────────────────────────────────────────────

const NODE_W = 150;
const NODE_H = 46;
const NODE_GAP_X = 36;
const PADDING = 16;

function ChainCard({ chain }: { chain: ExploitationChain }) {
  const entries = chain.entries ?? [];
  const width = Math.max(entries.length * (NODE_W + NODE_GAP_X) - NODE_GAP_X + PADDING * 2, 320);
  const height = NODE_H + PADDING * 2;
  const markerId = `arrow-${chain.chain_id}`;

  return (
    <Card className="border-border/60">
      <CardHeader className="pb-2">
        <CardTitle className="flex flex-wrap items-center gap-2 text-sm">
          <Network className="h-4 w-4" />
          <span className="font-mono">{chain.chain_id}</span>
          <Badge variant="outline" className="font-mono text-xs">{chain.target}</Badge>
          {chain.successful ? (
            <Badge variant="success" className="text-xs">successful</Badge>
          ) : (
            <Badge variant="danger" className="text-xs">failed</Badge>
          )}
          {chain.final_privilege && chain.final_privilege !== "none" && (
            <Badge variant="outline" className="text-xs">priv: {chain.final_privilege}</Badge>
          )}
        </CardTitle>
      </CardHeader>
      <CardContent>
        {entries.length === 0 ? (
          <p className="text-xs text-muted-foreground">No chain entries.</p>
        ) : (
          <div className="overflow-x-auto">
            <svg
              width={width}
              height={height}
              role="img"
              aria-label={`Attack chain ${chain.chain_id} for ${chain.target}`}
              className="max-w-full"
            >
              {entries.map((entry, i) => {
                const x = PADDING + i * (NODE_W + NODE_GAP_X);
                const y = PADDING;
                const success = (entry.result ?? "").toLowerCase() === "success";
                const fill = success ? "rgba(16,185,129,0.12)" : "rgba(239,68,68,0.12)";
                const stroke = success ? "rgb(52,211,153)" : "rgb(248,113,113)";
                return (
                  <g key={i}>
                    {i > 0 && (
                      <line
                        x1={x - NODE_GAP_X}
                        y1={y + NODE_H / 2}
                        x2={x}
                        y2={y + NODE_H / 2}
                        stroke="currentColor"
                        strokeWidth={1.5}
                        className="text-muted-foreground/60"
                        markerEnd={`url(#${markerId})`}
                      />
                    )}
                    <rect
                      x={x}
                      y={y}
                      width={NODE_W}
                      height={NODE_H}
                      rx={6}
                      fill={fill}
                      stroke={stroke}
                      strokeWidth={1.5}
                    />
                    <text
                      x={x + 8}
                      y={y + 18}
                      className="fill-foreground font-mono"
                      style={{ fontSize: 11 }}
                    >
                      {truncate(String(entry.module ?? "?"), 18)}
                    </text>
                    <text
                      x={x + 8}
                      y={y + 34}
                      className={success ? "fill-emerald-400" : "fill-red-400"}
                      style={{ fontSize: 10 }}
                    >
                      {entry.result ?? "—"}
                    </text>
                  </g>
                );
              })}
              <defs>
                <marker
                  id={markerId}
                  viewBox="0 0 10 10"
                  refX="8"
                  refY="5"
                  markerWidth="6"
                  markerHeight="6"
                  orient="auto-start-reverse"
                >
                  <path d="M 0 0 L 10 5 L 0 10 z" className="fill-muted-foreground/60" />
                </marker>
              </defs>
            </svg>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

// ── Findings table ─────────────────────────────────────────────────────────

function severityVariant(sev: string): "danger" | "info" | "success" | "outline" {
  const s = sev.toLowerCase();
  if (s === "critical" || s === "high") return "danger";
  if (s === "medium") return "info";
  if (s === "low") return "outline";
  return "outline";
}

function FindingsTable({ findings }: { findings: TechnicalFinding[] }) {
  const rows = useMemo(
    () => [...findings].sort((a, b) => (b.cvss?.base_score ?? 0) - (a.cvss?.base_score ?? 0)),
    [findings],
  );
  return (
    <Card className="border-border/60">
      <CardHeader className="pb-2">
        <CardTitle className="text-sm">Technical Findings</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="overflow-x-auto rounded-md border">
          <table className="w-full border-collapse text-xs">
            <caption className="sr-only">Technical findings</caption>
            <thead>
              <tr className="bg-muted/40">
                <th scope="col" className="p-2 text-left">Severity</th>
                <th scope="col" className="p-2 text-left">CVSS</th>
                <th scope="col" className="p-2 text-left">Finding</th>
                <th scope="col" className="p-2 text-left">Asset</th>
                <th scope="col" className="p-2 text-left">Class</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((f) => (
                <tr key={f.finding_id} className="border-t border-border/40">
                  <td className="p-2">
                    <Badge variant={severityVariant(f.severity)} className="text-[10px]">
                      {f.severity}
                    </Badge>
                  </td>
                  <td className="p-2 font-mono tabular-nums">
                    {f.cvss?.base_score?.toFixed(1) ?? "—"}
                  </td>
                  <td className="p-2 max-w-md truncate" title={f.title}>{f.title}</td>
                  <td className="p-2 font-mono">{f.affected_asset}</td>
                  <td className="p-2">{f.vuln_class}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </CardContent>
    </Card>
  );
}

function truncate(s: string, n: number): string {
  return s.length <= n ? s : s.slice(0, n - 1) + "…";
}