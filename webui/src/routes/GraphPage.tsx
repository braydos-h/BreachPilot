import { Link, useParams } from "react-router-dom";
import { ChevronLeft } from "lucide-react";
import { Button } from "@/components/ui/button";
import { AttackGraphDag } from "@/components/AttackGraphDag";
import { AttackGraph } from "@/components/AttackGraph";
import { useArtifacts } from "@/api/hooks";
import { truncateId } from "@/lib/utils";

const DAG_HEIGHT = Math.min(640, Math.max(320, (typeof window !== "undefined" ? window.innerHeight : 640) - 220));

export function GraphPage() {
  const { runId } = useParams<{ runId: string }>();
  const artifacts = useArtifacts(runId ?? null);
  const artifactNames = artifacts.data?.artifacts.map((a) => a.name) ?? [];
  const enhancedReady = artifactNames.includes("enhanced/enhanced_report.json");

  return (
    <div className="space-y-4 p-4 md:p-6">
      <div className="flex items-center gap-2">
        <Button asChild size="sm" variant="ghost">
          <Link to={`/runs/${runId}`}><ChevronLeft className="h-4 w-4" />Back to run</Link>
        </Button>
        <h1 className="text-sm font-mono text-muted-foreground" title={runId}>{truncateId(runId ?? "")}</h1>
        <span className="text-sm font-medium">Attack Path</span>
      </div>

      {artifacts.error && (
        <div className="flex items-center gap-2 text-sm text-destructive">
          <span>Failed to load artifacts.</span>
          <Button size="sm" variant="outline" onClick={() => artifacts.refetch()}>Retry</Button>
        </div>
      )}

      <AttackGraphDag runId={runId ?? ""} height={DAG_HEIGHT} />

      <AttackGraph runId={runId ?? ""} ready={enhancedReady} />
    </div>
  );
}