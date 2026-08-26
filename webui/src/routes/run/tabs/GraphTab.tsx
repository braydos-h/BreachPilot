import { Link } from "react-router-dom";
import { Network } from "lucide-react";
import { Button } from "@/components/ui/button";
import { AttackGraph } from "@/components/AttackGraph";
import { AttackGraphDag } from "@/components/AttackGraphDag";

interface GraphTabProps {
  runId: string;
  ready: boolean;
}

export function GraphTab({ runId, ready }: GraphTabProps) {
  return (
    <div className="space-y-2">
      <div className="flex justify-end">
        <Button asChild size="sm" variant="outline" className="h-7 text-xs">
          <Link to={`/runs/${runId}/graph`}>
            Open in full page <Network className="ml-1 h-3 w-3" />
          </Link>
        </Button>
      </div>
      <AttackGraphDag runId={runId} />
      <AttackGraph runId={runId} ready={ready} />
    </div>
  );
}
