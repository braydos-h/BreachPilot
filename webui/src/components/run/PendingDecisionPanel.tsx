import { memo } from "react";
import { AlertTriangle } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { DecisionCard } from "@/components/DecisionCard";
import type { DecisionListRow } from "@/api/types";

interface PendingDecisionPanelProps {
  decisions: DecisionListRow[];
  runId: string;
  /** Decision ids currently being auto-answered by the permission mode. */
  autoAnsweringIds: Set<string>;
}

/**
 * Hero panel shown whenever the run is waiting on the operator. Placed at the
 * top of the main column so it is visible on every tab; collapses to nothing
 * when there is nothing to review.
 */
export const PendingDecisionPanel = memo(function PendingDecisionPanel({
  decisions,
  runId,
  autoAnsweringIds,
}: PendingDecisionPanelProps) {
  return (
    <Card
      id="pending-decisions"
      className="border-yellow-500/40 bg-yellow-500/[0.06]"
    >
      <CardHeader className="px-2.5 py-2 pb-1">
        <CardTitle className="flex items-center gap-1.5 text-xs text-yellow-200">
          <AlertTriangle className="h-3.5 w-3.5 animate-pulse" aria-hidden />
          <span>Waiting on operator</span>
          <Badge variant="warn" className="ml-auto text-[9px] leading-none tabular-nums">
            {decisions.length}
          </Badge>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-1.5 px-2.5 pb-2 pt-0">
        {decisions.map((d) => (
          <DecisionCard
            key={d.id}
            decision={d}
            runId={runId}
            autoAnswering={autoAnsweringIds.has(d.id)}
          />
        ))}
      </CardContent>
    </Card>
  );
});
