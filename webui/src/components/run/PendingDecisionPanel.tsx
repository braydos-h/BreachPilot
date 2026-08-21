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
      <CardHeader className="pb-2">
        <CardTitle className="flex items-center gap-2 text-sm text-yellow-200">
          <AlertTriangle className="h-4 w-4 animate-pulse" aria-hidden />
          <span>Run is waiting on the operator</span>
          <Badge variant="warn" className="ml-auto tabular-nums">
            {decisions.length} pending
          </Badge>
        </CardTitle>
        <p className="text-xs text-muted-foreground">
          {decisions.length === 1
            ? "The agent is paused until this decision is answered."
            : "The agent is paused until these decisions are answered."}
        </p>
      </CardHeader>
      <CardContent className="space-y-2">
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
