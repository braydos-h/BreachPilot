import { Sparkles, Lock } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import { ratingColor, ratingBar } from "@/lib/risk";
import type { SuggestedGoal } from "@/api/types";

interface GoalSuggestionCardProps {
  goal: SuggestedGoal;
  selected?: boolean;
  onClick?: () => void;
  compact?: boolean;
  className?: string;
}

function riskVariant(risk?: string): "success" | "warn" | "danger" | "muted" {
  if (risk === "safe") return "success";
  if (risk === "gated") return "warn";
  if (risk === "high") return "danger";
  return "muted";
}

export function GoalSuggestionCard({
  goal,
  selected = false,
  onClick,
  compact = false,
  className,
}: GoalSuggestionCardProps) {
  const compatible = goal.compatible !== false;
  const rating = goal.success_rating ?? 0;
  const isAi = goal.is_ai_generated === true;

  return (
    <button
      type="button"
      onClick={onClick}
      disabled={!compatible || onClick == null}
      className={cn(
        "flex w-full items-start gap-3 rounded-md border p-2.5 text-left transition-colors",
        "hover:bg-accent focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring",
        !compatible && "cursor-not-allowed opacity-50 hover:bg-transparent",
        selected && "border-primary bg-accent ring-1 ring-primary",
        className,
      )}
    >
      <div className="min-w-0 flex-1 space-y-1">
        <div className="flex flex-wrap items-center gap-1.5">
          {isAi && (
            <Badge variant="violet">
              <Sparkles className="h-3 w-3" /> AI
            </Badge>
          )}
          <span className="text-sm font-medium">{goal.name}</span>
          {goal.risk_requirement && (
            <Badge variant={riskVariant(goal.risk_requirement)} className="text-[10px]">
              {goal.risk_requirement}
            </Badge>
          )}
          {!compatible && (
            <Badge variant="danger">
              <Lock className="h-3 w-3" /> BLOCKED
            </Badge>
          )}
        </div>

        <p className="line-clamp-2 text-xs text-muted-foreground">
          {goal.description || (goal.rationale ?? "")}
        </p>

        {!compact && goal.rationale && goal.description && (
          <p className="line-clamp-2 text-xs text-muted-foreground/80">{goal.rationale}</p>
        )}

        {goal.blocked_reason && (
          <p className="text-xs text-red-400/80">{goal.blocked_reason}</p>
        )}

        <div className="flex items-center gap-2 pt-0.5">
          {compatible ? (
            <>
              <span className={cn("font-mono text-xs font-semibold tabular-nums", ratingColor(rating))}>
                {rating}/100
              </span>
              <div className="h-1.5 w-20 overflow-hidden rounded-full bg-muted">
                <div className={cn("h-full rounded-full", ratingBar(rating))} style={{ width: `${rating}%` }} />
              </div>
              {goal.exploit_likelihood && (
                <span className="text-xs text-muted-foreground">{goal.exploit_likelihood}</span>
              )}
            </>
          ) : (
            <span className="text-xs text-muted-foreground">-</span>
          )}
        </div>
      </div>
    </button>
  );
}