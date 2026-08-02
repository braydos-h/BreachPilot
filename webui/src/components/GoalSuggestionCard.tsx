import { Sparkles, Lock } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import type { SuggestedGoal } from "@/api/types";

interface GoalSuggestionCardProps {
  goal: SuggestedGoal;
  selected?: boolean;
  onClick?: () => void;
  compact?: boolean;
  className?: string;
}

function ratingColor(rating: number): string {
  if (rating >= 80) return "text-emerald-400";
  if (rating >= 55) return "text-yellow-400";
  return "text-red-400";
}

function ratingBar(rating: number): string {
  if (rating >= 80) return "bg-emerald-500";
  if (rating >= 55) return "bg-yellow-500";
  return "bg-red-500";
}

function riskBadgeClass(risk?: string): string {
  if (risk === "safe") return "border-emerald-500/40 bg-emerald-500/10 text-emerald-300";
  if (risk === "gated") return "border-yellow-500/40 bg-yellow-500/10 text-yellow-300";
  if (risk === "high") return "border-red-500/40 bg-red-500/10 text-red-300";
  return "border-muted-foreground/30 text-muted-foreground";
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
            <Badge variant="outline" className="gap-1 border-violet-500/40 bg-violet-500/10 text-violet-300">
              <Sparkles className="h-3 w-3" /> AI
            </Badge>
          )}
          <span className="text-sm font-medium">{goal.name}</span>
          {goal.risk_requirement && (
            <Badge variant="outline" className={cn("text-[10px]", riskBadgeClass(goal.risk_requirement))}>
              {goal.risk_requirement}
            </Badge>
          )}
          {!compatible && (
            <Badge variant="outline" className="gap-1 border-red-500/40 bg-red-500/10 text-red-300">
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