import { cn } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";
import { stateCategory, type RunState } from "@/api/types";

const CATEGORY_STYLES: Record<"pending" | "active" | "done", string> = {
  pending: "border-muted-foreground/30 text-muted-foreground",
  active: "border-yellow-500/40 bg-yellow-500/10 text-yellow-300",
  done: "border-transparent bg-secondary text-secondary-foreground",
};

const DONE_STATE_LABEL: Partial<Record<RunState, string>> = {
  completed: "border-emerald-500/40 bg-emerald-500/10 text-emerald-300",
  failed: "border-destructive/40 bg-destructive/10 text-red-300",
  cancelled: "text-muted-foreground",
  interrupted: "border-amber-600/40 bg-amber-600/10 text-amber-300",
};

interface StatusBadgeProps {
  state: RunState;
  className?: string;
}

export function StatusBadge({ state, className }: StatusBadgeProps) {
  const category = stateCategory(state);
  const doneStyle = category === "done" ? DONE_STATE_LABEL[state] : null;
  return (
    <Badge
      variant="outline"
      className={cn("tabular-nums", doneStyle ?? CATEGORY_STYLES[category], className)}
    >
      {state}
    </Badge>
  );
}