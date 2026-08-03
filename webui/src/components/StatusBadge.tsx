import { cn } from "@/lib/utils";
import { Badge, type BadgeProps } from "@/components/ui/badge";
import { stateCategory, type RunState } from "@/api/types";

const CATEGORY_VARIANT: Record<"pending" | "active" | "done", BadgeProps["variant"]> = {
  pending: "muted",
  active: "warn",
  done: "secondary",
};

const DONE_VARIANT: Partial<Record<RunState, BadgeProps["variant"]>> = {
  completed: "success",
  failed: "danger",
  cancelled: "muted",
  interrupted: "warn",
};

interface StatusBadgeProps {
  state: RunState;
  className?: string;
}

export function StatusBadge({ state, className }: StatusBadgeProps) {
  const category = stateCategory(state);
  const variant = category === "done" ? (DONE_VARIANT[state] ?? "secondary") : CATEGORY_VARIANT[category];
  return (
    <Badge variant={variant} className={cn("tabular-nums", className)}>
      {state}
    </Badge>
  );
}