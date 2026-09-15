import { Link } from "react-router-dom";
import type { ReactNode } from "react";

/** Global empty-state convention (todo 47): every empty state = reason + next action. */
export function EmptyState({
  title,
  reason,
  actionLabel,
  actionTo,
  onAction,
  children,
}: {
  title: string;
  reason: string;
  actionLabel?: string;
  actionTo?: string;
  onAction?: () => void;
  children?: ReactNode;
}) {
  return (
    <div className="flex flex-col items-start gap-2 rounded-md border border-dashed p-6 text-sm">
      <div className="text-sm font-semibold">{title}</div>
      <p className="text-[13px] leading-relaxed text-muted-foreground">{reason}</p>
      {actionLabel && actionTo && (
        <Link to={actionTo} className="text-[13px] font-medium text-primary underline-offset-4 hover:underline">
          {actionLabel}
        </Link>
      )}
      {actionLabel && onAction && !actionTo && (
        <button type="button" onClick={onAction} className="text-[13px] font-medium text-primary underline-offset-4 hover:underline">
          {actionLabel}
        </button>
      )}
      {children}
    </div>
  );
}
