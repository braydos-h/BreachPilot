import { Activity } from "lucide-react";
import { cn } from "@/lib/utils";
import { Card, CardContent } from "@/components/ui/card";
import { Skeleton } from "@/components/Loading";
import type { Tone } from "./statsAggregations";

export function StatCard({
  icon: Icon,
  label,
  value,
  sub,
  tone,
  loading,
  available,
}: {
  icon: typeof Activity;
  label: string;
  value: string;
  sub: string;
  tone: Tone;
  loading: boolean;
  available: boolean;
}) {
  const toneClasses: Record<Tone, { icon: string; value: string; border: string }> = {
    neutral: { icon: "bg-primary/10 text-primary", value: "text-foreground", border: "border-primary/15" },
    success: { icon: "bg-emerald-500/10 text-emerald-700 dark:text-emerald-300", value: "text-foreground", border: "border-emerald-500/20" },
    danger: { icon: "bg-destructive/10 text-red-600 dark:text-red-300", value: "text-foreground", border: "border-destructive/20" },
    warning: { icon: "bg-amber-500/10 text-amber-700 dark:text-amber-300", value: "text-foreground", border: "border-amber-500/20" },
  };
  const classes = toneClasses[tone];

  return (
    <Card className={cn("h-full", classes.border)}>
      <CardContent className="flex min-h-[7.5rem] flex-col justify-between gap-3 p-4">
        <div className="flex items-center justify-between gap-2">
          <span className="text-[10px] font-medium uppercase tracking-wide text-muted-foreground">{label}</span>
          <span className={cn("flex h-7 w-7 items-center justify-center rounded-md", classes.icon)}>
            <Icon className="h-3.5 w-3.5" aria-hidden="true" />
          </span>
        </div>
        <div className="min-w-0">
          {loading ? (
            <Skeleton className="h-7 w-20" />
          ) : (
            <div className={cn("truncate font-mono text-2xl font-semibold tabular-nums", classes.value)}>
              {available ? value : "—"}
            </div>
          )}
          <div className="mt-1 truncate text-xs text-muted-foreground">
            {loading ? <Skeleton className="h-3 w-28" /> : available ? sub : "Data unavailable"}
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
