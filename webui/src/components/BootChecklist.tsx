import { CheckCircle2, Loader2, XCircle } from "lucide-react";
import { cn } from "@/lib/utils";
import type { RunEvent } from "@/api/types";

interface BootChecklistProps {
  events: RunEvent[];
  className?: string;
}

interface BootStep {
  key: string;
  label: string;
  ok: boolean;
  failed: boolean;
}

export function BootChecklist({ events, className }: BootChecklistProps) {
  const steps: Record<string, BootStep> = {};
  for (const event of events) {
    if (event.type !== "boot" && event.type !== "ok") continue;
    const step = typeof event.payload.step === "string" ? event.payload.step : "";
    const label = typeof event.payload.label === "string" ? event.payload.label : step;
    if (!step) continue;
    const ok = event.payload.ok === true || event.type === "ok";
    const failed = event.payload.failed === true || event.payload.ok === false;
    const existing = steps[step];
    if (existing && !failed && !ok) continue;
    steps[step] = { key: step, label: label || step, ok: ok ?? existing?.ok ?? false, failed: failed ?? existing?.failed ?? false };
  }

  const list = Object.values(steps);
  if (list.length === 0) return null;

  return (
    <ul className={cn("space-y-1.5 text-sm", className)} aria-label="Boot checklist">
      {list.map((step) => (
        <li key={step.key} className="flex items-center gap-2">
          {step.failed ? (
            <XCircle className="h-4 w-4 text-red-400" aria-label="Failed" />
          ) : step.ok ? (
            <CheckCircle2 className="h-4 w-4 text-emerald-400" aria-label="Completed" />
          ) : (
            <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" aria-label="In progress" />
          )}
          <span className={cn(step.failed ? "text-red-300" : step.ok ? "text-foreground" : "text-muted-foreground")}>
            {step.label}
          </span>
        </li>
      ))}
    </ul>
  );
}