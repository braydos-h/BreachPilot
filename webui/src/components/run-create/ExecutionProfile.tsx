import { Check } from "lucide-react";
import { cn } from "@/lib/utils";
import { Label } from "@/components/ui/label";
import { EXECUTION_PROFILES, type ExecutionProfileId } from "./profile";

interface ExecutionProfileProps {
  value: ExecutionProfileId;
  onSelect: (id: ExecutionProfileId) => void;
}

/** UI-only execution presets. A preset maps onto the existing frontend fields
 *  (power-ups + observer + skills) — it never creates a new backend run
 *  parameter. Selecting one batches the field values into the wizard; any
 *  manual change afterwards flips the profile back to Custom. */
export function ExecutionProfile({ value, onSelect }: ExecutionProfileProps) {
  return (
    <div className="space-y-2">
      <Label className="text-sm font-semibold">Execution profile</Label>
      <div role="radiogroup" aria-label="Execution profile" className="grid gap-2.5 sm:grid-cols-2">
        {EXECUTION_PROFILES.map((p) => {
          const selected = value === p.id;
          return (
            <button
              key={p.id}
              type="button"
              role="radio"
              aria-checked={selected}
              onClick={() => onSelect(p.id)}
              className={cn(
                "flex items-start gap-2.5 rounded-lg border p-3 text-left transition-colors",
                "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring",
                selected
                  ? "border-primary/50 bg-primary/5 ring-1 ring-primary/20"
                  : "border-border bg-background/40 hover:border-muted-foreground/40 hover:bg-accent/40",
              )}
            >
              <span
                className={cn(
                  "mt-0.5 flex h-4 w-4 shrink-0 items-center justify-center rounded-full border",
                  selected ? "border-primary bg-primary text-primary-foreground" : "border-muted-foreground/50",
                )}
                aria-hidden
              >
                {selected && <Check className="h-3 w-3" />}
              </span>
              <span className="min-w-0">
                <span className="block text-sm font-semibold">{p.label}</span>
                <span className="mt-0.5 block text-xs leading-relaxed text-muted-foreground">
                  {p.description}
                </span>
              </span>
            </button>
          );
        })}
      </div>
    </div>
  );
}
