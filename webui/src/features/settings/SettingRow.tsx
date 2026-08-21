// One labeled setting row: friendly label + description on the left, the
// control on the right. Stacks on narrow screens so the control never gets
// squeezed off the edge.

import type { ReactNode } from "react";
import { Label } from "@/components/ui/label";
import { cn } from "@/lib/utils";

interface SettingRowProps {
  label: string;
  description?: string;
  /** Raw config key shown as a subtle mono hint (Advanced mode, tooltips). */
  rawKey?: string;
  htmlFor?: string;
  /** Anchor id for search-to-scroll. */
  id?: string;
  children: ReactNode;
  className?: string;
}

export function SettingRow({ label, description, rawKey, htmlFor, id, children, className }: SettingRowProps) {
  return (
    <div id={id} className={cn("flex flex-col gap-2 py-3 sm:flex-row sm:items-center sm:justify-between sm:gap-4", className)}>
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-1.5">
          <Label htmlFor={htmlFor} className="text-sm font-medium leading-snug">
            {label}
          </Label>
          {rawKey && <code className="text-[10px] text-muted-foreground/70">{rawKey}</code>}
        </div>
        {description && <p className="mt-0.5 text-xs leading-relaxed text-muted-foreground">{description}</p>}
      </div>
      <div className="shrink-0">{children}</div>
    </div>
  );
}
