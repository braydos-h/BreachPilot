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
    <div id={id} className={cn("flex flex-col gap-3 py-4 sm:flex-row sm:items-center sm:justify-between sm:gap-6", className)}>
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-1.5">
          <Label htmlFor={htmlFor} className="text-sm font-medium leading-snug">
            {label}
          </Label>
          {rawKey && <code className="hidden text-[10px] text-muted-foreground/70 sm:inline">{rawKey}</code>}
        </div>
        {description && <p className="mt-0.5 max-w-[60ch] text-xs leading-relaxed text-muted-foreground">{description}</p>}
      </div>
      <div className="flex shrink-0 justify-start sm:min-w-[200px] sm:justify-end">{children}</div>
    </div>
  );
}
