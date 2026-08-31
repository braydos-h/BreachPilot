// A bordered settings section: title + optional description header, then the
// rows. Rows are separated by hairlines so long lists stay scannable.

import type { ReactNode } from "react";
import { cn } from "@/lib/utils";

interface SettingsSectionProps {
  title: string;
  description?: string;
  children: ReactNode;
  className?: string;
}

export function SettingsSection({ title, description, children, className }: SettingsSectionProps) {
  return (
    <section className={cn("overflow-hidden rounded-xl border bg-card shadow-sm", className)}>
      <header className="flex justify-between bg-muted/30 px-5 py-4">
        <div>
          <h2 className="text-sm font-semibold">{title}</h2>
          {description && <p className="mt-0.5 max-w-[65ch] text-xs leading-relaxed text-muted-foreground">{description}</p>}
        </div>
      </header>
      <div className="divide-y divide-border/60 px-5">{children}</div>
    </section>
  );
}
