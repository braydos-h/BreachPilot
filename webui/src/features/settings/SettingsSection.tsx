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
    <section className={cn("overflow-hidden rounded-lg border bg-card/40", className)}>
      <header className="border-b px-4 py-3">
        <h2 className="text-sm font-semibold">{title}</h2>
        {description && <p className="mt-0.5 text-xs leading-relaxed text-muted-foreground">{description}</p>}
      </header>
      <div className="divide-y divide-border px-4">{children}</div>
    </section>
  );
}
