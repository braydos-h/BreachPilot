// Category navigation: a compact vertical sidebar on desktop, a horizontally
// scrollable segmented control on mobile. No giant tab bar.

import { cn } from "@/lib/utils";
import { CATEGORY_LABELS, type SettingCategory } from "./settingMeta";
import { Settings, Brain, ScanSearch, Puzzle, PlugZap, SlidersHorizontal } from "lucide-react";

const CATEGORIES: Array<{ id: SettingCategory; label: string; icon: React.ComponentType<{ className?: string }> }> = [
  { id: "general", label: CATEGORY_LABELS.general, icon: Settings },
  { id: "ai", label: "AI & Models", icon: Brain },
  { id: "runs", label: "Runs & Scanning", icon: ScanSearch },
  { id: "features", label: "Features", icon: Puzzle },
  { id: "integrations", label: "Notifications & Integrations", icon: PlugZap },
  { id: "advanced", label: "Advanced", icon: SlidersHorizontal },
];

interface SettingsNavProps {
  value: SettingCategory;
  onChange: (category: SettingCategory) => void;
}

export function SettingsNav({ value, onChange }: SettingsNavProps) {
  return (
    <>
      <nav aria-label="Settings categories" className="hidden md:block">
        <ul className="space-y-1">
          {CATEGORIES.map(({ id, label, icon: Icon }) => (
            <li key={id}>
              <button
                type="button"
                onClick={() => onChange(id)}
                aria-current={value === id ? "page" : undefined}
                className={cn(
                  "flex w-full items-center gap-2 rounded-md px-3 py-2 text-sm transition-colors",
                  value === id
                    ? "bg-primary/10 font-medium text-primary"
                    : "text-muted-foreground hover:bg-accent hover:text-foreground",
                )}
              >
                <Icon className="h-4 w-4 shrink-0" />
                {label}
              </button>
            </li>
          ))}
        </ul>
      </nav>

      <div className="md:hidden" role="radiogroup" aria-label="Settings categories">
        <div className="flex gap-1 overflow-x-auto rounded-md border bg-muted/40 p-0.5">
          {CATEGORIES.map(({ id, label, icon: Icon }) => (
            <button
              key={id}
              type="button"
              role="radio"
              aria-checked={value === id}
              onClick={() => onChange(id)}
              className={cn(
                "flex h-8 shrink-0 items-center gap-1.5 rounded px-3 text-sm transition-colors",
                value === id ? "bg-background text-foreground shadow" : "text-muted-foreground hover:text-foreground",
              )}
            >
              <Icon className="h-3.5 w-3.5 shrink-0" />
              {label}
            </button>
          ))}
        </div>
      </div>
    </>
  );
}
