// Category navigation: a compact vertical sidebar on desktop, a horizontally
// scrollable segmented control on mobile. No giant tab bar.

import { cn } from "@/lib/utils";
import { CATEGORY_LABELS, type SettingCategory } from "./settingMeta";

const CATEGORIES: SettingCategory[] = ["general", "ai", "features", "advanced"];

interface SettingsNavProps {
  value: SettingCategory;
  onChange: (category: SettingCategory) => void;
}

export function SettingsNav({ value, onChange }: SettingsNavProps) {
  return (
    <>
      <nav aria-label="Settings categories" className="hidden md:block">
        <ul className="space-y-1">
          {CATEGORIES.map((c) => (
            <li key={c}>
              <button
                type="button"
                onClick={() => onChange(c)}
                aria-current={value === c ? "page" : undefined}
                className={cn(
                  "flex w-full items-center rounded-md px-3 py-2 text-sm transition-colors",
                  value === c
                    ? "bg-primary/10 font-medium text-primary"
                    : "text-muted-foreground hover:bg-accent hover:text-foreground",
                )}
              >
                {CATEGORY_LABELS[c]}
              </button>
            </li>
          ))}
        </ul>
      </nav>

      <div className="md:hidden" role="radiogroup" aria-label="Settings categories">
        <div className="flex gap-1 overflow-x-auto rounded-md border bg-muted/40 p-0.5">
          {CATEGORIES.map((c) => (
            <button
              key={c}
              type="button"
              role="radio"
              aria-checked={value === c}
              onClick={() => onChange(c)}
              className={cn(
                "h-8 shrink-0 rounded px-3 text-sm transition-colors",
                value === c ? "bg-background text-foreground shadow" : "text-muted-foreground hover:text-foreground",
              )}
            >
              {CATEGORY_LABELS[c]}
            </button>
          ))}
        </div>
      </div>
    </>
  );
}
