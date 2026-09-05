// Global settings search. Matches the friendly label, the raw config key, and
// the description across every schema section. Selecting a result jumps to its
// category (and scrolls to the field when it's visible).

import { useEffect, useMemo, useRef, useState } from "react";
import { Search } from "lucide-react";
import { Input } from "@/components/ui/input";
import { useSettingsDraft } from "./useSettingsDraft";
import { CATEGORY_LABELS, fieldCategory, getSettingMeta, type SettingCategory } from "./settingMeta";

interface SettingsSearchProps {
  onSelect: (category: SettingCategory, section: string, field: string) => void;
}

interface SearchHit {
  section: string;
  field: string;
  label: string;
  raw: string;
  category: SettingCategory;
}

export function SettingsSearch({ onSelect }: SettingsSearchProps) {
  const { schema } = useSettingsDraft();
  const [query, setQuery] = useState("");
  const [open, setOpen] = useState(false);
  const boxRef = useRef<HTMLDivElement>(null);

  const hits = useMemo<SearchHit[]>(() => {
    const q = query.trim().toLowerCase();
    if (q.length < 2 || !schema) return [];
    const out: SearchHit[] = [];
    for (const [section, value] of Object.entries(schema as Record<string, unknown>)) {
      for (const field of Object.keys((value ?? {}) as Record<string, unknown>)) {
        const meta = getSettingMeta(section, field);
        const label = meta?.label ?? `${section}.${field}`;
        const raw = `${section}.${field}`;
        const haystack = `${label} ${raw} ${meta?.description ?? ""}`.toLowerCase();
        if (haystack.includes(q)) {
          out.push({ section, field, label, raw, category: fieldCategory(section, field) });
        }
      }
    }
    return out.slice(0, 20);
  }, [query, schema]);

  // Close the dropdown on outside click.
  useEffect(() => {
    if (!open) return;
    const onDocClick = (e: MouseEvent) => {
      if (boxRef.current && !boxRef.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", onDocClick);
    return () => document.removeEventListener("mousedown", onDocClick);
  }, [open]);

  const select = (hit: SearchHit) => {
    onSelect(hit.category, hit.section, hit.field);
    setQuery("");
    setOpen(false);
  };

  return (
    <div ref={boxRef} className="relative w-full max-w-sm">
      <Search className="pointer-events-none absolute left-2.5 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
      <Input
        value={query}
        onChange={(e) => {
          setQuery(e.target.value);
          setOpen(true);
        }}
        onFocus={() => setOpen(true)}
        onKeyDown={(e) => {
          if (e.key === "Escape") setOpen(false);
          if (e.key === "Enter") {
            const first = hits[0];
            if (first) select(first);
          }
        }}
        placeholder="Search settings"
        aria-label="Search settings"
        aria-expanded={open}
        className="pl-8"
      />
      {open && query.trim().length >= 2 && (
        <div className="absolute left-0 right-0 top-full z-30 mt-1 overflow-hidden rounded-md border bg-popover text-popover-foreground shadow-md">
          {hits.length === 0 ? (
            <p className="px-3 py-2 text-sm text-muted-foreground">No matching settings.</p>
          ) : (
            <ul role="listbox" aria-label="Search results" className="max-h-72 overflow-y-auto p-1">
              {hits.map((hit) => (
                <li key={hit.raw}>
                  <button
                    type="button"
                    role="option"
                    onClick={() => select(hit)}
                    className="flex w-full items-center justify-between gap-2 rounded px-2 py-1.5 text-left text-sm hover:bg-accent"
                  >
                    <span className="min-w-0">
                      <span className="block truncate">{hit.label}</span>
                      <span className="block truncate font-mono text-[10px] text-muted-foreground">{hit.raw}</span>
                    </span>
                    <span className="shrink-0 rounded bg-muted px-1.5 py-0.5 text-[10px] text-muted-foreground">
                      {CATEGORY_LABELS[hit.category]}
                    </span>
                  </button>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
    </div>
  );
}
