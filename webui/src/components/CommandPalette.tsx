import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { PRODUCT_ROUTES } from "@/lib/productRoutes";

export interface PaletteEntry {
  label: string;
  hint?: string;
  to?: string;
  action?: () => void;
  keywords?: string;
}

/** Global Cmd/Ctrl+K palette (todo 33): entities + settings + help + commands. */
export function CommandPalette({
  open,
  onOpenChange,
  extraEntries = [],
}: {
  open: boolean;
  onOpenChange: (v: boolean) => void;
  extraEntries?: PaletteEntry[];
}) {
  const [query, setQuery] = useState("");
  const base: PaletteEntry[] = useMemo(
    () => [
      { label: "New run", hint: "Command", to: "/runs/new", keywords: "create start recon attack" },
      { label: "Runs", hint: "Go to", to: "/runs", keywords: "sessions list" },
      { label: "Connections", hint: "Go to", to: "/connections" },
      ...PRODUCT_ROUTES.map((r) => ({ label: r.label, hint: "Go to", to: r.path, keywords: r.helpDescription })),
      { label: "Provider settings", hint: "Settings", to: "/system", keywords: "model ollama keys" },
      { label: "Run local self-test", hint: "Command", to: "/system", keywords: "diagnostics smoke localhost" },
      { label: "Help & reference", hint: "Go to", to: "/help" },
    ],
    [],
  );
  const all = [...base, ...extraEntries];
  const q = query.trim().toLowerCase();
  const results = !q
    ? all.slice(0, 9)
    : all.filter((e) => `${e.label} ${e.hint ?? ""} ${e.keywords ?? ""}`.toLowerCase().includes(q)).slice(0, 12);
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-lg p-0">
        <DialogHeader className="border-b p-3">
          <DialogTitle className="sr-only">Global search</DialogTitle>
          <input
            autoFocus
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search runs, targets, settings, help, commands…"
            aria-label="Global search"
            className="w-full bg-transparent text-sm outline-none placeholder:text-muted-foreground"
          />
        </DialogHeader>
        <div className="max-h-80 overflow-y-auto p-1.5" role="listbox" aria-label="Search results">
          {results.length === 0 && <p className="px-3 py-6 text-sm text-muted-foreground">No matches. Try “run”, “provider”, or “evidence”.</p>}
          {results.map((r) => (
            <Link
              key={`${r.label}-${r.to ?? r.hint}`}
              to={r.to ?? "/"}
              onClick={() => {
                r.action?.();
                onOpenChange(false);
                setQuery("");
              }}
              className="flex items-center gap-2 rounded-md px-3 py-2 text-sm hover:bg-accent"
            >
              <span className="flex-1 truncate">{r.label}</span>
              {r.hint && <span className="text-xs text-muted-foreground">{r.hint}</span>}
            </Link>
          ))}
        </div>
      </DialogContent>
    </Dialog>
  );
}
