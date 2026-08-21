import { useMemo, useRef, useState } from "react";
import { Crosshair, Search, X } from "lucide-react";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import {
  nodeTypeMeta,
  rankNodeMatches,
  severityMeta,
  statusMeta,
} from "@/features/graph/graphTransforms";
import type { GraphExplorerNode } from "@/features/graph/graphTypes";

export interface GraphSearchProps {
  nodes: GraphExplorerNode[];
  onFocusNode: (id: string) => void;
  disabled?: boolean;
}

// Local "find node in current graph" search. This is distinct from the
// server-side filter search in the sidebar: it searches only the already
// loaded view and jumps/focuses a match — it never changes what the backend
// returns. Multi-result dropdown with keyboard navigation (↑/↓, Enter, Esc).
export function GraphSearch({ nodes, onFocusNode, disabled }: GraphSearchProps) {
  const [q, setQ] = useState("");
  const [open, setOpen] = useState(false);
  const [activeIndex, setActiveIndex] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);

  const results = useMemo(() => rankNodeMatches(nodes, q).slice(0, 8), [nodes, q]);
  const trimmed = q.trim();

  const focus = (nodeId: string) => {
    onFocusNode(nodeId);
    setOpen(false);
  };

  const onKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "Escape") {
      e.preventDefault();
      setQ("");
      setOpen(false);
      return;
    }
    if (!trimmed) return;
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setOpen(true);
      setActiveIndex((i) => (results.length ? (i + 1) % results.length : 0));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setActiveIndex((i) => (results.length ? (i - 1 + results.length) % results.length : 0));
    } else if (e.key === "Enter") {
      e.preventDefault();
      const hit = results[Math.min(activeIndex, results.length - 1)];
      if (hit) focus(hit.node_id);
    }
  };

  const showDropdown = open && trimmed.length > 0;

  return (
    <div className="relative min-w-0 flex-1 sm:max-w-sm">
      <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
      <input
        ref={inputRef}
        value={q}
        onChange={(e) => {
          setQ(e.target.value);
          setOpen(true);
          setActiveIndex(0);
        }}
        onKeyDown={onKeyDown}
        onFocus={() => trimmed && setOpen(true)}
        onBlur={() => setOpen(false)}
        disabled={disabled}
        placeholder="Find node in graph (value, CVE, severity…)"
        aria-label="Find node in graph"
        role="combobox"
        aria-expanded={showDropdown}
        aria-controls="graph-search-results"
        aria-autocomplete="list"
        className="h-8 w-full rounded-md border border-input bg-background pl-8 pr-7 text-xs placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-1 disabled:cursor-not-allowed disabled:opacity-50"
      />
      {q && (
        <Button
          type="button"
          variant="ghost"
          size="sm"
          className="absolute right-1 top-1/2 h-6 w-6 -translate-y-1/2 p-0"
          onClick={() => {
            setQ("");
            setOpen(false);
            inputRef.current?.focus();
          }}
          aria-label="Clear node search"
        >
          <X className="h-3.5 w-3.5" />
        </Button>
      )}

      {showDropdown && (
        <div className="absolute left-0 right-0 top-full z-40 mt-1.5 overflow-hidden rounded-lg border bg-popover text-popover-foreground shadow-lg">
          {results.length === 0 ? (
            <p className="px-3 py-2 text-[11px] text-muted-foreground" role="status">
              No nodes match “{trimmed}”.
            </p>
          ) : (
            <ul
              id="graph-search-results"
              role="listbox"
              aria-label="Matching graph nodes"
              className="max-h-80 overflow-y-auto py-1"
            >
              {results.map((n, i) => (
                <li key={n.node_id} role="option" aria-selected={i === activeIndex}>
                  <button
                    type="button"
                    onMouseDown={(e) => {
                      e.preventDefault();
                      focus(n.node_id);
                    }}
                    onMouseEnter={() => setActiveIndex(i)}
                    aria-label={`Focus ${n.value}`}
                    className={cn(
                      "flex w-full items-center gap-2 px-2.5 py-1.5 text-left text-xs hover:bg-accent",
                      i === activeIndex && "bg-accent",
                    )}
                  >
                    <SearchResult node={n} />
                  </button>
                </li>
              ))}
            </ul>
          )}
          <div className="border-t bg-muted/30 px-2.5 py-1 text-[10px] text-muted-foreground">
            <kbd className="rounded border border-border px-0.5">↵</kbd> focus ·{" "}
            <kbd className="rounded border border-border px-0.5">esc</kbd> close
          </div>
        </div>
      )}
    </div>
  );
}

// Compact result row: status dot · truncated value · type + severity badges,
// with a focus affordance on hover. Accessible name includes the value so the
// row is targetable as "Focus <value>".
function SearchResult({ node }: { node: GraphExplorerNode }) {
  const type = nodeTypeMeta(node.node_type);
  const status = statusMeta(node.status);
  const props = node.properties;
  const severity = typeof props.severity === "string" && props.severity ? (props.severity as string) : null;
  const sevMeta = severity ? severityMeta(severity) : null;

  return (
    <span className="flex w-full items-center gap-2">
      <span className="h-1.5 w-1.5 shrink-0 rounded-full" style={{ background: status.color }} aria-hidden />
      <span className="truncate font-mono">{node.value}</span>
      <span className="ml-auto flex shrink-0 items-center gap-1">
        {severity && sevMeta && (
          <span className="rounded bg-black/20 px-1 text-[9px] uppercase dark:bg-white/10" style={{ color: sevMeta.color }}>
            {severity}
          </span>
        )}
        <span className="rounded bg-black/20 px-1 text-[9px] uppercase dark:bg-white/10" style={{ color: type.color }}>
          {type.label}
        </span>
        <Crosshair className="h-3 w-3 text-muted-foreground" aria-hidden />
      </span>
    </span>
  );
}
