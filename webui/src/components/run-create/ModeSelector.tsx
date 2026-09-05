import { useRef } from "react";
import { Check, ScanSearch, Swords, Zap } from "lucide-react";
import { cn } from "@/lib/utils";
import type { RunMode } from "@/api/types";

interface ModeSelectorProps {
  value: RunMode;
  onChange: (mode: RunMode) => void;
}

const MODE_OPTIONS: Array<{
  value: RunMode;
  icon: typeof Swords;
  title: string;
  blurb: string;
}> = [
  {
    value: "recon",
    icon: ScanSearch,
    title: "Recon",
    blurb: "Map services, technologies and attack surface before exploitation.",
  },
  {
    value: "attack",
    icon: Swords,
    title: "Attack",
    blurb: "Run the autonomous offensive workflow against the selected target.",
  },
  {
    value: "fast",
    icon: Zap,
    title: "Fast",
    blurb: "Run optimized parallel recon first, then give the complete recon context to the AI agent.",
  },
];

/** Two compact selectable cards for Recon vs Attack — a visually meaningful
 *  alternative to a tiny segmented control. Keyboard-operable radiogroup. */
export function ModeSelector({ value, onChange }: ModeSelectorProps) {
  const refs = useRef<(HTMLButtonElement | null)[]>([]);

  const move = (from: number, dir: number) => {
    const next = (from + dir + MODE_OPTIONS.length) % MODE_OPTIONS.length;
    onChange(MODE_OPTIONS[next]?.value ?? value);
    refs.current[next]?.focus();
  };

  return (
    <div role="radiogroup" aria-label="Run mode" className="grid gap-3 sm:grid-cols-3">
      {MODE_OPTIONS.map((m, i) => {
        const Icon = m.icon;
        const selected = value === m.value;
        return (
          <button
            key={m.value}
            ref={(el) => {
              refs.current[i] = el;
            }}
            type="button"
            role="radio"
            aria-checked={selected}
            tabIndex={selected ? 0 : -1}
            onClick={() => onChange(m.value)}
            onKeyDown={(e) => {
              if (e.key === "ArrowLeft" || e.key === "ArrowUp") {
                e.preventDefault();
                move(i, -1);
              } else if (e.key === "ArrowRight" || e.key === "ArrowDown") {
                e.preventDefault();
                move(i, 1);
              } else if (e.key === "Home") {
                e.preventDefault();
                onChange(MODE_OPTIONS[0]?.value ?? value);
                refs.current[0]?.focus();
              } else if (e.key === "End") {
                e.preventDefault();
                onChange(MODE_OPTIONS[MODE_OPTIONS.length - 1]?.value ?? value);
                refs.current[MODE_OPTIONS.length - 1]?.focus();
              }
            }}
            className={cn(
              "group relative flex flex-col items-start gap-2 rounded-lg border p-4 text-left transition-all",
              "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring",
              selected
                ? "border-primary/50 bg-primary/5 ring-1 ring-primary/20"
                : "border-border bg-background/40 hover:border-muted-foreground/40 hover:bg-accent/40",
            )}
          >
            <span
              className={cn(
                "flex h-9 w-9 items-center justify-center rounded-md border",
                selected
                  ? "border-primary/40 bg-primary/10 text-primary"
                  : "border-border bg-muted/40 text-muted-foreground",
              )}
              aria-hidden
            >
              <Icon className="h-4 w-4" />
            </span>
            <span className="flex w-full items-center justify-between gap-2">
              <span className="text-sm font-semibold">{m.title}</span>
              {selected && (
                <span
                  className="inline-flex h-4 w-4 items-center justify-center rounded-full bg-primary text-primary-foreground"
                  aria-hidden
                >
                  <Check className="h-3 w-3" />
                </span>
              )}
            </span>
            <span className="text-xs leading-relaxed text-muted-foreground">{m.blurb}</span>
          </button>
        );
      })}
    </div>
  );
}
