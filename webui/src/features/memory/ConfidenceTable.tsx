import { cn, formatRelative } from "@/lib/utils";
import type { MemoryConfidence } from "@/api/types";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { formatMemoryPercent } from "./memoryFilters";
import type { MemoryTone } from "./MemoryOverviewCards";

function confidenceTone(confidence: number): MemoryTone {
  if (confidence >= 0.75) return "success";
  if (confidence >= 0.45) return "warning";
  return "danger";
}

export function ConfidenceMeter({ value }: { value: number }) {
  const pct = Math.max(0, Math.min(100, value * 100));
  const tone = confidenceTone(value);
  const label = tone === "success" ? "High" : tone === "warning" ? "Med" : "Low";
  const barClass =
    tone === "success" ? "bg-emerald-500" : tone === "warning" ? "bg-amber-500" : "bg-destructive";
  return (
    <div className="flex min-w-[120px] items-center gap-2">
      <div
        className="h-1.5 flex-1 overflow-hidden rounded-full bg-muted"
        role="progressbar"
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={Math.round(pct)}
        aria-label={`Confidence ${Math.round(pct)} percent, ${label}`}
      >
        <div className={cn("h-full rounded-full transition-[width]", barClass)} style={{ width: `${pct}%` }} />
      </div>
      <span className="inline-flex items-center gap-1 font-mono text-xs tabular-nums">
        {formatMemoryPercent(pct)}
        <span
          className={cn(
            "rounded px-1 py-0 text-[10px] font-medium leading-none",
            tone === "success" && "bg-emerald-500/10 text-emerald-700 dark:text-emerald-300",
            tone === "warning" && "bg-amber-500/10 text-amber-700 dark:text-amber-300",
            tone === "danger" && "bg-destructive/10 text-destructive",
          )}
          aria-hidden="true"
        >
          {label}
        </span>
        <span className="sr-only">({label})</span>
      </span>
    </div>
  );
}

export function DistributionBar({
  successes,
  failures,
  partials,
  observations,
}: {
  successes: number;
  failures: number;
  partials: number;
  observations: number;
}) {
  if (observations <= 0) return <span className="text-muted-foreground">—</span>;
  const s = Math.max(0, successes);
  const f = Math.max(0, failures);
  const p = Math.max(0, partials);
  const total = s + f + p;
  const denom = total > 0 ? total : observations;
  return (
    <div className="flex w-[96px] items-center gap-1" aria-hidden="true">
      <div className="flex h-1.5 flex-1 overflow-hidden rounded-full bg-muted">
        {s > 0 && <div className="bg-emerald-500" style={{ width: `${(s / denom) * 100}%` }} />}
        {p > 0 && <div className="bg-amber-500" style={{ width: `${(p / denom) * 100}%` }} />}
        {f > 0 && <div className="bg-destructive" style={{ width: `${(f / denom) * 100}%` }} />}
      </div>
    </div>
  );
}

export function ConfidenceTable({ items }: { items: MemoryConfidence[] }) {
  return (
    <div className="overflow-x-auto rounded-md border">
      <table className="w-full border-collapse text-xs">
        <caption className="sr-only">Skill outcome confidence</caption>
        <thead>
          <tr className="border-b bg-muted/30">
            <th scope="col" className="p-2 text-left font-semibold">Action</th>
            <th scope="col" className="p-2 text-left font-semibold">Obs</th>
            <th scope="col" className="p-2 text-left font-semibold">Success</th>
            <th scope="col" className="p-2 text-left font-semibold">Failure</th>
            <th scope="col" className="p-2 text-left font-semibold">Partial</th>
            <th scope="col" className="p-2 text-left font-semibold">Confidence</th>
            <th scope="col" className="p-2 text-left font-semibold">Distribution</th>
            <th scope="col" className="p-2 text-left font-semibold">Last seen</th>
          </tr>
        </thead>
        <tbody>
          {items.map((c) => (
            <tr key={c.action_type} className="border-b last:border-0 even:bg-muted/20 hover:bg-muted/30">
              <td className="max-w-[260px] truncate p-2 font-mono" title={c.action_type}>
                {c.action_type}
              </td>
              <td className="p-2 font-mono tabular-nums">{c.observations}</td>
              <td className="p-2 font-mono tabular-nums text-emerald-600 dark:text-emerald-300">{c.successes}</td>
              <td className="p-2 font-mono tabular-nums text-destructive">{c.failures}</td>
              <td className="p-2 font-mono tabular-nums text-amber-600 dark:text-amber-300">{c.partials}</td>
              <td className="p-2">
                <ConfidenceMeter value={c.confidence} />
              </td>
              <td className="p-2">
                <Tooltip>
                  <TooltipTrigger asChild>
                    <span className="inline-flex">
                      <DistributionBar
                        successes={c.successes}
                        failures={c.failures}
                        partials={c.partials}
                        observations={c.observations}
                      />
                    </span>
                  </TooltipTrigger>
                  <TooltipContent className="border border-border bg-popover text-popover-foreground shadow-lg">
                    <span className="font-mono text-xs">
                      {c.successes} success · {c.partials} partial · {c.failures} fail
                    </span>
                  </TooltipContent>
                </Tooltip>
              </td>
              <td className="whitespace-nowrap p-2 text-muted-foreground" title={c.last_seen}>
                {formatRelative(c.last_seen)}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
