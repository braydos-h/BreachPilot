import { useMemo } from "react";
import type { RunEvent } from "@/api/types";

/** Narrative activity feed (todo 18): grouped by phase/discovery, not raw JSON stream. */
export function NarrativeFeed({ events }: { events: RunEvent[] }) {
  const items = useMemo(() => {
    const out: string[] = [];
    let reconUpdates = 0;
    let tools = 0;
    for (const ev of events) {
      const t = ev.type;
      if (t === "progress" || t === "phase") {
        const p = ev.payload as Record<string, unknown>;
        const phase = String(p.phase ?? p.stage ?? "");
        if (phase) out.push(`Working: ${phase}`);
      } else if (t === "tool_start" || t === "tool_request" || t === "tool_result") {
        tools += 1;
        const p = ev.payload as Record<string, unknown>;
        const name = String(p.tool ?? p.name ?? "tool");
        if (tools <= 12) out.push(`Ran ${name}`);
      } else if (t === "state") {
        const p = ev.payload as Record<string, unknown>;
        out.push(`State: ${String(p.state ?? "")}`);
      } else if (t === "recon_assessment" || t === "fast_recon_progress" || t === "fast_recon_completed") {
        reconUpdates += 1;
      }
    }
    if (reconUpdates > 0) out.unshift(`${reconUpdates} recon update${reconUpdates === 1 ? "" : "s"} received`);
    return out.slice(-30);
  }, [events]);
  if (items.length === 0) return <p className="text-[13px] text-muted-foreground">BreachPilot is preparing — activity will appear here.</p>;
  return (
    <ol className="space-y-1.5 text-[13px] leading-relaxed" aria-live="polite">
      {items.map((line, i) => (
        <li key={i} className="flex gap-2">
          <span aria-hidden className="mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full bg-primary/60" />
          <span>{line}</span>
        </li>
      ))}
    </ol>
  );
}
