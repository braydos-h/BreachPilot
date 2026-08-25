import { useState } from "react";
import { ChevronDown, ChevronRight } from "lucide-react";
import { cn, formatRelative } from "@/lib/utils";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import type { DecisionListRow } from "@/api/types";

interface DecisionHistoryCardProps {
  decisions: DecisionListRow[];
}

export function DecisionHistoryCard({ decisions }: DecisionHistoryCardProps) {
  const answered = decisions.filter((d) => d.status !== "pending");
  const [open, setOpen] = useState(answered.length <= 3);
  const [expandedId, setExpandedId] = useState<string | null>(null);
  return (
    <Card className="overflow-hidden">
      <CardHeader className="px-2.5 py-2 pb-1">
        <button type="button" onClick={() => setOpen((v) => !v)} className="flex w-full items-center gap-1.5 text-left" aria-expanded={open}>
          {open ? <ChevronDown className="h-3.5 w-3.5 text-muted-foreground" /> : <ChevronRight className="h-3.5 w-3.5 text-muted-foreground" />}
          <CardTitle className="text-xs">Decision history</CardTitle>
          {answered.length > 0 && <Badge variant="outline" className="ml-1 tabular-nums text-[9px] leading-none">{answered.length}</Badge>}
        </button>
      </CardHeader>
      {open && (
        <CardContent className="space-y-1.5 px-2.5 pb-2 pt-0 text-xs">
          {answered.length === 0 ? <p className="text-muted-foreground">No answered decisions yet.</p> : answered.map((d) => {
              const isExpanded = expandedId === d.id;
              const optionNames = normalizeOptionNames((d as unknown as Record<string, unknown>).options_json ?? d.options);
              return (
                <div key={d.id} className="rounded-md border bg-card/40 p-2">
                  <button type="button" onClick={() => setExpandedId(isExpanded ? null : d.id)} className="flex w-full items-center gap-2 text-left" aria-expanded={isExpanded}>
                    {isExpanded ? <ChevronDown className="h-3 w-3 shrink-0 text-muted-foreground" /> : <ChevronRight className="h-3 w-3 shrink-0 text-muted-foreground" />}
                    <Badge variant="outline" className={cn("text-[10px]", d.kind === "tool_approval" && "border-destructive/40 text-red-300", d.kind === "start_confirm" && "border-yellow-500/40 text-yellow-300")}>{d.kind}</Badge>
                    <span className="font-mono text-muted-foreground">{d.status}</span>
                    {d.answer && <span className="ml-auto truncate font-mono text-foreground">{d.answer}</span>}
                  </button>
                  {isExpanded && (
                    <div className="mt-2 space-y-1.5 pl-5">
                      {d.prompt_text && <div className="whitespace-pre-wrap break-words rounded bg-muted/30 p-1.5 font-mono text-[11px] text-muted-foreground">{d.prompt_text}</div>}
                      {optionNames.length > 0 && <div className="flex flex-wrap gap-1">{optionNames.map((name, i) => <Badge key={i} variant="outline" className="text-[9px] font-mono">{name}</Badge>)}</div>}
                      {d.required_text && <div className="text-[11px] text-red-300">required: <code className="font-mono">{d.required_text}</code></div>}
                      <div className="flex items-center gap-2 text-[10px] text-muted-foreground">{d.created_at && <span>created {formatRelative(d.created_at)}</span>}{d.answered_at && <span>answered {formatRelative(d.answered_at)}</span>}</div>
                    </div>
                  )}
                </div>
              );
            })}
        </CardContent>
      )}
    </Card>
  );
}

function normalizeOptionNames(options: unknown): string[] {
  if (!Array.isArray(options)) return [];
  return options.filter((o): o is Record<string, unknown> => !!o && typeof o === "object").map((o) => String(o.name ?? o.action ?? o.label ?? "")).filter((s) => s.length > 0);
}
