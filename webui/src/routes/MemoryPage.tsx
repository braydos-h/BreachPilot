import { useMemo, useState } from "react";
import { Brain, RefreshCw } from "lucide-react";
import { cn, formatRelative } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { SkeletonRows } from "@/components/Loading";
import { useMemory } from "@/api/hooks";

export function MemoryPage() {
  const memory = useMemory();
  const confidence = memory.data?.confidence ?? [];
  const lessons = memory.data?.lessons ?? [];
  const attackMemory = memory.data?.attack_memory ?? [];

  const [targetFilter, setTargetFilter] = useState("");
  const [categoryFilter, setCategoryFilter] = useState("");

  const targetOptions = useMemo(
    () => [...new Set(attackMemory.map((m) => m.target_ip).filter(Boolean))].sort(),
    [attackMemory],
  );
  const categoryOptions = useMemo(
    () => [...new Set(attackMemory.map((m) => m.category).filter(Boolean))].sort(),
    [attackMemory],
  );

  const filteredAttackMemory = useMemo(() => {
    return attackMemory.filter((m) => {
      if (targetFilter && m.target_ip !== targetFilter) return false;
      if (categoryFilter && m.category !== categoryFilter) return false;
      return true;
    });
  }, [attackMemory, targetFilter, categoryFilter]);

  return (
    <div className="space-y-4 p-4 md:p-6">
      <div className="flex items-center gap-2">
        <Brain className="h-5 w-5 text-primary" />
        <h1 className="text-lg font-semibold">Memory &amp; Experience Store</h1>
        <Button size="sm" variant="ghost" onClick={() => memory.refetch()} disabled={memory.isFetching} className="ml-auto">
          <RefreshCw className={cn("h-3.5 w-3.5", memory.isFetching && "animate-spin")} />
        </Button>
      </div>
      <p className="text-sm text-muted-foreground">
        Cross-mission learnings, skill-outcome confidence, and attack memory. Accumulates across runs.
      </p>

      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm">Skill outcome confidence</CardTitle>
          </div>
        </CardHeader>
        <CardContent>
          {memory.isLoading && <SkeletonRows count={3} className="p-2" />}
          {memory.error && <div className="text-sm text-destructive">Failed to load memory.</div>}
          {confidence.length === 0 && (
            <p className="text-sm text-muted-foreground">No cross-mission outcome data recorded yet.</p>
          )}
          {confidence.length > 0 && (
            <div className="overflow-x-auto rounded-md border">
              <table className="w-full border-collapse text-xs">
                <thead>
                  <tr>
                    {["action", "obs", "success", "failure", "partial", "confidence", "last seen"].map((h) => (
                      <th key={h} className="border-b p-2 text-left font-semibold">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {confidence.map((c) => (
                    <tr key={c.action_type} className="even:bg-muted/20">
                      <td className="max-w-[260px] truncate border-b p-2 font-mono" title={c.action_type}>{c.action_type}</td>
                      <td className="border-b p-2 font-mono">{c.observations}</td>
                      <td className="border-b p-2 font-mono text-emerald-400">{c.successes}</td>
                      <td className="border-b p-2 font-mono text-destructive">{c.failures}</td>
                      <td className="border-b p-2 font-mono">{c.partials}</td>
                      <td className="border-b p-2 font-mono">{(c.confidence * 100).toFixed(0)}%</td>
                      <td className="border-b p-2">{formatRelative(c.last_seen)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader><CardTitle className="text-sm">Cross-mission learnings</CardTitle></CardHeader>
        <CardContent>
          {lessons.length === 0 && <p className="text-sm text-muted-foreground">No recorded lessons.</p>}
          {lessons.length > 0 && (
            <ul className="space-y-1.5 text-xs">
              {lessons.map((l) => (
                <li key={l.id} className="rounded-md border p-2">
                  <div className="flex flex-wrap items-center gap-2">
                    <Badge variant={l.outcome === "success" ? "success" : l.outcome === "failure" ? "danger" : "outline"} className="text-[10px]">
                      {l.outcome}
                    </Badge>
                    <span className="font-mono text-muted-foreground">{l.action_type}</span>
                    <span className="ml-auto text-muted-foreground">{formatRelative(l.created_at)}</span>
                  </div>
                  {l.target_signature && (
                    <div className="mt-1 font-mono text-muted-foreground">{l.target_signature}</div>
                  )}
                </li>
              ))}
            </ul>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <div className="flex flex-wrap items-center justify-between gap-2">
            <CardTitle className="text-sm">Attack memory</CardTitle>
            {attackMemory.length > 0 && (
              <div className="flex flex-wrap items-center gap-2">
                <select
                  value={targetFilter}
                  onChange={(e) => setTargetFilter(e.target.value)}
                  className="h-8 rounded-md border border-input bg-background px-2 text-xs"
                  aria-label="Filter by target"
                >
                  <option value="">All targets</option>
                  {targetOptions.map((t) => <option key={t} value={t}>{t}</option>)}
                </select>
                <select
                  value={categoryFilter}
                  onChange={(e) => setCategoryFilter(e.target.value)}
                  className="h-8 rounded-md border border-input bg-background px-2 text-xs"
                  aria-label="Filter by category"
                >
                  <option value="">All categories</option>
                  {categoryOptions.map((c) => <option key={c} value={c}>{c}</option>)}
                </select>
              </div>
            )}
          </div>
        </CardHeader>
        <CardContent>
          {attackMemory.length === 0 && <p className="text-sm text-muted-foreground">No attack-memory items captured.</p>}
          {attackMemory.length > 0 && (
            <>
              {filteredAttackMemory.length === 0 && (
                <p className="text-sm text-muted-foreground">No items match the current filters.</p>
              )}
              <ul className="space-y-1.5 text-xs">
                {filteredAttackMemory.map((m) => (
                  <li key={m.id} className="rounded-md border p-2">
                    <div className="flex flex-wrap items-center gap-2">
                      <Badge variant="outline" className="text-[10px]">{m.category}</Badge>
                      <span className="font-mono text-muted-foreground">{m.target_ip}</span>
                      {m.source_tool && <span className="font-mono text-muted-foreground">· {m.source_tool}</span>}
                      {m.success ? (
                        <Badge variant="success" className="text-[10px]">ok</Badge>
                      ) : (
                        <Badge variant="danger" className="text-[10px]">fail</Badge>
                      )}
                      <span className="ml-auto text-muted-foreground">{formatRelative(m.last_seen_at)}</span>
                    </div>
                    <div className="mt-1 font-mono">
                      {m.item_key && <span className="text-muted-foreground">{m.item_key}: </span>}
                      <span className="break-words">{m.item_value}</span>
                      {m.seen_count > 1 && <span className="text-muted-foreground"> ×{m.seen_count}</span>}
                    </div>
                  </li>
                ))}
              </ul>
            </>
          )}
        </CardContent>
      </Card>
    </div>
  );
}