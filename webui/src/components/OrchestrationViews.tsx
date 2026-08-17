import { Activity, CheckCircle2, XCircle, Users, ListTree, ShieldCheck } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Label } from "@/components/ui/label";
import { Skeleton } from "@/components/Loading";
import { ApiError } from "@/api/client";
import { asRecord, asArray, str, num, bool, json, type Json } from "@/lib/stateShape";

function EmptyState({ msg }: { msg: string }) {
  return <div className="rounded-md border border-dashed p-4 text-sm text-muted-foreground">{msg}</div>;
}

function NotFound({ error }: { error: unknown }) {
  const msg =
    error instanceof ApiError
      ? error.isNotFound
        ? "State unavailable for this run."
        : error.message
      : "Failed to load state.";
  return <EmptyState msg={msg} />;
}

// ── Swarm ────────────────────────────────────────────────────────────────────

interface SwarmViewProps {
  loading: boolean;
  error: unknown;
  state: unknown;
}

export function SwarmView({ loading, error, state }: SwarmViewProps) {
  if (loading) return <Skeleton className="h-40 rounded-md" />;
  if (error) return <NotFound error={error} />;

  const s = asRecord(state);
  const agents = asArray(s.agents);
  const blackboard = asRecord(s.blackboard);
  const battleLog = asArray(s.battle_log_tail);
  const resultsCount = num(s.results_count);
  const strategyShift = str(s.strategy_shift);

  // Namespaced blackboard: { __global__: {...}, "<target>": {...} }.
  const namespaces = Object.entries(blackboard).filter(([k]) => k !== "__global__");
  const global = asRecord(blackboard.__global__);

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <Badge variant="info" className="tabular-nums">
          <Activity className="h-3 w-3" /> {resultsCount} results
        </Badge>
        {strategyShift && <Badge variant="warn">{strategyShift}</Badge>}
      </div>

      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="flex items-center gap-2 text-sm">
            <Users className="h-4 w-4" /> Agents
          </CardTitle>
        </CardHeader>
        <CardContent>
          {agents.length === 0 ? (
            <p className="text-xs text-muted-foreground">No agents dispatched yet.</p>
          ) : (
            <div className="overflow-x-auto rounded-md border">
              <table className="w-full border-collapse text-xs">
                <thead>
                  <tr className="border-b bg-muted/40 text-left">
                    <th className="px-2 py-1.5 font-medium">Agent</th>
                    <th className="px-2 py-1.5 font-medium">Type</th>
                    <th className="px-2 py-1.5 font-medium">Status</th>
                    <th className="px-2 py-1.5 font-medium">Task</th>
                  </tr>
                </thead>
                <tbody>
                  {agents.map((a, i) => {
                    const rec = asRecord(a);
                    const status = str(rec.status);
                    return (
                      <tr key={i} className="border-b last:border-0">
                        <td className="px-2 py-1.5 font-mono">{str(rec.agent_id)}</td>
                        <td className="px-2 py-1.5">{str(rec.agent_type)}</td>
                        <td className="px-2 py-1.5">
                          <Badge variant={status === "completed" ? "success" : status === "failed" ? "danger" : "muted"} className="text-[10px]">
                            {status || "idle"}
                          </Badge>
                        </td>
                        <td className="px-2 py-1.5 font-mono text-muted-foreground">{str(rec.task_id) || "—"}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="flex items-center gap-2 text-sm">
            <ListTree className="h-4 w-4" /> Blackboard
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          {Object.keys(global).length > 0 && (
            <BlackboardSection title="global" data={global} />
          )}
          {namespaces.map(([ns, data]) => (
            <BlackboardSection key={ns} title={ns} data={asRecord(data)} />
          ))}
          {Object.keys(global).length === 0 && namespaces.length === 0 && (
            <p className="text-xs text-muted-foreground">Blackboard is empty.</p>
          )}
        </CardContent>
      </Card>

      {battleLog.length > 0 && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm">Battle log (last {battleLog.length})</CardTitle>
          </CardHeader>
          <CardContent className="space-y-1.5">
            {battleLog.map((entry, i) => {
              const rec = asRecord(entry);
              return (
                <div key={i} className="flex items-start gap-2 text-xs">
                  <span className="mt-0.5 shrink-0">
                    {str(rec.outcome) === "success" ? (
                      <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" />
                    ) : (
                      <XCircle className="h-3.5 w-3.5 text-red-400" />
                    )}
                  </span>
                  <span className="font-mono text-muted-foreground">{str(rec.agent_type)}</span>
                  <span className="text-foreground">{str(rec.summary ?? rec.output ?? rec.action)}</span>
                </div>
              );
            })}
          </CardContent>
        </Card>
      )}
    </div>
  );
}

function BlackboardSection({ title, data }: { title: string; data: Json }) {
  const entries = Object.entries(data);
  if (entries.length === 0) return null;
  return (
    <div className="rounded-md border">
      <div className="border-b bg-muted/40 px-2 py-1 font-mono text-xs text-muted-foreground">{title}</div>
      <div className="divide-y">
        {entries.map(([k, v]) => (
          <div key={k} className="grid grid-cols-[minmax(0,10rem)_minmax(0,1fr)] gap-2 px-2 py-1 text-xs">
            <span className="truncate font-mono text-muted-foreground">{k}</span>
            <span className="break-words font-mono text-foreground">
              {v && typeof v === "object" ? json(v) : str(v)}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

// ── Campaign ─────────────────────────────────────────────────────────────────

interface CampaignViewProps {
  loading: boolean;
  error: unknown;
  state: unknown;
}

export function CampaignView({ loading, error, state }: CampaignViewProps) {
  if (loading) return <Skeleton className="h-40 rounded-md" />;
  if (error) return <NotFound error={error} />;

  const s = asRecord(state);
  const states = asRecord(s.states);
  const tasks = asRecord(s.tasks);
  const savedAt = str(s.saved_at);

  const targets = Object.entries(states);
  const taskEntries = Object.entries(tasks);

  return (
    <div className="space-y-3">
      {savedAt && <p className="text-xs text-muted-foreground">Last saved: {savedAt}</p>}

      {targets.length === 0 ? (
        <EmptyState msg="No campaign state yet. The autonomous orchestrator writes state as it progresses." />
      ) : (
        targets.map(([target, raw]) => {
          const st = asRecord(raw);
          const exploits = asArray(st.successful_exploits);
          const failed = asRecord(st.failed_attempts);
          const creds = asArray(st.credentials_found);
          const loot = asArray(st.loot);
          const pivots = asArray(st.pivot_targets);
          const access = bool(st.access_achieved);
          return (
            <Card key={target}>
              <CardHeader className="pb-2">
                <CardTitle className="flex flex-wrap items-center gap-2 text-sm">
                  <span className="font-mono">{target}</span>
                  <Badge variant="info" className="text-[10px]">{str(st.current_phase)}</Badge>
                  <Badge variant={access ? "success" : "muted"} className="text-[10px]">
                    <ShieldCheck className="h-3 w-3" /> {str(st.privilege_level)}
                  </Badge>
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-2 text-xs">
                {exploits.length > 0 && (
                  <div>
                    <Label className="text-[10px] text-muted-foreground">Successful exploits</Label>
                    <div className="mt-1 flex flex-wrap gap-1">
                      {exploits.map((e, i) => (
                        <Badge key={i} variant="success" className="font-mono text-[10px]">{str(e)}</Badge>
                      ))}
                    </div>
                  </div>
                )}
                {Object.keys(failed).length > 0 && (
                  <div>
                    <Label className="text-[10px] text-muted-foreground">Failed attempts</Label>
                    <div className="mt-1 flex flex-wrap gap-1">
                      {Object.entries(failed).map(([mod, errs]) => (
                        <Badge key={mod} variant="danger" className="font-mono text-[10px]" title={json(errs)}>
                          {mod} ({asArray(errs).length})
                        </Badge>
                      ))}
                    </div>
                  </div>
                )}
                {creds.length > 0 && (
                  <div>
                    <Label className="text-[10px] text-muted-foreground">Credentials found</Label>
                    <div className="mt-1 flex flex-wrap gap-1">
                      {creds.map((c, i) => {
                        const rec = asRecord(c);
                        return (
                          <Badge key={i} variant="warn" className="font-mono text-[10px]">
                            {str(rec.username)}:{str(rec.password)}
                          </Badge>
                        );
                      })}
                    </div>
                  </div>
                )}
                {loot.length > 0 && (
                  <div>
                    <Label className="text-[10px] text-muted-foreground">Loot</Label>
                    <div className="mt-1 flex flex-wrap gap-1">
                      {loot.map((l, i) => (
                        <Badge key={i} variant="outline" className="font-mono text-[10px]">{str(l)}</Badge>
                      ))}
                    </div>
                  </div>
                )}
                {pivots.length > 0 && (
                  <div>
                    <Label className="text-[10px] text-muted-foreground">Pivot targets</Label>
                    <div className="mt-1 flex flex-wrap gap-1">
                      {pivots.map((p, i) => (
                        <Badge key={i} variant="outline" className="font-mono text-[10px]">{str(p)}</Badge>
                      ))}
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>
          );
        })
      )}

      {taskEntries.length > 0 && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm">Tasks ({taskEntries.length})</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="overflow-x-auto rounded-md border">
              <table className="w-full border-collapse text-xs">
                <thead>
                  <tr className="border-b bg-muted/40 text-left">
                    <th className="px-2 py-1.5 font-medium">ID</th>
                    <th className="px-2 py-1.5 font-medium">Status</th>
                    <th className="px-2 py-1.5 font-medium">Priority</th>
                    <th className="px-2 py-1.5 font-medium">Module</th>
                    <th className="px-2 py-1.5 font-medium">Target</th>
                  </tr>
                </thead>
                <tbody>
                  {taskEntries.map(([tid, raw]) => {
                    const t = asRecord(raw);
                    const status = str(t.status);
                    return (
                      <tr key={tid} className="border-b last:border-0">
                        <td className="px-2 py-1.5 font-mono">{tid}</td>
                        <td className="px-2 py-1.5">
                          <Badge variant={status === "completed" ? "success" : status === "failed" ? "danger" : status === "running" ? "info" : "muted"} className="text-[10px]">
                            {status}
                          </Badge>
                        </td>
                        <td className="px-2 py-1.5 tabular-nums">{num(t.priority)}</td>
                        <td className="px-2 py-1.5 font-mono text-muted-foreground">{str(t.module_name)}</td>
                        <td className="px-2 py-1.5 font-mono text-muted-foreground">{str(t.target)}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
