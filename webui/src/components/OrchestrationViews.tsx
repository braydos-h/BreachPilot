import { useState } from "react";
import { Activity, AlertTriangle, CheckCircle2, Clock, XCircle, Users, ListTree, ShieldCheck, TrendingUp } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Label } from "@/components/ui/label";
import { Skeleton } from "@/components/Loading";
import { ApiError } from "@/api/client";
import { asRecord, asArray, str, num, bool, json, type Json } from "@/lib/stateShape";
import {
  CAMPAIGN_PHASES,
  CAMPAIGN_PHASE_LABELS,
  aggressionVariant,
  phaseIndex,
  type CampaignTimelineEntry,
} from "@/lib/campaignPhases";

function EmptyState({ msg }: { msg: string }) {
  return <div className="rounded-md border border-dashed p-4 text-sm text-muted-foreground">{msg}</div>;
}

/** Reflection headline badge colour, keyed off the recommended_strategy_shift
 *  prefix the reflection agent emits (MAJOR PIVOT/PIVOT/ACCELERATE/PROCEED/…). */
function reflectionShiftVariant(shift: string): "danger" | "success" | "warn" | "muted" {
  const s = shift.toUpperCase();
  if (s.includes("PIVOT")) return "danger";
  if (s.startsWith("ACCELERATE")) return "success";
  return s ? "warn" : "muted";
}

/** Bullet list shared by the reflection card's three outcome columns. */
function ReflectionList({ label, items }: { label: string; items: unknown[] }) {
  if (items.length === 0) return null;
  return (
    <div>
      <Label className="text-[10px] text-muted-foreground">{label}</Label>
      <ul className="mt-1 list-inside list-disc space-y-0.5 text-foreground">
        {items.map((item, i) => (
          <li key={i} className="break-words">{str(item)}</li>
        ))}
      </ul>
    </div>
  );
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

interface WitnessFlagView {
  signal: string;
  severity: string;
  message: string;
  timestamp?: string;
}

interface SwarmViewProps {
  loading: boolean;
  error: unknown;
  state: unknown;
  /** Advisory witness flags from reports/witness.jsonl (witness feature). */
  witnessFlags?: WitnessFlagView[];
  witnessLoading?: boolean;
  /** swarm.negotiation_rounds config value (negotiation_rounds feature). */
  negotiationRounds?: number;
}

export function SwarmView({ loading, error, state, witnessFlags, witnessLoading, negotiationRounds }: SwarmViewProps) {
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

  const flags = witnessFlags ?? [];
  const criticalFlags = flags.filter((f) => f.severity === "critical" || f.severity === "high");

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <Badge variant="info" className="tabular-nums">
          <Activity className="h-3 w-3" /> {resultsCount} results
        </Badge>
        {strategyShift && <Badge variant="warn">{strategyShift}</Badge>}
        {negotiationRounds != null && negotiationRounds > 0 && (
          <Badge variant="outline" className="tabular-nums" title="swarm.negotiation_rounds">
            negotiation ×{negotiationRounds}
          </Badge>
        )}
        {criticalFlags.length > 0 && (
          <Badge variant="danger" className="tabular-nums">
            <AlertTriangle className="h-3 w-3" /> {criticalFlags.length} witness flag{criticalFlags.length === 1 ? "" : "s"}
          </Badge>
        )}
      </div>

      {flags.length > 0 && (
        <Card className="border-red-500/30">
          <CardHeader className="pb-2">
            <CardTitle className="flex items-center gap-2 text-sm">
              <AlertTriangle className="h-4 w-4 text-red-400" /> Witness flags ({flags.length})
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-1.5">
            {flags.map((f, i) => {
              const sev = f.severity || "low";
              const variant = sev === "critical" ? "danger" : sev === "high" ? "danger" : sev === "medium" ? "warn" : "muted";
              return (
                <div key={i} className="flex items-start gap-2 text-xs">
                  <Badge variant={variant as "danger" | "warn" | "muted"} className="shrink-0 text-[10px]">{sev}</Badge>
                  <span className="font-mono text-muted-foreground">{f.signal}</span>
                  <span className="break-words text-foreground">{f.message}</span>
                </div>
              );
            })}
          </CardContent>
        </Card>
      )}
      {witnessLoading && flags.length === 0 && (
        <p className="text-xs text-muted-foreground">Loading witness flags…</p>
      )}

      {Object.keys(asRecord(s.last_reflection)).length > 0 && (
        <ReflectionCard reflection={asRecord(s.last_reflection)} />
      )}

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
                <caption className="sr-only">Swarm agents</caption>
                <thead>
                  <tr className="border-b bg-muted/40 text-left">
                    <th scope="col" className="px-2 py-1.5 font-medium">Agent</th>
                    <th scope="col" className="px-2 py-1.5 font-medium">Type</th>
                    <th scope="col" className="px-2 py-1.5 font-medium">Status</th>
                    <th scope="col" className="px-2 py-1.5 font-medium">Task</th>
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
            <p className="text-[10px] text-muted-foreground">
              The server persists the most recent 200 entries per swarm run.
            </p>
          </CardHeader>
          <CardContent className="max-h-72 space-y-1.5 overflow-y-auto">
            {battleLog.map((entry, i) => {
              const rec = asRecord(entry);
              // Backend entries are {task_id, tool, target, success: bool,
              // summary, error, ...} — `success`/`tool`, not the legacy
              // outcome/agent_type keys this card once assumed.
              const success = "success" in rec ? bool(rec.success) : str(rec.outcome) === "success";
              return (
                <div key={i} className="flex items-start gap-2 text-xs">
                  <span className="mt-0.5 shrink-0">
                    {success ? (
                      <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" />
                    ) : (
                      <XCircle className="h-3.5 w-3.5 text-red-400" />
                    )}
                  </span>
                  <span className="font-mono text-muted-foreground">{str(rec.tool)}</span>
                  <span className="text-foreground">{str(rec.summary ?? rec.error)}</span>
                </div>
              );
            })}
          </CardContent>
        </Card>
      )}
    </div>
  );
}

/** Last reflection_agent output from the blackboard (`state.last_reflection`).
 *  Renders only the known keys — never the raw object. */
function ReflectionCard({ reflection }: { reflection: Record<string, unknown> }) {
  const shift = str(reflection.recommended_strategy_shift);
  const confidence = num(reflection.confidence);
  const why = str(reflection.why);
  const hypothesis = str(reflection.new_hypothesis);
  const worked = asArray(reflection.what_worked);
  const failed = asArray(reflection.what_failed);
  const patterns = asArray(reflection.patterns_identified);

  if (!shift && !why && !hypothesis && worked.length === 0 && failed.length === 0 && patterns.length === 0) {
    return null;
  }

  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="flex items-center gap-2 text-sm">
          <TrendingUp className="h-4 w-4" /> Reflection
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-2.5 text-xs">
        <div className="flex flex-wrap items-center gap-2">
          {shift && (
            <Badge variant={reflectionShiftVariant(shift)} className="text-[10px]">
              {shift}
            </Badge>
          )}
          {confidence > 0 && (
            <span className="text-muted-foreground tabular-nums">
              confidence {Math.round(confidence * 100)}%
            </span>
          )}
        </div>
        {why && (
          <p className="break-words text-foreground">
            <span className="font-medium">Why: </span>
            {why}
          </p>
        )}
        {hypothesis && (
          <p className="break-words text-foreground">
            <span className="font-medium">New hypothesis: </span>
            {hypothesis}
          </p>
        )}
        <div className="grid gap-3 sm:grid-cols-3">
          <ReflectionList label="What worked" items={worked} />
          <ReflectionList label="What failed" items={failed} />
          <ReflectionList label="Patterns identified" items={patterns} />
        </div>
      </CardContent>
    </Card>
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
  const [revealCreds, setRevealCreds] = useState(false);
  if (loading) return <Skeleton className="h-40 rounded-md" />;
  if (error) return <NotFound error={error} />;

  const s = asRecord(state);
  const states = asRecord(s.states);
  const tasks = asRecord(s.tasks);
  const savedAt = str(s.saved_at);

  const targets = Object.entries(states);
  const taskEntries = Object.entries(tasks);
  const credCount = targets.reduce(
    (n, [, raw]) => n + asArray(asRecord(raw).credentials_found).length,
    0,
  );

  return (
    <div className="space-y-3">
      {savedAt && <p className="text-xs text-muted-foreground">Last saved: {savedAt}</p>}
      {credCount > 0 && (
        <button
          type="button"
          onClick={() => setRevealCreds((v) => !v)}
          className="text-xs text-muted-foreground underline-offset-4 hover:underline"
          aria-pressed={revealCreds}
        >
          {revealCreds ? "Hide" : "Reveal"} credentials ({credCount})
        </button>
      )}

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
          const currentPhase = str(st.current_phase);
          const aggression = str(st.aggression);
          return (
            <Card key={target}>
              <CardHeader className="pb-2">
                <CardTitle className="flex flex-wrap items-center gap-2 text-sm">
                  <span className="font-mono">{target}</span>
                  <Badge variant="info" className="text-[10px]">{currentPhase}</Badge>
                  {aggression && (
                    <Badge variant={aggressionVariant(aggression)} className="text-[10px]">
                      {aggression}
                    </Badge>
                  )}
                  <Badge variant={access ? "success" : "muted"} className="text-[10px]">
                    <ShieldCheck className="h-3 w-3" /> {str(st.privilege_level)}
                  </Badge>
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-2 text-xs">
                <KillChainStepper currentPhase={currentPhase} />
                <CampaignTimeline timeline={st.timeline} />
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
                            {str(rec.username)}:{revealCreds ? str(rec.password) : "\u2022\u2022\u2022\u2022"}
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
                <caption className="sr-only">Campaign tasks</caption>
                <thead>
                  <tr className="border-b bg-muted/40 text-left">
                    <th scope="col" className="px-2 py-1.5 font-medium">ID</th>
                    <th scope="col" className="px-2 py-1.5 font-medium">Status</th>
                    <th scope="col" className="px-2 py-1.5 font-medium">Priority</th>
                    <th scope="col" className="px-2 py-1.5 font-medium">Module</th>
                    <th scope="col" className="px-2 py-1.5 font-medium">Target</th>
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

/** 8-chip kill-chain stepper. `current_phase: "done"` (campaign finished) is
 *  not one of the 8 phases — every chip renders neutral plus the raw badge the
 *  header already shows, so a state file from a different version degrades. */
function KillChainStepper({ currentPhase }: { currentPhase: string }) {
  const current = phaseIndex(currentPhase);
  return (
    <div>
      <Label className="text-[10px] text-muted-foreground">Kill chain</Label>
      <ol className="mt-1 flex flex-wrap gap-1" aria-label="Campaign kill chain progress">
        {CAMPAIGN_PHASES.map((phase, i) => {
          const state =
            current < 0 ? "future" : i < current ? "done" : i === current ? "current" : "future";
          return (
            <li key={phase}>
              <Badge
                variant={state === "current" ? "info" : state === "done" ? "success" : "outline"}
                className="text-[10px]"
                aria-current={state === "current" ? "step" : undefined}
              >
                {CAMPAIGN_PHASE_LABELS[phase]}
              </Badge>
            </li>
          );
        })}
      </ol>
    </div>
  );
}

/** Per-target event timeline (`AttackState.timeline`), newest first.
 *  ISO-8601 timestamps sort lexically; entries without a timestamp sort last.
 *  Entries are untrusted JSON — every field goes through a stateShape
 *  accessor so a malformed row degrades instead of throwing. */
function CampaignTimeline({ timeline }: { timeline: unknown }) {
  const [showAll, setShowAll] = useState(false);
  const entries = asArray(timeline)
    .map((e, i) => ({ e, i }))
    .sort((a, b) => {
      const ta = str(asRecord(a.e).timestamp);
      const tb = str(asRecord(b.e).timestamp);
      if (ta === tb) return b.i - a.i;
      if (!ta) return 1;
      if (!tb) return -1;
      return tb > ta ? 1 : -1;
    })
    .map(({ e }) => asRecord(e) as unknown as CampaignTimelineEntry);

  if (entries.length === 0) return null;

  const visible = showAll ? entries : entries.slice(0, 100);
  return (
    <div>
      <Label className="text-[10px] text-muted-foreground">Timeline ({entries.length})</Label>
      <div className="mt-1 max-h-72 space-y-1 overflow-y-auto pr-1">
        {visible.map((entry, i) => {
          const et = str(entry.event_type).toLowerCase();
          const icon =
            et.includes("success") ? (
              <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" />
            ) : et.includes("fail") || et.includes("error") ? (
              <XCircle className="h-3.5 w-3.5 text-red-400" />
            ) : (
              <Clock className="h-3.5 w-3.5 text-muted-foreground" />
            );
          const moduleName = str(asRecord(entry.metadata).module);
          return (
            <div key={i} className="flex items-start gap-2 text-xs">
              <span className="mt-0.5 shrink-0 font-mono text-muted-foreground tabular-nums">
                {str(entry.timestamp).split("T")[1]?.slice(0, 8) || "—"}
              </span>
              <span className="mt-0.5 shrink-0">{icon}</span>
              <span className="shrink-0 font-mono text-muted-foreground">{str(entry.event_type)}</span>
              <span className="min-w-0 break-words text-foreground">{str(entry.description)}</span>
              {moduleName && (
                <Badge variant="outline" className="shrink-0 font-mono text-[10px]">
                  {moduleName}
                </Badge>
              )}
            </div>
          );
        })}
      </div>
      {entries.length > 100 && (
        <button
          type="button"
          onClick={() => setShowAll((v) => !v)}
          className="mt-1 text-xs text-muted-foreground underline-offset-4 hover:underline"
          aria-pressed={showAll}
        >
          {showAll ? "Show less" : `Show all ${entries.length} entries`}
        </button>
      )}
    </div>
  );
}
