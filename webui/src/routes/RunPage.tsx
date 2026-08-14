import { useEffect, useMemo, useRef, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import {
  AlertTriangle,
  Loader2,
  Play,
  Square,
  Terminal,
  Wrench,
  ScanSearch,
  ClipboardList,
  Gauge,
  Network,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { StatusBadge } from "@/components/StatusBadge";
import { CopyButton } from "@/components/CopyButton";
import { EventList } from "@/components/EventList";
import { DecisionCard } from "@/components/DecisionCard";
import { ReconAssessmentCard } from "@/components/ReconAssessmentCard";
import { AttackGraph } from "@/components/AttackGraph";
import { LiveRunSummary } from "@/components/LiveRunSummary";
import { PhaseTracker } from "@/components/PhaseTracker";
import { SessionSummaryCard } from "@/components/SessionSummaryCard";
import { Skeleton, SkeletonCards, SkeletonRows, Spinner } from "@/components/Loading";
import { useRunEvents } from "@/api/ws";
import {
  useAnswerDecision,
  useAudit,
  useCallTool,
  useCancelRun,
  useDecisions,
  useArtifacts,
  useFetchArtifactBlob,
  useResumeRun,
  useRun,
  useRunTools,
  useSwarmState,
  useCampaignState,
} from "@/api/hooks";
import { ApiError } from "@/api/client";
import { isActiveState, isTerminalState, type RunState, type ReconAssessment, type RunResult, type RunResultTelemetry } from "@/api/types";
import { autoAnswerFor, usePermissionMode } from "@/lib/permissionMode";

export function RunPage() {
  const { runId } = useParams<{ runId: string }>();
  const navigate = useNavigate();
  const run = useRun(runId ?? null);
  const decisions = useDecisions(runId ?? null);
  const events = useRunEvents(runId ?? null);
  const cancel = useCancelRun();
  const resume = useResumeRun();
  const audit = useAudit(runId ?? null);
  const swarm = useSwarmState(runId ?? null);
  const campaign = useCampaignState(runId ?? null);
  const tools = useRunTools(runId ?? null, isActiveState(run.data?.state as RunState));
  const callTool = useCallTool(runId ?? "");
  const fetchArtifact = useFetchArtifactBlob(runId ?? "");
  const artifacts = useArtifacts(runId ?? null);

  // Gate per-artifact fetches on run state so we don't 404-loop while recon is
  // still in progress. An artifact is "ready to fetch" once the run is terminal
  // OR the artifact list already contains it (recon/attack finished writing it).
  const artifactNames = useMemo(
    () => new Set((artifacts.data?.artifacts ?? []).map((a) => a.name)),
    [artifacts.data],
  );
  const runIsActive = isActiveState(run.data?.state as RunState);
  const artifactReady = (name: string) => !runIsActive || artifactNames.has(name);

  const [showCancel, setShowCancel] = useState(false);
  const [selectedTool, setSelectedTool] = useState<string>("");
  const [toolArgs, setToolArgs] = useState<string>("{}");
  const [toolResult, setToolResult] = useState<string>("");

  const mergedDecisions = useMemo(() => {
    const rows = (decisions.data?.decisions ?? []).map((row) => ({ ...row }));
    const byId = new Map(rows.map((row) => [row.id, row]));
    for (const ev of events.events) {
      if (ev.type !== "approval") continue;
      const id = ev.payload.decision_id;
      if (typeof id !== "string") continue;
      const existing = byId.get(id);
      if (ev.payload.status === "answered") {
        if (existing) {
          existing.status = "answered";
          if (typeof ev.payload.answer === "string") existing.answer = ev.payload.answer;
        }
        continue;
      }
      if (existing) continue;
      const row = {
        id,
        kind: String(ev.payload.kind ?? "tool_approval"),
        status: "pending" as const,
        answer: "",
        prompt_text: String(ev.payload.prompt_text ?? ""),
        required_text: String(ev.payload.required_text ?? ""),
        options: Array.isArray(ev.payload.options) ? ev.payload.options : [],
      };
      byId.set(id, row);
      rows.unshift(row);
    }
    return rows;
  }, [decisions.data, events.events]);

  const pendingDecisions = mergedDecisions.filter((d) => d.status === "pending");
  const currentState =
    (events.events.findLast((e) => e.type === "state")?.payload?.state as RunState | undefined) ??
    run.data?.state;
  const active = isActiveState(currentState as RunState);
  const terminal = isTerminalState(currentState as RunState);

  // Permission-mode auto-answer loop. For each pending decision the armed
  // mode covers, submit the resolved answer via useAnswerDecision. Tracked in
  // a ref set so a slow mutate + re-render doesn't double-submit.
  const { mode } = usePermissionMode();
  const answerDecision = useAnswerDecision(runId ?? "");
  const inFlight = useRef<Set<string>>(new Set());
  useEffect(() => {
    if (mode === "read_only") return;
    for (const d of pendingDecisions) {
      if (inFlight.current.has(d.id)) continue;
      const ans = autoAnswerFor(d, mode);
      if (ans === null) continue;
      inFlight.current.add(d.id);
      answerDecision.mutate(
        { decisionId: d.id, answer: ans },
        {
          onError: () => {
            inFlight.current.delete(d.id);
          },
        },
      );
    }
  }, [mode, pendingDecisions, answerDecision]);

  const liveTelemetry = useMemo<RunResultTelemetry | null>(() => {
    for (let i = events.events.length - 1; i >= 0; i--) {
      const ev = events.events[i];
      if (ev.type !== "progress") continue;
      const tel = ev.payload.telemetry as RunResultTelemetry | undefined;
      if (tel && typeof tel === "object") return tel;
    }
    const finalTel = (run.data?.result ?? {}).telemetry as RunResultTelemetry | undefined;
    return finalTel && typeof finalTel === "object" ? finalTel : null;
  }, [events.events, run.data?.result]);

  if (run.isLoading) {
    return (
      <div className="space-y-4 p-4 md:p-6" role="status" aria-live="polite">
        <div className="flex items-center gap-2">
          <Skeleton className="h-4 w-40" />
          <Skeleton className="h-5 w-16 rounded-full" />
        </div>
        <div className="flex flex-wrap gap-x-3 gap-y-1">
          <Skeleton className="h-3 w-32" />
          <Skeleton className="h-3 w-24" />
          <Skeleton className="h-3 w-28" />
        </div>
        <div className="grid flex-1 gap-4 lg:grid-cols-[minmax(0,1fr)_320px]">
          <Skeleton className="h-[40vh] rounded-md" />
          <SkeletonCards count={2} />
        </div>
      </div>
    );
  }
  if (run.error || !run.data) {
    const notFound = run.error instanceof ApiError && run.error.isNotFound;
    return (
      <div className="flex flex-col items-start gap-3 p-6 text-sm">
        <div className="text-destructive">{notFound ? "Run not found." : "Failed to load run."}</div>
        <div className="flex gap-2">
          <Button asChild variant="outline" size="sm">
            <Link to="/runs">Back to runs</Link>
          </Button>
          <Button size="sm" onClick={() => run.refetch()}>Retry</Button>
        </div>
      </div>
    );
  }

  const preview = run.data.preview ?? {};
  const request = run.data.request ?? {};
  const transportLabel = events.transport === "sse" ? "SSE" : events.transport === "websocket" ? "WS" : "\u2014";

  return (
    <div className="flex flex-col gap-4 p-4 md:p-6">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <h1 className="font-mono text-sm">
            <span className="text-gradient-primary">{run.data.id}</span>
          </h1>
            <CopyButton value={run.data.id} size="icon" label="Copy ID" />
            {currentState && <StatusBadge state={currentState as RunState} />}
            <Badge variant="outline" className="text-xs">
              {transportLabel}
              {active && (events.status === "connecting" || events.status === "closed") && (
                <span className="ml-1 inline-flex items-center gap-1 text-[10px] text-muted-foreground">
                  <Loader2 className="h-2.5 w-2.5 animate-spin" /> reconnecting
                </span>
              )}
            </Badge>
          </div>
          <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-muted-foreground">
            <span><span className="text-muted-foreground/70">target:</span> <span className="font-mono text-foreground">{String(preview.target_ip ?? request.target ?? "\u2014")}</span></span>
            <span><span className="text-muted-foreground/70">mode:</span> <span className="text-foreground">{String(request.mode ?? preview.mode ?? "\u2014")}</span></span>
            <span><span className="text-muted-foreground/70">goal:</span> <span className="text-foreground">{String(preview.goal_name ?? request.goal_name ?? "\u2014")}</span></span>
            <span><span className="text-muted-foreground/70">model:</span> <span className="font-mono text-foreground">{String(preview.model_alias ?? request.model_alias ?? "\u2014")}</span></span>
            <span><span className="text-muted-foreground/70">permission:</span> <span className="text-foreground">{String(preview.permission ?? "\u2014")}</span></span>
          </div>
          {liveTelemetry && (
            <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-muted-foreground">
              <span className="inline-flex items-center gap-1">
                <Gauge className="h-3 w-3" />
                <span className="text-muted-foreground/70">tokens:</span>{" "}
                <span className="font-mono tabular-nums text-foreground">{Number(liveTelemetry.total_tokens ?? 0).toLocaleString()}</span>
              </span>
              {liveTelemetry.calls != null && (
                <span>
                  <span className="text-muted-foreground/70">calls:</span>{" "}
                  <span className="font-mono tabular-nums text-foreground">{Number(liveTelemetry.calls)}</span>
                </span>
              )}
              {liveTelemetry.context_window_tokens != null && (
                <span>
                  <span className="text-muted-foreground/70">ctx window:</span>{" "}
                  <span className="font-mono tabular-nums text-foreground">{Number(liveTelemetry.context_window_tokens).toLocaleString()}</span>
                </span>
              )}
              {liveTelemetry.last_ctx_pct != null && (
                <span>
                  <span className="text-muted-foreground/70">ctx used:</span>{" "}
                  <span className="font-mono tabular-nums text-foreground">{Number(liveTelemetry.last_ctx_pct).toFixed(1)}%</span>
                </span>
              )}
              {liveTelemetry.last_estimated_context_tokens != null && liveTelemetry.context_window_tokens != null && (
                <span className="hidden sm:inline">
                  <span className="text-muted-foreground/70">remaining:</span>{" "}
                  <span className="font-mono tabular-nums text-foreground">
                    {Math.max(0, Number(liveTelemetry.context_window_tokens) - Number(liveTelemetry.last_estimated_context_tokens)).toLocaleString()}
                  </span>
                </span>
              )}
            </div>
          )}
        </div>
        <div className="flex flex-col items-end gap-2">
          <PhaseTracker events={events.events} runState={currentState as RunState} className="w-full max-w-sm" />
          <div className="flex items-center gap-2">
            {active && (
              <Button variant="destructive" size="sm" onClick={() => setShowCancel(true)} disabled={cancel.isPending}>
                {cancel.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Square className="h-4 w-4" />}
                Cancel
              </Button>
            )}
            {terminal && (
              <Button size="sm" onClick={() => resume.mutate(run.data.id, { onSuccess: (data) => navigate(`/runs/${data.run_id}`) })} disabled={resume.isPending}>
                {resume.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />}
                Resume
              </Button>
            )}
            <Button asChild size="sm" variant="outline">
              <Link to={`/runs/${run.data.id}/artifacts`}>Artifacts</Link>
            </Button>
            <Button asChild size="sm" variant="outline">
              <Link to={`/runs/${run.data.id}/loot`}>Loot</Link>
            </Button>
          </div>
        </div>
      </div>

      {events.authError && (
        <div className="flex items-start gap-2 rounded-md border border-destructive/40 bg-destructive/10 p-3 text-sm text-red-200">
          <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
          {events.authError}
        </div>
      )}

      <div className="grid flex-1 gap-4 lg:grid-cols-[minmax(0,1fr)_320px]">
        <div className="flex-1">
          <EventList events={events.events} decisions={mergedDecisions} runId={run.data.id} terminal={terminal} className="h-[70vh]" />
        </div>
        <div className="space-y-3">
          <LiveRunSummary events={events.events} />

          <Card className={cn(pendingDecisions.length > 0 && "border-primary/40 glow-primary")}>
            <CardHeader className="pb-2">
              <CardTitle className="flex items-center gap-2 text-sm">
                Pending decisions
                {pendingDecisions.length > 0 && (
                  <Badge variant="info" className="tabular-nums">{pendingDecisions.length}</Badge>
                )}
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-2">
              {pendingDecisions.length === 0 ? (
                <p className="text-xs text-muted-foreground">No pending input.</p>
              ) : (
                pendingDecisions.map((d) => (
                  <DecisionCard key={d.id} decision={d} runId={run.data.id} autoAnswering={inFlight.current.has(d.id) && mode !== "read_only"} />
                ))
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm">Decisions</CardTitle>
            </CardHeader>
            <CardContent className="space-y-1 text-xs">
              {mergedDecisions.length === 0 ? (
                <p className="text-muted-foreground">None.</p>
              ) : (
                mergedDecisions.map((d) => (
                  <div key={d.id} className="flex items-center gap-2">
                    <Badge variant="outline" className="text-[10px]">{d.kind}</Badge>
                    <span className={cn("font-mono", d.status === "pending" && "text-yellow-300")}>{d.status}</span>
                    {d.answer && <span className="ml-auto truncate text-muted-foreground">{d.answer}</span>}
                  </div>
                ))
              )}
            </CardContent>
          </Card>
        </div>
      </div>

      <Tabs defaultValue="recon" className="mt-2">
        <TabsList>
          <TabsTrigger value="recon"><ScanSearch className="mr-1.5 h-3.5 w-3.5" />Recon</TabsTrigger>
          <TabsTrigger value="graph"><Network className="mr-1.5 h-3.5 w-3.5" />Attack Path</TabsTrigger>
          <TabsTrigger value="summary"><ClipboardList className="mr-1.5 h-3.5 w-3.5" />Summary</TabsTrigger>
          <TabsTrigger value="tools"><Wrench className="mr-1.5 h-3.5 w-3.5" />Tools</TabsTrigger>
          <TabsTrigger value="audit">Audit</TabsTrigger>
          <TabsTrigger value="swarm">Swarm</TabsTrigger>
          <TabsTrigger value="campaign">Campaign</TabsTrigger>
        </TabsList>
        <TabsContent value="recon" className="space-y-3">
          <ReconTab
            runId={run.data.id}
            fetchArtifact={fetchArtifact}
            ready={artifactReady("recon_assessment.json")}
          />
        </TabsContent>
        <TabsContent value="graph" className="space-y-3">
          <AttackGraph runId={run.data.id} ready={artifactReady("enhanced/enhanced_report.json")} />
        </TabsContent>
        <TabsContent value="summary" className="space-y-3">
          <SessionSummaryCard result={(run.data.result ?? {}) as RunResult} title={run.data.title} />
        </TabsContent>
        <TabsContent value="tools" className="space-y-3">
          <ManualToolPanel
            runId={run.data.id}
            tools={tools.data?.tools ?? []}
            isLoading={tools.isLoading}
            selectedTool={selectedTool}
            onSelect={setSelectedTool}
            args={toolArgs}
            onArgs={setToolArgs}
            result={toolResult}
            onResult={setToolResult}
            onCall={(name, parsedArgs) =>
              callTool.mutate(
                { tool: name, arguments: parsedArgs },
                {
                  onSuccess: (data) => setToolResult(data.result || "(no output)"),
                  onError: (err) => setToolResult(err instanceof ApiError ? err.message : "Tool call failed."),
                },
              )
            }
            calling={callTool.isPending}
          />
        </TabsContent>
        <TabsContent value="audit" className="space-y-3">
          <AuditView
            loading={audit.isLoading}
            error={audit.error}
            records={audit.data?.records ?? []}
            chainValid={audit.data?.chain_valid ?? false}
            chainReason={audit.data?.chain_reason ?? ""}
          />
        </TabsContent>
        <TabsContent value="swarm">
          <StateView label="swarm_state.json" loading={swarm.isLoading} error={swarm.error} data={swarm.data?.state} />
        </TabsContent>
        <TabsContent value="campaign">
          <StateView label="attack_states.json" loading={campaign.isLoading} error={campaign.error} data={campaign.data?.state} />
        </TabsContent>
      </Tabs>

      <Dialog open={showCancel} onOpenChange={setShowCancel}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Cancel this run?</DialogTitle>
            <DialogDescription>
              Cancellation is cooperative. The agent stops at the next boundary and tears down MCP/swarm children.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowCancel(false)}>Keep running</Button>
            <Button
              variant="destructive"
              onClick={() => {
                cancel.mutate(run.data.id, { onSettled: () => setShowCancel(false) });
              }}
              disabled={cancel.isPending}
            >
              {cancel.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Square className="h-4 w-4" />}
              Cancel run
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

interface ManualToolPanelProps {
  runId: string;
  tools: Array<{ function?: { name: string; description?: string; parameters?: Record<string, unknown> } }>;
  isLoading: boolean;
  selectedTool: string;
  onSelect: (name: string) => void;
  args: string;
  onArgs: (args: string) => void;
  result: string;
  onResult: (result: string) => void;
  onCall: (name: string, args: Record<string, unknown>) => void;
  calling: boolean;
}

function ManualToolPanel({
  tools,
  isLoading,
  selectedTool,
  onSelect,
  args,
  onArgs,
  result,
  onResult,
  onCall,
  calling,
}: ManualToolPanelProps) {
  const tool = tools.find((t) => t.function?.name === selectedTool);

  const call = () => {
    if (!selectedTool) return;
    let parsed: Record<string, unknown> = {};
    try {
      parsed = args.trim() ? JSON.parse(args) : {};
    } catch {
      onResult("Invalid JSON arguments.");
      return;
    }
    onCall(selectedTool, parsed);
  };

  if (isLoading) {
    return <Spinner label="Loading tools..." />;
  }
  if (tools.length === 0) {
    return (
      <div className="rounded-md border border-dashed p-4 text-sm text-muted-foreground">
        No live MCP tools. Tools are available only while a run is active and the MCP session is attached.
      </div>
    );
  }

  return (
    <div className="space-y-3">
      <div className="space-y-2">
        <Label className="text-xs">Tool</Label>
        <div className="flex flex-wrap gap-2">
          {tools.map((t) => (
            <Button
              key={t.function?.name}
              type="button"
              variant={selectedTool === t.function?.name ? "default" : "outline"}
              size="sm"
              className="font-mono text-xs"
              onClick={() => {
                onSelect(t.function?.name ?? "");
                onArgs("{}");
                onResult("");
              }}
            >
              {t.function?.name}
            </Button>
          ))}
        </div>
        {tool?.function?.description && (
          <p className="text-xs text-muted-foreground">{tool.function.description}</p>
        )}
      </div>
      <div className="space-y-2">
        <Label className="text-xs" htmlFor="tool-args">Arguments (JSON)</Label>
        <Textarea
          id="tool-args"
          value={args}
          onChange={(e) => onArgs(e.target.value)}
          className="min-h-[6rem] font-mono text-xs"
          spellCheck={false}
        />
      </div>
      <Button type="button" size="sm" onClick={call} disabled={!selectedTool || calling}>
        {calling ? <Loader2 className="h-4 w-4 animate-spin" /> : <Terminal className="h-4 w-4" />}
        Run tool
      </Button>
      {result && (
        <div className="space-y-1.5">
          <div className="flex items-center justify-between">
            <Label className="text-xs">Result</Label>
            <CopyButton value={result} size="sm" />
          </div>
          <pre className="max-h-72 overflow-auto rounded-md border bg-muted/40 p-2 font-mono text-xs whitespace-pre-wrap break-words scrollbar-thin">
            {result}
          </pre>
        </div>
      )}
    </div>
  );
}

interface AuditViewProps {
  loading: boolean;
  error: unknown;
  records: Array<Record<string, unknown>>;
  chainValid: boolean;
  chainReason: string;
}

function AuditView({ loading, error, records, chainValid, chainReason }: AuditViewProps) {
  if (loading) return <SkeletonRows count={3} />;
  if (error) return <div className="text-sm text-destructive">Failed to load audit.</div>;
  return (
    <div className="space-y-3">
      <div className={cn("rounded-md border p-3 text-sm", chainValid ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-200" : "border-destructive/40 bg-destructive/10 text-red-200")}>
        <div className="flex items-center gap-2">
          <Badge variant={chainValid ? "success" : "danger"}>
            {chainValid ? "Chain valid" : "Chain invalid"}
          </Badge>
        </div>
        <div className="mt-1 text-xs">{chainReason}</div>
      </div>
      {records.length === 0 ? (
        <p className="text-sm text-muted-foreground">No audit records.</p>
      ) : (
        <div className="overflow-x-auto rounded-md border">
          <table className="w-full border-collapse text-xs">
            <thead>
              <tr>
                {Object.keys(records[0]).slice(0, 6).map((k) => (
                  <th key={k}>{k}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {records.map((rec, i) => (
                <tr key={i}>
                  {Object.keys(records[0]).slice(0, 6).map((k) => (
                    <td key={k} className="max-w-xs truncate font-mono" title={String(rec[k] ?? "")}>
                      {String(rec[k] ?? "")}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

interface StateViewProps {
  label: string;
  loading: boolean;
  error: unknown;
  data: unknown;
}

function StateView({ label, loading, error, data }: StateViewProps) {
  if (loading) return <Skeleton className="h-40 rounded-md" />;
  if (error) {
    const msg = error instanceof ApiError ? (error.isNotFound ? "State unavailable for this run." : error.message) : "Failed to load state.";
    return <div className="rounded-md border border-dashed p-4 text-sm text-muted-foreground">{msg}</div>;
  }
  return (
    <div className="space-y-2">
      <Label className="text-xs">{label}</Label>
      <pre className="max-h-[40vh] overflow-auto rounded-md border bg-muted/40 p-3 font-mono text-xs scrollbar-thin">
        {safeStringify(data)}
      </pre>
    </div>
  );
}

interface ReconTabProps {
  runId: string;
  fetchArtifact: ReturnType<typeof useFetchArtifactBlob>;
  ready: boolean;
}

function ReconTab({ fetchArtifact, ready }: ReconTabProps) {
  const [assessment, setAssessment] = useState<ReconAssessment | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string>("");
  const mutate = fetchArtifact.mutate;

  useEffect(() => {
    // Don't fetch recon_assessment.json until the run is terminal or the
    // artifact list confirms it exists -- otherwise an in-progress recon
    // 404s on every mount (StrictMode double-mount + tab remounts).
    if (!ready) {
      setLoading(false);
      setAssessment(null);
      setError("");
      return;
    }
    setLoading(true);
    setError("");
    mutate("recon_assessment.json", {
      onSuccess: async (blob) => {
        try {
          const text = await blob.text();
          const data = JSON.parse(text) as ReconAssessment;
          setAssessment(data);
        } catch {
          setError("recon_assessment.json is not valid JSON.");
        }
        setLoading(false);
      },
      onError: (err) => {
        setError(err instanceof ApiError && err.isNotFound
          ? "No recon was run for this session."
          : "Failed to load recon assessment.");
        setAssessment(null);
        setLoading(false);
      },
    });
  }, [mutate, ready]);

  if (loading) {
    return <Spinner label="Loading recon..." />;
  }
  if (assessment) {
    return <ReconAssessmentCard assessment={assessment} />;
  }
  return (
    <div className="space-y-2 rounded-md border border-dashed p-4 text-sm text-muted-foreground">
      {error || "Recon in progress — assessment will appear here once recon completes."}
    </div>
  );
}

function safeStringify(value: unknown): string {
  try {
    return typeof value === "string" ? value : JSON.stringify(value, null, 2);
  } catch {
    return String(value);
  }
}
