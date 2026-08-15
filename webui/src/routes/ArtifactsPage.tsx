import { useMemo, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { ChevronLeft, FileText, RefreshCw } from "lucide-react";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Badge } from "@/components/ui/badge";
import { ArtifactViewer } from "@/components/ArtifactViewer";
import { SkeletonRows, Spinner } from "@/components/Loading";
import { useArtifacts, useAudit, useRunLog } from "@/api/hooks";
import { ApiError } from "@/api/client";
import { formatBytes } from "@/lib/utils";

const RUN_LOGS = ["mcp_exploit_server.log", "session_error.log", "recon_first_error.log"];
const ATTEMPT_LOGS = ["terminal.log", "python_run.log", "msf_output.log", "run_active_check.ps1"];

export function ArtifactsPage() {
  const { runId } = useParams<{ runId: string }>();
  const [tab, setTab] = useState("artifacts");
  const artifacts = useArtifacts(runId ?? null);
  const audit = useAudit(runId ?? null, tab === "audit");
  const [selected, setSelected] = useState<string>("");

  const artifactNames = artifacts.data?.artifacts.map((a) => a.name) ?? [];
  const effectiveSelected = selected || artifactNames[0] || "";

  const attemptCandidates = useMemo(() => {
    const out: Array<{ target: string; attempt: string }> = [];
    const seen = new Set<string>();
    for (const name of artifactNames) {
      const match = name.match(/^exploit_workspace\/(?:(?<ip>[^/]+)\/)?(?<attempt>[^/]+)\//);
      if (match && match.groups) {
        const ip = match.groups.ip ?? "_root_";
        const attempt = match.groups.attempt;
        const key = `${ip}|${attempt}`;
        if (!seen.has(key)) {
          seen.add(key);
          out.push({ target: ip, attempt });
        }
      }
    }
    return out;
  }, [artifactNames]);

  return (
    <div className="space-y-4 p-4 md:p-6">
      <div className="flex items-center gap-2">
        <Button asChild size="sm" variant="ghost">
          <Link to={`/runs/${runId}`}><ChevronLeft className="h-4 w-4" />Back to run</Link>
        </Button>
        <h1 className="text-sm font-mono text-muted-foreground">{runId}</h1>
        <Button size="sm" variant="ghost" onClick={() => artifacts.refetch()} disabled={artifacts.isFetching}>
          <RefreshCw className={cn("h-3.5 w-3.5", artifacts.isFetching && "animate-spin")} />
        </Button>
      </div>

      <Tabs value={tab} onValueChange={setTab}>
        <TabsList>
          <TabsTrigger value="artifacts">Artifacts</TabsTrigger>
          <TabsTrigger value="audit">Audit</TabsTrigger>
          <TabsTrigger value="logs">Logs</TabsTrigger>
        </TabsList>

        <TabsContent value="artifacts" className="grid gap-4 md:grid-cols-[260px_minmax(0,1fr)]">
          <div className="space-y-1">
            {artifacts.isLoading && <SkeletonRows count={4} />}
            {artifacts.error && <div className="text-sm text-destructive">Failed to load artifacts.</div>}
            {!artifacts.isLoading && artifactNames.length === 0 && (
              <div className="rounded-md border border-dashed p-4 text-sm text-muted-foreground">
                No artifacts yet. They appear as the run writes reports.
              </div>
            )}
            {artifactNames.map((name) => (
              <button
                key={name}
                type="button"
                onClick={() => setSelected(name)}
                className={cn(
                  "flex w-full items-center gap-2 rounded-md border px-2 py-1.5 text-left text-xs transition-colors",
                  effectiveSelected === name ? "border-primary bg-accent" : "hover:bg-accent/50",
                )}
              >
                <FileText className="h-3.5 w-3.5 shrink-0 text-muted-foreground" />
                <span className="truncate font-mono">{name}</span>
                <span className="ml-auto text-muted-foreground">{formatBytes(artifacts.data?.artifacts.find((a) => a.name === name)?.bytes ?? 0)}</span>
              </button>
            ))}
          </div>
          <div>
            {effectiveSelected ? (
              <Card>
                <CardHeader className="pb-2">
                  <CardTitle className="text-xs font-mono text-muted-foreground">{effectiveSelected}</CardTitle>
                </CardHeader>
                <CardContent>
                  <ArtifactViewer runId={runId ?? ""} name={effectiveSelected} />
                </CardContent>
              </Card>
            ) : (
              <div className="rounded-md border border-dashed p-8 text-center text-sm text-muted-foreground">
                Select an artifact to view it.
              </div>
            )}
          </div>
        </TabsContent>

        <TabsContent value="audit" className="space-y-3">
          <div className={cn("rounded-md border p-3 text-sm", audit.data?.chain_valid ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-200" : "border-destructive/40 bg-destructive/10 text-red-200")}>
            <div className="flex items-center gap-2 text-xs uppercase tracking-wide">
              <Badge variant={audit.data?.chain_valid ? "success" : "danger"}>
                {audit.data?.chain_valid ? "Chain valid" : "Chain invalid"}
              </Badge>
            </div>
            <div className="mt-1 text-xs">{audit.data?.chain_reason ?? ""}</div>
          </div>
          <div className="overflow-x-auto rounded-md border">
            <table className="w-full border-collapse text-xs">
              <thead>
                <tr>
                  {(audit.data?.records[0] ? Object.keys(audit.data.records[0]).slice(0, 6) : ["record"]).map((k) => (
                    <th key={k}>{k}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {(audit.data?.records ?? []).map((rec, i) => (
                  <tr key={i}>
                    {(audit.data?.records[0] ? Object.keys(audit.data.records[0]).slice(0, 6) : ["record"]).map((k) => (
                      <td key={k} className="max-w-xs truncate font-mono" title={String(rec[k] ?? "")}>
                        {String(rec[k] ?? "")}
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </TabsContent>

        <TabsContent value="logs">
          <LogsPanel runId={runId ?? ""} attemptCandidates={attemptCandidates} />
        </TabsContent>
      </Tabs>
    </div>
  );
}

interface LogsPanelProps {
  runId: string;
  attemptCandidates: Array<{ target: string; attempt: string }>;
}

function LogsPanel({ runId, attemptCandidates }: LogsPanelProps) {
  const [name, setName] = useState<string>(RUN_LOGS[0]);
  const [tail, setTail] = useState<number>(200);
  const [attempt, setAttempt] = useState<string>(attemptCandidates[0]?.attempt ?? "");
  const [target, setTarget] = useState<string>(attemptCandidates[0]?.target ?? "");
  const isAttemptLog = ATTEMPT_LOGS.includes(name);
  const log = useRunLog(runId, name, tail, attempt, target, true);

  return (
    <div className="space-y-3">
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <div className="space-y-1.5">
          <Label className="text-xs">Log</Label>
          <select
            value={name}
            onChange={(e) => setName(e.target.value)}
            className="h-9 w-full rounded-md border border-input bg-background px-2 text-sm"
          >
            <optgroup label="Run-level">
              {RUN_LOGS.map((n) => <option key={n} value={n}>{n}</option>)}
            </optgroup>
            <optgroup label="Per-attempt">
              {ATTEMPT_LOGS.map((n) => <option key={n} value={n}>{n}</option>)}
            </optgroup>
          </select>
        </div>
        <div className="space-y-1.5">
          <Label className="text-xs">Tail (lines)</Label>
          <Input type="number" min={1} max={2000} value={tail} onChange={(e) => setTail(Number(e.target.value))} />
        </div>
        {isAttemptLog && (
          <>
            <div className="space-y-1.5">
              <Label className="text-xs">Attempt ID</Label>
              <select
                value={attempt}
                onChange={(e) => setAttempt(e.target.value)}
                className="h-9 w-full rounded-md border border-input bg-background px-2 text-sm"
              >
                {attemptCandidates.length === 0 && <option value="">(none discovered)</option>}
                {attemptCandidates.map((c) => (
                  <option key={`${c.target}|${c.attempt}`} value={c.attempt}>{c.attempt}</option>
                ))}
              </select>
            </div>
            <div className="space-y-1.5">
              <Label className="text-xs">Target IP</Label>
              <select
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                className="h-9 w-full rounded-md border border-input bg-background px-2 text-sm"
              >
                {attemptCandidates.length === 0 && <option value="">(none discovered)</option>}
                {attemptCandidates.map((c) => (
                  <option key={`${c.target}|${c.attempt}`} value={c.target}>{c.target}</option>
                ))}
              </select>
            </div>
          </>
        )}
      </div>

      {isAttemptLog && attemptCandidates.length === 0 && (
        <div className="rounded-md border border-amber-500/30 bg-amber-500/10 p-3 text-xs text-amber-200">
          Per-attempt logs require attempt_id and target_ip. The artifacts endpoint does not list attempt
          directories, so these values must come from the run. If none are shown, the API path may not match
          the workspace layout for this run.
        </div>
      )}

      <div className="space-y-2">
        <div className="flex items-center gap-2">
          <Badge variant="outline" className="text-xs">{name}</Badge>
          {log.data && <span className="text-xs text-muted-foreground">{log.data.total_lines_returned}/{log.data.total_lines_in_file} lines</span>}
          <Button size="sm" variant="ghost" onClick={() => log.refetch()} disabled={log.isFetching}>
            <RefreshCw className={cn("h-3.5 w-3.5", log.isFetching && "animate-spin")} />
          </Button>
        </div>
        {log.isLoading && <Spinner label="Loading log..." />}
        {log.error && (
          <div className="rounded-md border border-destructive/40 bg-destructive/10 p-3 text-sm text-red-200">
            {log.error instanceof ApiError ? log.error.message : "Failed to load log."}
          </div>
        )}
        {log.data && (
          <pre className="max-h-[60vh] overflow-auto rounded-md border bg-muted/30 p-3 font-mono text-xs whitespace-pre-wrap break-words scrollbar-thin">
            {log.data.lines.join("\n") || "(empty)"}
          </pre>
        )}
      </div>
    </div>
  );
}