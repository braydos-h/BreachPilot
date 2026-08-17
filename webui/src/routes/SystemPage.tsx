import { useState } from "react";
import { Loader2, Plus, RefreshCw, ShieldCheck, Stethoscope, Trash2, Wrench } from "lucide-react";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ConfigEditor } from "@/components/ConfigEditor";
import { SkeletonRows } from "@/components/Loading";
import { ProviderSetup } from "@/components/ProviderSetup";
import {
  useAddModel,
  useDiagnostics,
  useLiveModels,
  useMemory,
  useModels,
  usePlugins,
  usePutSecrets,
  useRemoveModel,
  useSecrets,
  useTelemetry,
} from "@/api/hooks";
import { ApiError } from "@/api/client";
import { formatRelative } from "@/lib/utils";
import type { DiagnosticsResponse } from "@/api/types";

export function SystemPage() {
  return (
    <div className="space-y-4 p-4 md:p-6">
      <h1 className="text-lg font-semibold">System</h1>
      <Tabs defaultValue="config">
        <TabsList className="flex-wrap">
          <TabsTrigger value="config">Config</TabsTrigger>
          <TabsTrigger value="secrets">Secrets</TabsTrigger>
          <TabsTrigger value="models">Models</TabsTrigger>
          <TabsTrigger value="telemetry">Telemetry</TabsTrigger>
          <TabsTrigger value="memory">Memory</TabsTrigger>
          <TabsTrigger value="plugins">Plugins</TabsTrigger>
          <TabsTrigger value="diagnostics">Diagnostics</TabsTrigger>
        </TabsList>
        <TabsContent value="config"><ConfigEditor /></TabsContent>
        <TabsContent value="secrets"><SecretsTab /></TabsContent>
        <TabsContent value="models"><ModelsTab /></TabsContent>
        <TabsContent value="telemetry"><TelemetryTab /></TabsContent>
        <TabsContent value="memory"><MemoryTab /></TabsContent>
        <TabsContent value="plugins"><PluginsTab /></TabsContent>
        <TabsContent value="diagnostics"><DiagnosticsTab /></TabsContent>
      </Tabs>
    </div>
  );
}

function SecretsTab() {
  const secrets = useSecrets();
  const put = usePutSecrets();
  const [draft, setDraft] = useState<Record<string, string>>({});

  const entries = Object.entries(secrets.data?.keys ?? {});

  const onSave = () => {
    const payload = Object.fromEntries(Object.entries(draft).filter(([, v]) => v.trim()));
    if (Object.keys(payload).length === 0) return;
    put.mutate(payload, { onSuccess: () => setDraft({}) });
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-sm">Provider API keys</CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        {secrets.isLoading && <SkeletonRows count={2} className="p-2" />}
        {secrets.error && <div className="text-sm text-destructive">Failed to load secrets.</div>}
        {entries.length === 0 && <p className="text-sm text-muted-foreground">No configured provider keys.</p>}
        {entries.map(([name, status]) => (
          <div key={name} className="grid gap-2 sm:grid-cols-[200px_1fr_auto]">
            <div className="flex items-center gap-2">
              <span className="font-mono text-xs">{name}</span>
              {status === "configured" ? (
                <Badge variant="success"><ShieldCheck className="h-3 w-3" />configured</Badge>
              ) : (
                <Badge variant="muted">missing</Badge>
              )}
            </div>
            <Input
              type="password"
              placeholder={status === "configured" ? "Write-only. Enter a new value to replace." : "Enter value"}
              value={draft[name] ?? ""}
              onChange={(e) => setDraft((p) => ({ ...p, [name]: e.target.value }))}
              autoComplete="off"
            />
            <Button size="sm" variant="outline" onClick={onSave} disabled={!draft[name]?.trim() || put.isPending}>
              Save
            </Button>
          </div>
        ))}
        {put.error && <p className="text-xs text-destructive">{put.error instanceof ApiError ? put.error.message : "Save failed."}</p>}
      </CardContent>
    </Card>
  );
}

function ModelsTab() {
  const models = useModels();
  const live = useLiveModels();
  const addModel = useAddModel();
  const removeModel = useRemoveModel();
  const provider = models.data?.provider ?? "ollama";
  const isChatgpt = provider === "chatgpt";
  const registry = Object.entries(models.data?.registry ?? {});
  const [newAlias, setNewAlias] = useState("");
  const [newModel, setNewModel] = useState("");

  const onAdd = () => {
    const alias = newAlias.trim();
    const model = newModel.trim();
    if (!alias || !model) return;
    addModel.mutate({ alias, model }, { onSuccess: () => { setNewAlias(""); setNewModel(""); } });
  };

  return (
    <div className="space-y-3">
      <Card>
        <CardHeader><CardTitle className="text-sm">AI provider</CardTitle></CardHeader>
        <CardContent><ProviderSetup /></CardContent>
      </Card>

      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm">{isChatgpt ? "Live ChatGPT models" : "Live Ollama models"}</CardTitle>
            <Button size="sm" variant="ghost" onClick={() => live.refetch()} disabled={live.isFetching}>
              <RefreshCw className={cn("h-3.5 w-3.5", live.isFetching && "animate-spin")} />
            </Button>
          </div>
        </CardHeader>
        <CardContent className="space-y-2">
          {live.data && (
            <div className="flex items-center gap-2">
              <Badge variant="outline">{live.data.source}</Badge>
              {isChatgpt && live.data.error && (
                <span className="text-xs text-amber-200">{live.data.error} — sign in / start the proxy via the AI provider card above.</span>
              )}
              {!isChatgpt && live.data.source === "registry" && live.data.error && (
                <span className="rounded border border-amber-500/30 bg-amber-500/10 px-1.5 py-0.5 text-xs text-amber-200">
                  Ollama unreachable — showing configured registry models below.
                </span>
              )}
              {!isChatgpt && live.data.source === "ollama" && live.data.error && (
                <span className="text-xs text-muted-foreground">{live.data.error}</span>
              )}
            </div>
          )}
          <ul className="space-y-1 font-mono text-xs">
            {(live.data?.models ?? []).map((m) => <li key={m} className="rounded bg-muted/40 px-2 py-1">{m}</li>)}
            {(live.data?.models ?? []).length === 0 && (
              <li className="text-muted-foreground">No models reported. {isChatgpt ? "Sign in and start the proxy, then refresh." : "Is the daemon running?"}</li>
            )}
          </ul>
        </CardContent>
      </Card>
      <Card>
        <CardHeader><CardTitle className="text-sm">{isChatgpt ? "Configured ChatGPT models" : "Registry"}</CardTitle></CardHeader>
        <CardContent>
          {isChatgpt ? (
            <ul className="space-y-1 font-mono text-xs">
              {(models.data?.chatgpt?.configured_models ?? []).map((m) => (
                <li key={m} className="rounded bg-muted/40 px-2 py-1">{m}</li>
              ))}
              {(models.data?.chatgpt?.configured_models ?? []).length === 0 && (
                <li className="text-muted-foreground">Empty — models are discovered from <span className="font-mono">/v1/models</span> at run time.</li>
              )}
            </ul>
          ) : (
            <>
              <div className="text-xs text-muted-foreground">Default alias: <span className="font-mono text-foreground">{models.data?.default_alias ?? "—"}</span></div>
              <div className="mt-3 flex flex-wrap items-end gap-2">
                <div className="flex-1 min-w-[8rem]">
                  <label className="text-[10px] uppercase tracking-wide text-muted-foreground">Alias</label>
                  <Input value={newAlias} onChange={(e) => setNewAlias(e.target.value)} placeholder="e.g. llama" className="h-8 font-mono text-xs" />
                </div>
                <div className="flex-[2] min-w-[12rem]">
                  <label className="text-[10px] uppercase tracking-wide text-muted-foreground">Model id</label>
                  <Input value={newModel} onChange={(e) => setNewModel(e.target.value)} placeholder="e.g. llama3.1:8b" className="h-8 font-mono text-xs" />
                </div>
                <Button size="sm" onClick={onAdd} disabled={!newAlias.trim() || !newModel.trim() || addModel.isPending}>
                  {addModel.isPending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Plus className="h-3.5 w-3.5" />}
                  Add
                </Button>
              </div>
              {addModel.error && (
                <p className="mt-2 text-xs text-destructive">{addModel.error instanceof ApiError ? addModel.error.message : "Add failed."}</p>
              )}
              <ul className="mt-3 space-y-2 text-xs">
                {registry.map(([alias, model]) => {
                  const info = models.data?.info?.[alias];
                  const isDefault = alias === models.data?.default_alias;
                  return (
                    <li key={alias} className="rounded-md border p-2">
                      <div className="flex flex-wrap items-center gap-2 font-mono">
                        <span className="text-muted-foreground">{alias}</span>
                        <span>{String(model)}</span>
                        {isDefault && <Badge variant="success" className="text-[10px]">default</Badge>}
                        {info?.label && <span className="font-sans text-muted-foreground">{info.label}</span>}
                        {typeof info?.context_window === "number" && (
                          <span className="font-sans text-muted-foreground">{(info.context_window / 1000).toFixed(0)}K ctx</span>
                        )}
                        {!isDefault && (
                          <Button
                            size="sm"
                            variant="ghost"
                            className="ml-auto h-6 w-6 p-0 text-muted-foreground hover:text-destructive"
                            onClick={() => removeModel.mutate(alias)}
                            disabled={removeModel.isPending}
                            aria-label={`Remove ${alias}`}
                            title={`Remove ${alias}`}
                          >
                            <Trash2 className="h-3.5 w-3.5" />
                          </Button>
                        )}
                      </div>
                      {info?.description && (
                        <p className="mt-1 font-sans text-muted-foreground">{info.description}</p>
                      )}
                    </li>
                  );
                })}
              </ul>
              {removeModel.error && (
                <p className="mt-2 text-xs text-destructive">{removeModel.error instanceof ApiError ? removeModel.error.message : "Remove failed."}</p>
              )}
            </>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

function TelemetryTab() {
  const telemetry = useTelemetry();
  const summary = telemetry.data?.summary;
  const recent = telemetry.data?.recent ?? [];

  return (
    <div className="space-y-3">
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm">LLM usage</CardTitle>
            <Button size="sm" variant="ghost" onClick={() => telemetry.refetch()} disabled={telemetry.isFetching}>
              <RefreshCw className={cn("h-3.5 w-3.5", telemetry.isFetching && "animate-spin")} />
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          {telemetry.isLoading && <SkeletonRows count={3} className="p-2" />}
          {telemetry.error && <div className="text-sm text-destructive">Failed to load telemetry.</div>}
          {summary && (
            <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-4">
              <Stat label="Calls" value={String(summary.calls)} />
              <Stat label="Failed" value={String(summary.failed_calls)} />
              <Stat label="Total tokens" value={summary.total_tokens.toLocaleString()} />
              <Stat label="Avg tok/s" value={summary.average_tokens_per_second != null ? summary.average_tokens_per_second.toFixed(1) : "—"} />
              <Stat label="Avg ctx %" value={summary.average_context_usage_pct != null ? `${summary.average_context_usage_pct.toFixed(1)}%` : "—"} />
              <Stat label="Max ctx %" value={summary.max_context_usage_pct != null ? `${summary.max_context_usage_pct.toFixed(1)}%` : "—"} />
              <Stat label="Last call" value={formatRelative(summary.last_call_at)} />
              <Stat label="Aliases" value={summary.aliases.join(", ") || "—"} />
            </div>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader><CardTitle className="text-sm">Recent calls</CardTitle></CardHeader>
        <CardContent>
          {recent.length === 0 && <p className="text-sm text-muted-foreground">No LLM calls recorded yet.</p>}
          {recent.length > 0 && (
            <div className="overflow-x-auto rounded-md border">
              <table className="w-full border-collapse text-xs">
                <thead>
                  <tr>
                    {["alias", "model", "source", "tokens", "tok/s", "ctx %", "duration", "error"].map((h) => (
                      <th key={h} className="border-b p-2 text-left font-semibold">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {recent.map((r, i) => (
                    <tr key={i} className="even:bg-muted/20">
                      <td className="border-b p-2 font-mono">{r.alias ?? "—"}</td>
                      <td className="max-w-[200px] truncate border-b p-2 font-mono" title={String(r.model_id ?? "")}>{r.model_id ?? "—"}</td>
                      <td className="border-b p-2">{r.source ?? "—"}</td>
                      <td className="border-b p-2 font-mono">{r.total_tokens ?? "—"}</td>
                      <td className="border-b p-2 font-mono">{r.tokens_per_second != null ? r.tokens_per_second.toFixed(1) : "—"}</td>
                      <td className="border-b p-2 font-mono">{r.context_usage_pct != null ? `${r.context_usage_pct.toFixed(1)}%` : "—"}</td>
                      <td className="border-b p-2 font-mono">{r.wall_duration_seconds != null ? `${r.wall_duration_seconds.toFixed(1)}s` : "—"}</td>
                      <td className="border-b p-2">{r.error ? <Badge variant="danger">error</Badge> : ""}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

function MemoryTab() {
  const memory = useMemory();
  const confidence = memory.data?.confidence ?? [];
  const lessons = memory.data?.lessons ?? [];
  const attackMemory = memory.data?.attack_memory ?? [];

  return (
    <div className="space-y-3">
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm">Skill outcome confidence</CardTitle>
            <Button size="sm" variant="ghost" onClick={() => memory.refetch()} disabled={memory.isFetching}>
              <RefreshCw className={cn("h-3.5 w-3.5", memory.isFetching && "animate-spin")} />
            </Button>
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
        <CardHeader><CardTitle className="text-sm">Attack memory</CardTitle></CardHeader>
        <CardContent>
          {attackMemory.length === 0 && <p className="text-sm text-muted-foreground">No attack-memory items captured.</p>}
          {attackMemory.length > 0 && (
            <ul className="space-y-1.5 text-xs">
              {attackMemory.map((m) => (
                <li key={m.id} className="rounded-md border p-2">
                  <div className="flex flex-wrap items-center gap-2">
                    <Badge variant="outline" className="text-[10px]">{m.category}</Badge>
                    <span className="font-mono text-muted-foreground">{m.target_ip}</span>
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
          )}
        </CardContent>
      </Card>
    </div>
  );
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-md border p-2">
      <div className="text-[10px] uppercase tracking-wide text-muted-foreground">{label}</div>
      <div className="mt-0.5 truncate font-mono text-sm" title={value}>{value}</div>
    </div>
  );
}

function PluginsTab() {
  const plugins = usePlugins();
  const list = plugins.data?.plugins ?? [];
  return (
    <Card>
      <CardHeader><CardTitle className="text-sm">Plugins</CardTitle></CardHeader>
      <CardContent className="space-y-2">
        {plugins.isLoading && <SkeletonRows count={3} className="p-2" />}
        {list.length === 0 && <p className="text-sm text-muted-foreground">No discovered plugins.</p>}
        {list.map((p, i) => (
          <div key={i} className="rounded-md border p-2 text-xs">
            <div className="flex flex-wrap items-center gap-2">
              <span className="font-mono">{String(p.name ?? `plugin-${i}`)}</span>
              {p.version && <Badge variant="outline" className="text-[10px]">{String(p.version)}</Badge>}
              {p.loaded ? <Badge variant="success" className="text-[10px]">loaded</Badge>
                : (p.enabled ? <Badge variant="warn" className="text-[10px]">enabled·not loaded</Badge>
                  : <Badge variant="muted" className="text-[10px]">disabled</Badge>)}
            </div>
            {p.description && <div className="mt-1 text-muted-foreground">{String(p.description)}</div>}
            <div className="mt-1 flex flex-wrap items-center gap-1">
              {Array.isArray(p.capabilities) && p.capabilities.map((cap) => (
                <Badge key={cap} variant={cap === "event_subscriber" ? "info" : "outline"} className="text-[10px]">{String(cap)}</Badge>
              ))}
            </div>
            <PluginGatingHints plugin={p} />
          </div>
        ))}
      </CardContent>
    </Card>
  );
}

/** Derive gating hints from a plugin's config_section (the manifest schema).
 *  Shows "requires allowlist" for mcp_tool plugins touching targets, "no-op
 *  without url" when a url field is empty in the schema, and surfaces
 *  api_key_env fields (the actual env-var presence is runtime — we show the
 *  key name as a hint, not a live BLOCKED check, since the API doesn't expose
 *  env var state per-plugin). */
function PluginGatingHints({ plugin }: { plugin: { config_section?: Record<string, Record<string, unknown>> | null; capabilities?: string[] } }) {
  const section = plugin.config_section;
  if (!section || typeof section !== "object") {
    // No config_section — derive from capabilities only.
    const caps = plugin.capabilities ?? [];
    if (caps.includes("mcp_tool")) {
      return <div className="mt-1 text-muted-foreground"><Badge variant="outline" className="text-[10px]">requires allowlist</Badge></div>;
    }
    return null;
  }
  const hints: Array<{ label: string; variant: "warn" | "outline" | "info" }> = [];
  for (const block of Object.values(section)) {
    if (!block || typeof block !== "object") continue;
    const envKey = block.api_key_env;
    const url = block.url;
    if (typeof envKey === "string" && envKey) {
      hints.push({ label: `needs ${envKey}`, variant: "warn" });
    }
    if (typeof url === "string" && url === "") {
      hints.push({ label: "no-op without url", variant: "warn" });
    }
    if (block.enabled === false) {
      hints.push({ label: "plugin block disabled", variant: "outline" });
    }
  }
  const caps = plugin.capabilities ?? [];
  if (caps.includes("mcp_tool")) {
    hints.push({ label: "requires allowlist", variant: "info" });
  }
  if (hints.length === 0) return null;
  return (
    <div className="mt-1 flex flex-wrap items-center gap-1">
      {hints.map((h, idx) => (
        <Badge key={idx} variant={h.variant} className="text-[10px]">{h.label}</Badge>
      ))}
    </div>
  );
}

function DiagnosticsTab() {
  const diag = useDiagnostics();
  const [result, setResult] = useState<DiagnosticsResponse | null>(null);
  const [error, setError] = useState<string>("");

  const run = (kind: "doctor" | "self-test") => {
    setError("");
    setResult(null);
    diag.mutate(kind, {
      onSuccess: setResult,
      onError: (err) => setError(err instanceof ApiError ? err.message : "Diagnostics failed."),
    });
  };

  return (
    <Card>
      <CardHeader><CardTitle className="text-sm">Diagnostics</CardTitle></CardHeader>
      <CardContent className="space-y-3">
        <div className="flex flex-wrap gap-2">
          <Button size="sm" onClick={() => run("doctor")} disabled={diag.isPending}>
            {diag.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Stethoscope className="h-4 w-4" />}
            Run doctor
          </Button>
          <Button size="sm" onClick={() => run("self-test")} disabled={diag.isPending}>
            {diag.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Wrench className="h-4 w-4" />}
            Run self-test
          </Button>
        </div>
        {error && <div className="text-sm text-destructive">{error}</div>}
        {result && (
          <div className="space-y-2">
            <div className="flex items-center gap-2">
              <Badge variant={result.exit_code === 0 ? "success" : "danger"}>
                exit {result.exit_code}
              </Badge>
            </div>
            <pre className="max-h-[60vh] overflow-auto rounded-md border bg-muted/30 p-3 font-mono text-xs whitespace-pre-wrap break-words scrollbar-thin">
              {result.output || "(no output)"}
            </pre>
          </div>
        )}
      </CardContent>
    </Card>
  );
}