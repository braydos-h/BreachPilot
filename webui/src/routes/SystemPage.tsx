import { useState } from "react";
import { Loader2, RefreshCw, ShieldCheck, Stethoscope, Wrench } from "lucide-react";
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
  useDiagnostics,
  useLiveModels,
  useModels,
  usePlugins,
  usePutSecrets,
  useSecrets,
} from "@/api/hooks";
import { ApiError } from "@/api/client";
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
          <TabsTrigger value="plugins">Plugins</TabsTrigger>
          <TabsTrigger value="diagnostics">Diagnostics</TabsTrigger>
        </TabsList>
        <TabsContent value="config"><ConfigEditor /></TabsContent>
        <TabsContent value="secrets"><SecretsTab /></TabsContent>
        <TabsContent value="models"><ModelsTab /></TabsContent>
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
  const provider = models.data?.provider ?? "ollama";
  const isChatgpt = provider === "chatgpt";
  const registry = Object.entries(models.data?.registry ?? {});

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
              <ul className="mt-2 space-y-2 text-xs">
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
                      </div>
                      {info?.description && (
                        <p className="mt-1 font-sans text-muted-foreground">{info.description}</p>
                      )}
                    </li>
                  );
                })}
              </ul>
            </>
          )}
        </CardContent>
      </Card>
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
            <div className="flex items-center gap-2">
              <span className="font-mono">{String(p.name ?? `plugin-${i}`)}</span>
              {p.version && <Badge variant="outline" className="text-[10px]">{String(p.version)}</Badge>}
              {p.loaded && <Badge variant="success" className="text-[10px]">loaded</Badge>}
            </div>
            {Array.isArray(p.capabilities) && p.capabilities.length > 0 && (
              <div className="mt-1 text-muted-foreground">{p.capabilities.join(", ")}</div>
            )}
          </div>
        ))}
      </CardContent>
    </Card>
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