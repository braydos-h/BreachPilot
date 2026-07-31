import { useState } from "react";
import { Loader2, RefreshCw, Search, ShieldCheck, Stethoscope, Wrench } from "lucide-react";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ConfigEditor } from "@/components/ConfigEditor";
import {
  useDiagnostics,
  useLiveModels,
  useModels,
  usePlugins,
  usePutSecrets,
  useSecrets,
  useSkillDetail,
  useSkillSearch,
  useSkills,
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
          <TabsTrigger value="skills">Skills</TabsTrigger>
          <TabsTrigger value="plugins">Plugins</TabsTrigger>
          <TabsTrigger value="diagnostics">Diagnostics</TabsTrigger>
        </TabsList>
        <TabsContent value="config"><ConfigEditor /></TabsContent>
        <TabsContent value="secrets"><SecretsTab /></TabsContent>
        <TabsContent value="models"><ModelsTab /></TabsContent>
        <TabsContent value="skills"><SkillsTab /></TabsContent>
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
        {secrets.isLoading && <div className="text-sm text-muted-foreground">Loading...</div>}
        {secrets.error && <div className="text-sm text-destructive">Failed to load secrets.</div>}
        {entries.length === 0 && <p className="text-sm text-muted-foreground">No configured provider keys.</p>}
        {entries.map(([name, status]) => (
          <div key={name} className="grid gap-2 sm:grid-cols-[200px_1fr_auto]">
            <div className="flex items-center gap-2">
              <span className="font-mono text-xs">{name}</span>
              {status === "configured" ? (
                <Badge variant="outline" className="border-emerald-500/40 text-emerald-300"><ShieldCheck className="mr-1 h-3 w-3" />configured</Badge>
              ) : (
                <Badge variant="outline" className="text-muted-foreground">missing</Badge>
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
  const registry = Object.entries(models.data?.registry ?? {});

  return (
    <div className="space-y-3">
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm">Live Ollama models</CardTitle>
            <Button size="sm" variant="ghost" onClick={() => live.refetch()} disabled={live.isFetching}>
              <RefreshCw className={cn("h-3.5 w-3.5", live.isFetching && "animate-spin")} />
            </Button>
          </div>
        </CardHeader>
        <CardContent className="space-y-2">
          {live.data && (
            <div className="flex items-center gap-2">
              <Badge variant="outline">{live.data.source}</Badge>
              {live.data.error && <span className="text-xs text-muted-foreground">{live.data.error}</span>}
            </div>
          )}
          <ul className="space-y-1 font-mono text-xs">
            {(live.data?.models ?? []).map((m) => <li key={m} className="rounded bg-muted/40 px-2 py-1">{m}</li>)}
          </ul>
        </CardContent>
      </Card>
      <Card>
        <CardHeader><CardTitle className="text-sm">Registry</CardTitle></CardHeader>
        <CardContent>
          <div className="text-xs text-muted-foreground">Default alias: <span className="font-mono text-foreground">{models.data?.default_alias ?? "\u2014"}</span></div>
          <ul className="mt-2 space-y-1 font-mono text-xs">
            {registry.map(([alias, model]) => (
              <li key={alias} className="flex items-center gap-2">
                <span className="text-muted-foreground">{alias}</span>
                <span>{String(model)}</span>
              </li>
            ))}
          </ul>
        </CardContent>
      </Card>
    </div>
  );
}

function SkillsTab() {
  const skills = useSkills();
  const [query, setQuery] = useState("");
  const search = useSkillSearch(query, query.trim().length > 0);
  const [selected, setSelected] = useState<string | null>(null);
  const detail = useSkillDetail(selected);

  const list = query.trim() ? search.data?.results ?? [] : skills.data?.skills ?? [];

  return (
    <div className="grid gap-3 md:grid-cols-[280px_minmax(0,1fr)]">
      <Card>
        <CardHeader>
          <div className="flex items-center gap-2">
            <Search className="h-3.5 w-3.5 text-muted-foreground" />
            <Input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search skills" className="h-8" />
          </div>
        </CardHeader>
        <CardContent className="space-y-1">
          {list.length === 0 && <p className="text-xs text-muted-foreground">No skills.</p>}
          {list.map((s) => (
            <button
              key={s.name}
              type="button"
              onClick={() => setSelected(s.name)}
              className={cn(
                "flex w-full flex-col items-start rounded-md border px-2 py-1.5 text-left text-xs transition-colors",
                selected === s.name ? "border-primary bg-accent" : "hover:bg-accent/50",
              )}
            >
              <span className="font-mono">{s.name}</span>
              <span className="text-muted-foreground">{s.description}</span>
            </button>
          ))}
        </CardContent>
      </Card>
      <Card>
        <CardHeader><CardTitle className="text-sm">{selected ?? "Select a skill"}</CardTitle></CardHeader>
        <CardContent>
          {!selected && <p className="text-sm text-muted-foreground">Choose a skill to view its body, sections, and references.</p>}
          {selected && detail.isLoading && <div className="flex items-center gap-2 text-sm text-muted-foreground"><Loader2 className="h-4 w-4 animate-spin" />Loading...</div>}
          {selected && detail.error && <div className="text-sm text-destructive">Failed to load skill.</div>}
          {detail.data && (
            <div className="space-y-3 text-sm">
              <p className="text-muted-foreground">{detail.data.description}</p>
              {detail.data.domain && <div className="text-xs">Domain: {detail.data.domain}{detail.data.subdomain ? ` / ${detail.data.subdomain}` : ""}</div>}
              {detail.data.tags.length > 0 && (
                <div className="flex flex-wrap gap-1">
                  {detail.data.tags.map((t) => <Badge key={t} variant="outline" className="text-[10px]">{t}</Badge>)}
                </div>
              )}
              {detail.data.nist_csf.length > 0 && (
                <div className="text-xs"><span className="text-muted-foreground">NIST CSF:</span> {detail.data.nist_csf.join(", ")}</div>
              )}
              {detail.data.mitre_attack.length > 0 && (
                <div className="text-xs"><span className="text-muted-foreground">MITRE ATT&CK:</span> {detail.data.mitre_attack.join(", ")}</div>
              )}
              <pre className="max-h-[50vh] overflow-auto rounded-md border bg-muted/30 p-3 font-mono text-xs whitespace-pre-wrap break-words scrollbar-thin">
                {detail.data.body}
              </pre>
              {detail.data.references.length > 0 && (
                <details>
                  <summary className="cursor-pointer text-xs text-muted-foreground">References</summary>
                  <ul className="mt-1 list-disc space-y-0.5 pl-4 text-xs">
                    {detail.data.references.map((r) => <li key={r} className="font-mono">{r}</li>)}
                  </ul>
                </details>
              )}
            </div>
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
        {plugins.isLoading && <div className="text-sm text-muted-foreground">Loading...</div>}
        {list.length === 0 && <p className="text-sm text-muted-foreground">No discovered plugins.</p>}
        {list.map((p, i) => (
          <div key={i} className="rounded-md border p-2 text-xs">
            <div className="flex items-center gap-2">
              <span className="font-mono">{String(p.name ?? `plugin-${i}`)}</span>
              {p.version && <Badge variant="outline" className="text-[10px]">{String(p.version)}</Badge>}
              {p.loaded && <Badge variant="outline" className="text-[10px] text-emerald-300">loaded</Badge>}
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
              <Badge variant="outline" className={result.exit_code === 0 ? "border-emerald-500/40 text-emerald-300" : "border-destructive/40 text-red-300"}>
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