// Shared AI-provider setup pieces: the Ollama/ChatGPT picker, the ChatGPT
// sign-in / proxy controls, and a composed <ProviderSetup /> used by
// System → Models. OnboardingGate also imports ProviderPicker + ChatGptControls
// so first-run setup can ask for provider choice + ChatGPT OAuth alongside
// the API keys.

import { useCallback, useMemo, useState } from "react";
import { Loader2, LogIn, Play, ShieldCheck, Square } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { SegmentedControl } from "@/components/ui/segmented";
import {
  useChatgptLogin,
  useChatgptProxyStart,
  useChatgptProxyStop,
  useLiveModels,
  useModels,
  usePatchConfig,
  useProviders,
} from "@/api/hooks";
import { ApiError } from "@/api/client";

/** Active provider + a switch() that persists `models.provider` (and flips
 *  `chatgpt.enabled` / `opencode_go.enabled` on when switching, mirroring the CLI menu). */
export function useProviderSwitch() {
  const models = useModels();
  const patchConfig = usePatchConfig();
  const provider = models.data?.provider ?? "ollama";
  const switchTo = useCallback(
    (next: string) => {
      if (next === provider) return;
      let patch: Record<string, unknown>;
      if (next === "chatgpt") patch = { models: { provider: "chatgpt" }, chatgpt: { enabled: true } };
      else if (next === "opencode_go")
        patch = { models: { provider: "opencode_go" }, opencode_go: { enabled: true } };
      else if (next === "ollama") patch = { models: { provider: "ollama" } };
      // Generic registered provider: the backend persists its `providers.<id>`
      // block (mirrored from POST /models/provider).
      else patch = { models: { provider: next }, providers: { [next]: { enabled: true } } };
      patchConfig.mutate(patch);
    },
    [provider, patchConfig],
  );
  return { provider, switchTo, isPending: patchConfig.isPending, error: patchConfig.error };
}

/** Provider-aware list of selectable models for a run: live models (when the
 *  provider is reachable) plus configured/registry models plus the provider
 *  default. Single source of truth — RunWizard and ProviderPicker consumers all use this
 *  so a provider switch is reflected everywhere, not just one component. */
export function useModelOptions(): string[] {
  const models = useModels();
  const live = useLiveModels();
  const provider = models.data?.provider ?? "ollama";
  return useMemo(() => {
    const set = new Set<string>();
    if (provider === "chatgpt") {
      if (live.data?.source === "chatgpt") (live.data.models ?? []).forEach((m) => set.add(m));
      (models.data?.chatgpt?.configured_models ?? []).forEach((m) => set.add(m));
      if (models.data?.chatgpt?.default_model) set.add(models.data.chatgpt.default_model);
    } else if (provider === "opencode_go") {
      if (live.data?.source === "opencode_go") (live.data.models ?? []).forEach((m) => set.add(m));
      (models.data?.opencode_go?.configured_models ?? []).forEach((m) => set.add(m));
      if (models.data?.opencode_go?.default_model) set.add(models.data.opencode_go.default_model);
    } else if (provider === "ollama") {
      if (live.data?.source === "ollama") (live.data.models ?? []).forEach((m) => set.add(m));
      Object.values(models.data?.registry ?? {}).forEach((m) => set.add(String(m)));
      if (models.data?.default_alias) set.add(models.data.default_alias);
    } else {
      // Generic registered provider: live models come straight from the
      // provider adapter (/models/live dispatches by registry id); the static
      // registry is the configured fallback.
      if (live.data?.source === provider) (live.data.models ?? []).forEach((m) => set.add(m));
      Object.values(models.data?.registry ?? {}).forEach((m) => set.add(String(m)));
    }
    return Array.from(set);
  }, [models.data, live.data, provider]);
}

/** Provider-aware default model id to preselect (chatgpt/opencode_go default_model, registry
 *  metadata default_model for other providers, else the ollama default_alias). Empty string
 *  when nothing is configured. */
export function useDefaultModel(): string {
  const models = useModels();
  const providers = useProviders();
  const provider = models.data?.provider ?? "ollama";
  if (provider === "chatgpt") return models.data?.chatgpt?.default_model ?? "";
  if (provider === "opencode_go") return models.data?.opencode_go?.default_model ?? "";
  if (provider !== "ollama") {
    const meta = providers.data?.providers?.find((p) => p.id === provider);
    if (meta?.default_model) return meta.default_model;
  }
  return models.data?.default_alias ?? "";
}

export interface ProviderStatus {
  provider: string;
  /** Human label for badges: "Ollama" | "ChatGPT" | "OpenCode Go". */
  label: string;
  /** Live models are available and the live query reported no error. */
  online: boolean;
  source: string;
  liveCount: number;
  error?: string;
}

function providerLabel(provider: string): string {
  switch (provider) {
    case "ollama":
      return "Ollama";
    case "chatgpt":
      return "ChatGPT";
    case "opencode_go":
      return "OpenCode Go";
    default:
      // Generic registered provider — derive a readable label from its id and
      // prefer the registry display name when the metadata is loaded.
      return provider.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
  }
}

/** Provider-aware connectivity status for badges/status rows. Replaces the
 *  hardcoded "Ollama online/offline" checks in Layout and Wizard. */
export function useProviderStatus(): ProviderStatus {
  const models = useModels();
  const live = useLiveModels();
  const provider = models.data?.provider ?? "ollama";
  const liveModels = live.data?.models ?? [];
  return {
    provider,
    label: providerLabel(provider),
    online: liveModels.length > 0 && !live.data?.error,
    source: live.data?.source ?? "—",
    liveCount: liveModels.length,
    error: live.data?.error,
  };
}

/** Provider picker bound to models.provider (persists on change). Options are
 *  registry-driven (one per registered adapter) with the built-in three as
 *  fallback while metadata loads. */
const BUILTIN_PROVIDER_OPTIONS = [
  { value: "ollama", label: "Ollama" },
  { value: "chatgpt", label: "ChatGPT" },
  { value: "opencode_go", label: "OpenCode Go" },
];

export function ProviderPicker() {
  const { provider, switchTo, isPending, error } = useProviderSwitch();
  const providers = useProviders();
  const rows = providers.data?.providers;
  const options =
    rows && rows.length > 0
      ? rows.map((r) => ({
          value: r.id,
          label: BUILTIN_PROVIDER_OPTIONS.find((o) => o.value === r.id)?.label ?? r.name,
        }))
      : BUILTIN_PROVIDER_OPTIONS;
  return (
    <div className="space-y-2">
      <SegmentedControl value={provider} onChange={switchTo} options={options} />
      {isPending && <p className="text-xs text-muted-foreground">Switching provider…</p>}
      {error && (
        <p className="text-xs text-destructive">
          {error instanceof ApiError ? error.message : "Failed to switch provider."}
        </p>
      )}
    </div>
  );
}

/** OpenCode Go controls — API-key status, base URL, default model, live count. No secrets leave the backend. */
export function OpenCodeGoControls() {
  const providers = useProviders();
  const models = useModels();
  const live = useLiveModels();
  const og = providers.data?.opencode_go;

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2 text-xs">
        <Badge variant={og?.api_key_present ? "success" : "muted"}>
          <ShieldCheck className="h-3 w-3" />
          {og?.api_key_present ? "API key configured" : "API key missing"}
        </Badge>
        <Badge variant={og?.reachable ? "success" : "muted"}>{og?.reachable ? "online" : "offline"}</Badge>
        {og && (
          <span className="text-muted-foreground">
            <span className="font-mono">{og.base_url}</span> · default{" "}
            <span className="font-mono text-foreground">{og.default_model ?? "muse-spark-1.2-contributor"}</span>
          </span>
        )}
      </div>
      {!og?.api_key_present && (
        <p className="text-xs text-amber-200">
          Set <span className="font-mono">OPENCODE_GO_API_KEY</span> via System → API keys or secr.json. Responses API:{" "}
          <span className="font-mono">https://opencode.ai/zen/go/v1/responses</span> (model{" "}
          <span className="font-mono">muse-spark-1.2-contributor</span>).
        </p>
      )}
      <p className="text-xs text-muted-foreground">
        Uses <span className="font-mono">OPENCODE_GO_API_KEY</span> as{" "}
        <span className="font-mono">Authorization: Bearer</span> to{" "}
        <span className="font-mono">https://opencode.ai/zen/go/v1</span>. Key never leaves the server.{" "}
        {og?.available_models?.length ? `Discovered ${og.available_models.length} models.` : ""}
        {models.data?.opencode_go?.configured_models?.length
          ? ` Configured: ${models.data.opencode_go.configured_models.join(", ")}.`
          : ""}
      </p>
      <div className="flex flex-wrap gap-2 text-xs text-muted-foreground">
        <span>Live source: {live.data?.source ?? "—"}</span>
        <span>·</span>
        <span>{(live.data?.models ?? []).length} live models</span>
        {og?.context_window && <span>· {og.context_window} ctx</span>}
      </div>
      {og?.error && <p className="text-xs text-destructive">{og.error}</p>}
      {live.data?.error && <p className="text-xs text-amber-200">{live.data.error}</p>}
    </div>
  );
}

/** ChatGPT (openai-oauth) auth + proxy controls. Self-contained — uses the
 *  /providers + /providers/chatgpt/* hooks. OAuth tokens never reach this UI. */
export function ChatGptControls() {
  const providers = useProviders();
  const login = useChatgptLogin();
  const start = useChatgptProxyStart();
  const stop = useChatgptProxyStop();
  const [loginUrl, setLoginUrl] = useState<string>("");
  const [error, setError] = useState<string>("");

  const cg = providers.data?.chatgpt;
  const refresh = () => providers.refetch();

  const onLogin = () => {
    setError("");
    setLoginUrl("");
    login.mutate(undefined, {
      onSuccess: (r) => {
        if (r.ok && r.url) setLoginUrl(r.url);
        else setError(r.reason || "Login did not return a URL.");
      },
      onError: (e) => setError(e instanceof ApiError ? e.message : "Login failed."),
    });
  };

  const onStart = () => {
    setError("");
    start.mutate(undefined, {
      onError: (e) => setError(e instanceof ApiError ? e.message : "Proxy start failed."),
      onSuccess: () => refresh(),
    });
  };

  const onStop = () => {
    setError("");
    stop.mutate(undefined, {
      onError: (e) => setError(e instanceof ApiError ? e.message : "Proxy stop failed."),
      onSuccess: () => refresh(),
    });
  };

  const busy = login.isPending || start.isPending || stop.isPending || providers.isFetching;

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2 text-xs">
        <Badge variant={cg?.authenticated ? "success" : "muted"}>
          <ShieldCheck className="h-3 w-3" />{cg?.authenticated ? "signed in" : "not signed in"}
        </Badge>
        <Badge variant={cg?.proxy_running ? "success" : "muted"}>
          {cg?.proxy_running ? "proxy running" : "proxy stopped"}
        </Badge>
        {cg?.we_started && <Badge variant="outline">started by BreachPilot</Badge>}
        {cg && (
          <span className="text-muted-foreground">
            <span className="font-mono">{cg.host}:{cg.port}</span> · default{" "}
            <span className="font-mono text-foreground">{cg.default_model ?? "gpt-5.2"}</span>
          </span>
        )}
      </div>
      {!cg?.authenticated && (
        <p className="text-xs text-amber-200">Sign in with ChatGPT to use this provider.</p>
      )}
      <p className="text-xs text-muted-foreground">
        OAuth tokens live in openai-oauth's <span className="font-mono">~/.codex/auth.json</span> on the
        server — they never enter this UI or config. Sign in opens a browser on the server host.
      </p>
      <div className="flex flex-wrap gap-2">
        <Button size="sm" variant="outline" onClick={onLogin} disabled={busy || cg?.authenticated}>
          {login.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <LogIn className="h-4 w-4" />}
          Sign in with ChatGPT
        </Button>
        <Button size="sm" variant="outline" onClick={onStart} disabled={busy || !cg?.authenticated || cg?.proxy_running}>
          {start.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />}
          Start proxy
        </Button>
        <Button size="sm" variant="outline" onClick={onStop} disabled={busy || !cg?.proxy_running || !cg?.we_started}>
          {stop.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Square className="h-4 w-4" />}
          Stop proxy
        </Button>
      </div>
      {loginUrl && (
        <div className="rounded-md border bg-muted/30 p-2 text-xs">
          <span className="text-muted-foreground">Open this URL to authorize (server-side browser also opened): </span>
          <a className="font-mono break-all text-blue-400 underline" href={loginUrl} target="_blank" rel="noreferrer">{loginUrl}</a>
        </div>
      )}
      {error && <p className="text-xs text-destructive">{error}</p>}
    </div>
  );
}

/** Picker + provider-appropriate body (ChatGPT / OpenCode Go controls, Ollama note otherwise). */
export function ProviderSetup() {
  const { provider } = useProviderSwitch();
  let body: React.ReactNode;
  if (provider === "chatgpt") body = <ChatGptControls />;
  else if (provider === "opencode_go") body = <OpenCodeGoControls />;
  else body = <p className="text-xs text-muted-foreground">Local Ollama models. Embeddings also use Ollama.</p>;
  return (
    <div className="space-y-3">
      <ProviderPicker />
      {body}
    </div>
  );
}