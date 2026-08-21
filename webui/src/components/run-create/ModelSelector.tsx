import { RefreshCw, ShieldAlert } from "lucide-react";
import { cn } from "@/lib/utils";
import { Label } from "@/components/ui/label";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { useLiveModels, useModelOptions, useProviderStatus } from "@/components/ProviderSetup";

interface ModelSelectorProps {
  model: string;
  onModelChange: (m: string) => void;
}

interface StatusMeta {
  tone: "ok" | "warn" | "err";
  label: string;
  detail: string;
}

/** Provider-aware model picker. Status row collapses the provider/live/registry
 *  states into one line: Connected, Registry fallback, Authentication required,
 *  Offline, or Loading. Self-contained — same hooks ProviderSetup uses. */
export function ModelSelector({ model, onModelChange }: ModelSelectorProps) {
  const modelOptions = useModelOptions();
  const liveModels = useLiveModels();
  const status = useProviderStatus();
  const refetch = liveModels.refetch;

  const meta: StatusMeta = liveModels.isLoading
    ? { tone: "warn", label: "Checking…", detail: "Contacting the model provider." }
    : status.online
      ? { tone: "ok", label: "Connected", detail: `${status.liveCount} live ${status.label} models` }
      : status.provider === "ollama" && status.source === "registry"
        ? { tone: "warn", label: "Registry fallback", detail: "Ollama unreachable — using configured registry models." }
        : status.provider === "chatgpt"
          ? { tone: "err", label: "Authentication required", detail: status.error ?? "Sign in via System → Models." }
          : { tone: "err", label: "Offline", detail: status.error ?? `${status.label} is not reachable.` };

  const dot = cn(
    "h-1.5 w-1.5 rounded-full",
    meta.tone === "ok" && "bg-emerald-400",
    meta.tone === "warn" && "bg-amber-400",
    meta.tone === "err" && "bg-destructive",
  );

  return (
    <div className="space-y-2">
      <Label className="text-sm font-semibold">Model</Label>
      <div className="flex items-start gap-2">
        <div className="min-w-0 flex-1">
          <Select value={model} onValueChange={onModelChange}>
            <SelectTrigger className="h-10">
              <SelectValue placeholder="Default model" />
            </SelectTrigger>
            <SelectContent>
              {modelOptions.length === 0 ? (
                <div className="px-3 py-2 text-xs text-muted-foreground">No models discovered.</div>
              ) : (
                modelOptions.map((m) => (
                  <SelectItem key={m} value={m}>
                    {m}
                  </SelectItem>
                ))
              )}
            </SelectContent>
          </Select>
        </div>
        <Button
          type="button"
          size="icon"
          variant="outline"
          className="h-10 w-10 shrink-0"
          onClick={() => refetch()}
          disabled={liveModels.isFetching}
          aria-label="Refresh models"
          title="Refresh models"
        >
          <RefreshCw className={cn("h-4 w-4", liveModels.isFetching && "animate-spin")} />
        </Button>
      </div>

      <div
        className={cn(
          "flex items-center gap-2 rounded-md border px-2.5 py-1.5 text-xs",
          meta.tone === "ok" && "border-emerald-500/20 bg-emerald-500/5",
          meta.tone === "warn" && "border-amber-500/25 bg-amber-500/5",
          meta.tone === "err" && "border-destructive/25 bg-destructive/5",
        )}
        role="status"
      >
        <span className={dot} aria-hidden />
        <span
          className={cn(
            "font-medium",
            meta.tone === "ok" && "text-emerald-300",
            meta.tone === "warn" && "text-amber-200",
            meta.tone === "err" && "text-destructive",
          )}
        >
          {meta.label}
        </span>
        <span className="min-w-0 flex-1 truncate text-muted-foreground">{meta.detail}</span>
        {meta.tone === "err" && <ShieldAlert className="h-3.5 w-3.5 shrink-0" aria-hidden />}
      </div>
    </div>
  );
}
