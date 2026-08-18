import { Radio } from "lucide-react";
import { cn } from "@/lib/utils";
import { StatusBadge } from "@/components/StatusBadge";
import { useLiveModels, useRuns, useSecrets } from "@/api/hooks";
import { useDefaultModel } from "@/components/ProviderSetup";
import { isActiveState, isTerminalState, type RunState } from "@/api/types";

// ponytail: API health is derived from useRuns (polls every 5s) — no extra
// health/capabilities query needed. If runs refetch succeeds, API is up.

export function LiveStatus({ compact = false }: { compact?: boolean }) {
  const runs = useRuns(50, 0);
  const defaultModel = useDefaultModel();
  const live = useLiveModels();
  const secrets = useSecrets();

  const rows = runs.data?.runs ?? [];
  const activeRun = rows.find((r) => isActiveState(r.state));
  const total = rows.length;
  const activeCount = rows.filter((r) => isActiveState(r.state)).length;
  const doneCount = rows.filter((r) => isTerminalState(r.state as RunState)).length;
  const failedCount = rows.filter((r) => r.state === "failed").length;

  const apiOnline = !!runs.data && !runs.error;
  const apiStatus = runs.error ? "offline" : runs.isLoading ? "..." : "online";

  const secretEntries = Object.entries(secrets.data?.keys ?? {});
  const configured = secretEntries.filter(([, s]) => s === "configured").length;
  const secretTotal = secretEntries.length;

  const liveModels = live.data?.models ?? [];
  const liveSource = live.data?.source ?? "—";
  const defaultAlias = defaultModel || "—";

  if (compact) {
    return (
      <div className="flex items-center gap-2 border-b bg-card/30 px-3 py-1.5 text-xs md:hidden">
        <span
          className={cn(
            "h-2 w-2 shrink-0 rounded-full",
            apiOnline ? "bg-emerald-400" : runs.isLoading ? "bg-muted-foreground/50" : "bg-red-400",
          )}
          title={`API ${apiStatus}`}
        />
        <span className="text-muted-foreground">API {apiStatus}</span>
        {activeRun && (
          <>
            <span className="text-muted-foreground">·</span>
            <StatusBadge state={activeRun.state} />
            <span className="truncate font-mono">{activeRun.target || activeRun.target_ip}</span>
          </>
        )}
      </div>
    );
  }

  return (
    <div className="hidden border-b p-3 text-xs md:block">
      <div className="mb-2 flex items-center gap-2">
        <Radio className={cn("h-3.5 w-3.5", apiOnline ? "text-emerald-400" : "text-red-400")} />
        <span className="font-mono uppercase tracking-wide text-muted-foreground">Live status</span>
        <span
          className={cn(
            "ml-auto h-2 w-2 rounded-full",
            apiOnline ? "bg-emerald-400" : runs.isLoading ? "bg-muted-foreground/50" : "bg-red-400",
          )}
          title={`API ${apiStatus}`}
        />
      </div>
      <div className="space-y-1.5">
        <Row label="API" value={apiStatus} ok={apiOnline} />
        <Row label="Runs" value={`${activeCount} active · ${total} total`} />
        <Row label="Done" value={`${doneCount}`} accent={doneCount > 0 ? "emerald" : undefined} />
        <Row label="Failed" value={`${failedCount}`} accent={failedCount > 0 ? "red" : undefined} />
        {activeRun ? (
          <div className="flex flex-col gap-1 rounded-md border bg-muted/20 px-2 py-1.5">
            <div className="flex items-center gap-1.5">
              <span className="text-muted-foreground">Active</span>
              <StatusBadge state={activeRun.state} />
            </div>
            <div className="truncate font-mono text-[11px]">{activeRun.target || activeRun.target_ip}</div>
            <div className="flex items-center gap-2 text-[11px] text-muted-foreground">
              <span>{activeRun.mode}</span>
              <span>·</span>
              <span className="font-mono">{activeRun.model_alias || "—"}</span>
            </div>
            <div className="truncate text-[11px] text-muted-foreground">{activeRun.goal_name || "—"}</div>
          </div>
        ) : (
          <Row label="Active" value="idle" muted />
        )}
        <Row label="Model" value={`${defaultAlias} · ${liveModels.length} live (${liveSource})`} />
        <Row
          label="Keys"
          value={secretTotal ? `${configured}/${secretTotal}` : "—"}
          ok={secretTotal ? configured === secretTotal : undefined}
        />
      </div>
    </div>
  );
}

function Row({
  label,
  value,
  ok,
  muted,
  accent,
}: {
  label: string;
  value: string;
  ok?: boolean;
  muted?: boolean;
  accent?: "emerald" | "red";
}) {
  const valueClass = cn(
    "font-mono tabular-nums",
    muted && "text-muted-foreground",
    ok === true && "text-emerald-300",
    ok === false && "text-red-300",
    accent === "emerald" && "text-emerald-300",
    accent === "red" && "text-red-300",
  );
  return (
    <div className="flex items-center justify-between gap-2">
      <span className="shrink-0 text-muted-foreground">{label}</span>
      <span className={cn("truncate text-right", valueClass)} title={value}>{value}</span>
    </div>
  );
}