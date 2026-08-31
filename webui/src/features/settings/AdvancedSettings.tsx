// Advanced: system information, sandbox, diagnostics, LLM usage, the raw/advanced
// config (unknown fields surface here with their raw keys), and the Danger
// Zone at the very bottom.

import { useState } from "react";
import { Loader2, RefreshCw, ShieldCheck, Stethoscope, Wrench } from "lucide-react";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { SettingsSection } from "./SettingsSection";
import { ConfigEditor } from "./ConfigEditor";
import { DangerZone } from "./DangerZone";
import { useDiagnostics, useSandboxStatus, useSystemInfo, useTelemetry } from "@/api/hooks";
import { ApiError } from "@/api/client";
import { formatRelative } from "@/lib/utils";
import { SkeletonRows } from "@/components/Loading";
import type { DiagnosticsResponse } from "@/api/types";

export function AdvancedSettings() {
  return (
    <div className="space-y-4">
      <div className="rounded-xl border border-amber-500/20 bg-amber-500/5 px-5 py-3 text-xs leading-relaxed text-muted-foreground">
        Technical settings for operators who need fine control. Most daily use does not require changes here. If you are
        unsure, leave these at their defaults.
      </div>
      <SettingsSection title="System information" description="Host details for this daemon.">
        <SystemInfo />
      </SettingsSection>
      <SettingsSection
        title="Sandbox"
        description="Disposable Docker worker that contains every attack command. Read-only status; no Docker controls."
      >
        <SandboxPanel />
      </SettingsSection>
      <SettingsSection title="Diagnostics" description="Run the doctor or self-test.">
        <Diagnostics />
      </SettingsSection>
      <SettingsSection title="Usage" description="LLM telemetry.">
        <TelemetryTable />
      </SettingsSection>
      <ConfigEditor category="advanced" />
      <DangerZone />
    </div>
  );
}

function SandboxPanel() {
  const sandbox = useSandboxStatus();
  const data = sandbox.data;

  return (
    <div className="space-y-3 py-3">
      <div className="flex items-center justify-between">
        <span className="text-xs font-medium uppercase tracking-wide text-muted-foreground">Worker containment</span>
        <Button size="sm" variant="ghost" onClick={() => sandbox.refetch()} disabled={sandbox.isFetching}>
          <RefreshCw className={cn("h-3.5 w-3.5", sandbox.isFetching && "animate-spin")} />
        </Button>
      </div>
      {sandbox.isLoading && <SkeletonRows count={4} className="p-2" />}
      {sandbox.error && <div className="text-sm text-destructive">Failed to load sandbox status.</div>}
      {data && (
        <>
          <div className="flex flex-wrap items-center gap-2">
            {data.enabled ? (
              data.docker_available ? (
                data.image_present === false ? (
                  <Badge variant="warn">Image missing</Badge>
                ) : (
                  <Badge variant="success">
                    <ShieldCheck className="mr-1 h-3 w-3" />
                    Contained ({data.backend})
                  </Badge>
                )
              ) : (
                <Badge variant="danger">Docker unreachable</Badge>
              )
            ) : (
              <Badge variant="warn">Disabled (host exec)</Badge>
            )}
            {data.docker_error && <span className="text-xs text-muted-foreground">{data.docker_error}</span>}
          </div>
          {data.enabled && data.image_present === false && (
            <div className="rounded-md border border-yellow-500/40 bg-yellow-500/10 p-2 text-xs">
              <p>The worker image is not built — every attack command will be blocked (fail closed).</p>
              <pre className="mt-1 overflow-x-auto font-mono text-xs scrollbar-thin">
                docker build -t {data.image} docker/sandbox
              </pre>
            </div>
          )}
          <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
            <Stat label="Image" value={data.image} />
            <Stat label="Worker user" value={data.user || "—"} />
            <Stat label="Root filesystem" value={data.read_only_rootfs ? "read-only" : "writable"} />
            <Stat label="DNS policy" value={data.network.allow_dns || "—"} />
            <Stat label="Memory" value={`${data.resources.memory_mb} MB`} />
            <Stat label="CPUs" value={String(data.resources.cpus)} />
            <Stat label="PIDs" value={String(data.resources.pids)} />
            <Stat label="Exec timeout" value={`${data.resources.timeout_seconds}s`} />
            <Stat label="Output cap" value={`${(data.resources.output_max_bytes / 1000).toFixed(0)} kB`} />
            <Stat label="Network enforce" value={data.network.enforce ? "iptables lock" : "off"} />
            <Stat label="Fail closed" value={data.network.fail_closed ? "yes" : "no"} />
            <Stat label="Host loopback" value={data.network.map_host_loopback ? "mapped" : "blocked"} />
            <div className="sm:col-span-2">
              <Stat
                label="Extra allowed CIDRs"
                value={data.network.extra_allow_cidrs.length > 0 ? data.network.extra_allow_cidrs.join(", ") : "—"}
              />
            </div>
            <div className="sm:col-span-2">
              <Stat
                label="Cleanup"
                value={
                  [
                    data.cleanup.remove_on_exit ? "remove on exit" : null,
                    data.cleanup.remove_stale_on_startup ? "stale sweep on startup" : null,
                  ]
                    .filter(Boolean)
                    .join(" · ") || "—"
                }
              />
            </div>
          </div>
          {data.note && <p className="text-xs text-muted-foreground">{data.note}</p>}
        </>
      )}
    </div>
  );
}

function SystemInfo() {
  const info = useSystemInfo();
  return (
    <div className="py-3">
      <div className="flex items-center justify-between">
        <span className="text-xs font-medium uppercase tracking-wide text-muted-foreground">Host</span>
        <Button size="sm" variant="ghost" onClick={() => info.refetch()} disabled={info.isFetching}>
          <RefreshCw className={cn("h-3.5 w-3.5", info.isFetching && "animate-spin")} />
        </Button>
      </div>
      {info.isLoading && <SkeletonRows count={4} className="p-2" />}
      {info.error && <div className="text-sm text-destructive">Failed to load system info.</div>}
      {info.data && (
        <div className="mt-2 grid gap-2 sm:grid-cols-2">
          <Stat label="Hostname" value={info.data.hostname} />
          <Stat label="Public IP" value={info.data.public_ip ?? "unavailable"} />
          <Stat label="OS" value={info.data.os} />
          <Stat label="Python" value={info.data.python} />
          <div className="sm:col-span-2">
            <Stat label="Platform" value={info.data.platform} />
          </div>
          <div className="sm:col-span-2">
            <Stat label="Local IPs" value={info.data.local_ips.join(", ") || "—"} />
          </div>
        </div>
      )}
    </div>
  );
}

function Diagnostics() {
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
    <div className="space-y-3 py-3">
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
          <Badge variant={result.exit_code === 0 ? "success" : "danger"}>exit {result.exit_code}</Badge>
          <pre className="max-h-[60vh] overflow-auto rounded-md border bg-muted/30 p-3 font-mono text-xs whitespace-pre-wrap break-words scrollbar-thin">
            {result.output || "(no output)"}
          </pre>
        </div>
      )}
    </div>
  );
}

function TelemetryTable() {
  const telemetry = useTelemetry();
  const summary = telemetry.data?.summary;
  const recent = telemetry.data?.recent ?? [];

  return (
    <div className="space-y-3 py-3">
      <div className="flex items-center justify-between">
        <span className="text-xs font-medium uppercase tracking-wide text-muted-foreground">LLM usage</span>
        <Button size="sm" variant="ghost" onClick={() => telemetry.refetch()} disabled={telemetry.isFetching}>
          <RefreshCw className={cn("h-3.5 w-3.5", telemetry.isFetching && "animate-spin")} />
        </Button>
      </div>
      {telemetry.isLoading && <SkeletonRows count={3} className="p-2" />}
      {telemetry.error && <div className="text-sm text-destructive">Failed to load telemetry.</div>}
      {summary && (
        <div className="grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-4">
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
      <div>
        <span className="text-xs font-medium uppercase tracking-wide text-muted-foreground">Recent calls</span>
        {recent.length === 0 && <p className="mt-1 text-sm text-muted-foreground">No LLM calls recorded yet.</p>}
        {recent.length > 0 && (
          <div className="mt-1.5 overflow-x-auto rounded-md border">
            <table className="w-full border-collapse text-xs">
              <caption className="sr-only">Recent LLM calls</caption>
              <thead>
                <tr>
                  {["alias", "model", "source", "tokens", "tok/s", "ctx %", "duration", "error"].map((h) => (
                    <th key={h} scope="col" className="border-b p-2 text-left font-semibold">
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {recent.map((r, i) => (
                  <tr key={i} className="even:bg-muted/20">
                    <td className="border-b p-2 font-mono">{r.alias ?? "—"}</td>
                    <td className="max-w-[200px] truncate border-b p-2 font-mono" title={String(r.model_id ?? "")}>
                      {r.model_id ?? "—"}
                    </td>
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
      </div>
    </div>
  );
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-md border p-2">
      <div className="text-[10px] uppercase tracking-wide text-muted-foreground">{label}</div>
      <div className="mt-0.5 truncate font-mono text-sm" title={value}>
        {value}
      </div>
    </div>
  );
}
