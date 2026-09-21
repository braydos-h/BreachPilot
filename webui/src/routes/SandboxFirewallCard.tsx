// Sandbox/Firewall card for /system — one place to see the effective
// containment posture (mode), Docker/image health, firewall enforcement,
// and containment facts. Read-only over GET /system/sandbox (30s staleTime
// via useSandboxStatus); loading/error/empty states render inline and never
// block the other System panels.

import { useState } from "react";
import { RefreshCw, ShieldCheck, Wrench } from "lucide-react";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { SkeletonRows } from "@/components/Loading";
import { useSandboxStatus, type SandboxStatusResponse } from "@/api/hooks";
import { SandboxFixDialog } from "@/routes/HomePage";

type SandboxMode = "disabled" | "contained" | "native_fallback" | "blocked";

function isKnownMode(mode: string): mode is SandboxMode {
  return mode === "disabled" || mode === "contained" || mode === "native_fallback" || mode === "blocked";
}

function ModeBadge({ mode }: { mode: string }) {
  if (!isKnownMode(mode)) {
    return (
      <Badge variant="muted" data-testid="sandbox-mode-badge">
        Unknown
      </Badge>
    );
  }
  if (mode === "contained") {
    return (
      <Badge variant="success" data-testid="sandbox-mode-badge">
        <ShieldCheck className="mr-1 h-3 w-3" />
        Contained
      </Badge>
    );
  }
  if (mode === "disabled") {
    return (
      <Badge variant="muted" data-testid="sandbox-mode-badge">
        Disabled — host execution
      </Badge>
    );
  }
  if (mode === "native_fallback") {
    return (
      <Badge variant="warn" data-testid="sandbox-mode-badge">
        Native fallback — NOT contained
      </Badge>
    );
  }
  return (
    <Badge variant="danger" data-testid="sandbox-mode-badge">
      Blocked — fail closed
    </Badge>
  );
}

function Fact({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-md border p-2">
      <div className="text-[10px] uppercase tracking-wide text-muted-foreground">{label}</div>
      <div className="mt-0.5 truncate font-mono text-sm" title={value}>
        {value}
      </div>
    </div>
  );
}

export function SandboxFirewallCard() {
  const sandbox = useSandboxStatus();
  const [fixOpen, setFixOpen] = useState(false);
  const data = sandbox.data;
  const reason = (data?.fallback_reason || data?.docker_error || "").trim();
  const degraded = !!data && isKnownMode(data.mode) && data.mode !== "contained" && data.mode !== "disabled";

  return (
    <Card data-testid="sandbox-firewall-card">
      <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
        <CardTitle className="text-sm font-semibold">Sandbox / Firewall</CardTitle>
        <Button size="sm" variant="ghost" onClick={() => sandbox.refetch()} disabled={sandbox.isFetching} aria-label="Refresh sandbox status">
          <RefreshCw className={cn("h-3.5 w-3.5", sandbox.isFetching && "animate-spin")} />
        </Button>
      </CardHeader>
      <CardContent className="space-y-3">
        {sandbox.isLoading && <SkeletonRows count={4} />}
        {sandbox.error && (
          <p className="text-sm text-destructive" data-testid="sandbox-firewall-error">
            Failed to load sandbox status.
          </p>
        )}
        {!sandbox.isLoading && !sandbox.error && !data && (
          <p className="text-sm text-muted-foreground" data-testid="sandbox-firewall-empty">
            Sandbox status unavailable.
          </p>
        )}
        {data && <SandboxFirewallBody data={data} reason={reason} degraded={degraded} onFix={() => setFixOpen(true)} />}
      </CardContent>
      <SandboxFixDialog open={fixOpen} onOpenChange={setFixOpen} sandboxReason={reason} />
    </Card>
  );
}

function SandboxFirewallBody({
  data,
  reason,
  degraded,
  onFix,
}: {
  data: SandboxStatusResponse;
  reason: string;
  degraded: boolean;
  onFix: () => void;
}) {
  const imageState = data.image_present === null ? "unknown" : data.image_present ? "built" : "missing";
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <ModeBadge mode={data.mode} />
        <span className="font-mono text-xs text-muted-foreground">mode={data.mode || "—"}</span>
      </div>
      {degraded && reason && (
        <p className="text-xs text-muted-foreground" data-testid="sandbox-fallback-reason">
          Reason: {reason}
        </p>
      )}

      <div>
        <span className="text-xs font-medium uppercase tracking-wide text-muted-foreground">Docker</span>
        <div className="mt-1.5 grid gap-2 sm:grid-cols-3">
          <Fact label="Daemon" value={data.docker_available ? "reachable" : "unreachable"} />
          <Fact
            label="Worker image"
            value={imageState === "unknown" ? "unknown" : imageState === "built" ? `built (${data.image})` : "missing"}
          />
          <Fact label="Error" value={data.docker_error || "—"} />
        </div>
        {data.image_present === false && (
          <div className="mt-2 flex flex-wrap items-center gap-2 rounded-md border border-yellow-500/40 bg-yellow-500/10 p-2 text-xs">
            <span>The worker image is not built — executions fail closed until it exists.</span>
            <Button size="sm" variant="outline" onClick={onFix} className="gap-1.5">
              <Wrench className="h-3.5 w-3.5" />
              Fix sandbox
            </Button>
          </div>
        )}
      </div>

      <div>
        <span className="text-xs font-medium uppercase tracking-wide text-muted-foreground">Firewall / network</span>
        <p className="mt-1 text-xs" data-testid="sandbox-firewall-enforcement">
          {data.network.enforce ? (
            <span className="font-medium text-emerald-300">default-DROP enforced</span>
          ) : (
            <span className="font-medium text-amber-300">NOT enforced — bridge isolation only</span>
          )}
        </p>
        <div className="mt-1.5 grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
          <Fact label="Enforce" value={data.network.enforce ? "yes" : "no"} />
          <Fact label="Fail closed" value={data.network.fail_closed ? "yes" : "no"} />
          <Fact label="DNS policy" value={data.network.allow_dns || "—"} />
          <Fact label="Host loopback" value={data.network.map_host_loopback ? "mapped" : "blocked"} />
        </div>
        <div className="mt-2">
          <Fact
            label="Extra allowed CIDRs"
            value={data.network.extra_allow_cidrs.length > 0 ? data.network.extra_allow_cidrs.join(", ") : "—"}
          />
        </div>
      </div>

      <div>
        <span className="text-xs font-medium uppercase tracking-wide text-muted-foreground">Containment</span>
        <div className="mt-1.5 grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
          <Fact label="Backend" value={data.backend || "—"} />
          <Fact label="Image" value={data.image || "—"} />
          <Fact label="Worker user" value={data.user || "—"} />
          <Fact label="Root filesystem" value={data.read_only_rootfs ? "read-only" : "writable"} />
          <Fact label="Native fallback" value={data.fallback_native ? "allowed" : "fail closed"} />
          <Fact label="Memory" value={`${data.resources.memory_mb} MB`} />
          <Fact label="CPUs" value={String(data.resources.cpus)} />
          <Fact label="PIDs" value={String(data.resources.pids)} />
          <Fact label="Exec timeout" value={`${data.resources.timeout_seconds}s`} />
          <Fact label="Output cap" value={`${(data.resources.output_max_bytes / 1000).toFixed(0)} kB`} />
        </div>
        {data.note && <p className="mt-1.5 text-xs text-muted-foreground">{data.note}</p>}
      </div>
    </div>
  );
}
