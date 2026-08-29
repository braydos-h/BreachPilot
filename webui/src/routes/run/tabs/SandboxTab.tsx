import { Container, ShieldAlert, ShieldCheck } from "lucide-react";
import { cn } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";
import { SkeletonRows } from "@/components/Loading";
import type { RunSandboxResponse } from "@/api/types";

interface SandboxTabProps {
  loading: boolean;
  error: unknown;
  data: RunSandboxResponse | undefined;
}

export function SandboxTab({ loading, error, data }: SandboxTabProps) {
  if (loading) return <SkeletonRows count={3} />;
  if (error) return <div className="text-sm text-destructive">Failed to load sandbox info.</div>;
  if (!data || !data.found) {
    return (
      <p className="text-sm text-muted-foreground">
        No sandbox activity recorded for this run — attack commands either never executed or ran in disabled (host)
        mode.
      </p>
    );
  }

  const exec = data.executions;
  const network = data.network;

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <Badge variant="success">
          <ShieldCheck className="mr-1 h-3 w-3" />
          Contained ({data.config.backend ?? "docker"})
        </Badge>
        {data.blocked.total > 0 && (
          <Badge variant="danger">
            <ShieldAlert className="mr-1 h-3 w-3" />
            {data.blocked.total} blocked
          </Badge>
        )}
        <span className="text-xs text-muted-foreground">
          {exec.total} execution{exec.total === 1 ? "" : "s"} ·{" "}
          {exec.failed + exec.timed_out > 0
            ? `${exec.failed} failed, ${exec.timed_out} timed out`
            : "no failures"}
        </span>
      </div>

      <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
        <Stat label="Image" value={data.config.image ?? "—"} />
        <Stat label="Worker user" value={data.config.user ?? "—"} />
        <Stat label="Container" value={data.container.id ? data.container.id.slice(0, 12) : "—"} />
        <Stat label="Last activity" value={data.last_activity || "—"} />
        <Stat label="Completed" value={String(exec.completed)} />
        <Stat label="Failed" value={String(exec.failed)} />
        <Stat label="Timed out" value={String(exec.timed_out)} />
        <Stat label="Blocked results" value={String(data.blocked.total)} />
      </div>

      <div className="rounded-md border p-2">
        <div className="mb-1.5 flex items-center gap-1.5 text-xs font-medium uppercase tracking-wide text-muted-foreground">
          <Container className="h-3.5 w-3.5" />
          Network policy
        </div>
        <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
          <Stat label="Firewall" value={network.enforced ? "locked (default drop)" : "not enforced"} />
          <Stat label="DNS" value={network.allow_dns ?? "—"} />
          <Stat
            label="Authorized destinations"
            value={(network.authorized_destinations ?? []).join(", ") || "—"}
          />
          <Stat
            label="Explicitly blocked"
            value={(network.explicitly_blocked ?? []).join(", ") || "—"}
          />
          <div className="sm:col-span-2">
            <Stat
              label="Resolved domains"
              value={
                Object.entries(network.resolved_domains ?? {})
                  .map(([d, ip]) => `${d} -> ${ip}`)
                  .join(", ") || "—"
              }
            />
          </div>
          <div className="sm:col-span-2">
            <Stat
              label="Unresolved targets"
              value={(network.unresolved_targets ?? []).join(", ") || "—"}
            />
          </div>
        </div>
        {network.fingerprint && (
          <p className="mt-1.5 truncate font-mono text-[10px] text-muted-foreground" title={network.fingerprint}>
            policy fingerprint {network.fingerprint}
          </p>
        )}
      </div>

      <div>
        <div className="mb-1.5 flex items-center justify-between">
          <span className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
            Recent blocked commands
          </span>
          <span className="text-xs text-muted-foreground">full history in the Audit tab</span>
        </div>
        {(data.blocked.recent ?? []).length === 0 ? (
          <p className="text-sm text-muted-foreground">No SANDBOX_* blocks in this run.</p>
        ) : (
          <div className="overflow-x-auto rounded-md border">
            <table className="w-full border-collapse text-xs">
              <caption className="sr-only">Recent sandbox-blocked commands</caption>
              <thead>
                <tr>
                  {["time", "tool", "code", "reason"].map((h) => (
                    <th key={h} scope="col" className="border-b p-2 text-left font-semibold">
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {data.blocked.recent.map((b, i) => (
                  <tr key={i} className="even:bg-muted/20">
                    <td className="border-b p-2 font-mono whitespace-nowrap">{formatTime(b.timestamp)}</td>
                    <td className="border-b p-2 font-mono">{b.tool || "—"}</td>
                    <td className="border-b p-2">
                      <Badge variant="danger">{b.code}</Badge>
                    </td>
                    <td className="max-w-[420px] break-words border-b p-2">{b.message || "—"}</td>
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
      <div className={cn("mt-0.5 truncate font-mono text-sm")} title={value}>
        {value}
      </div>
    </div>
  );
}

function formatTime(ts: string): string {
  if (!ts) return "—";
  const d = new Date(ts);
  return Number.isNaN(d.getTime()) ? ts : d.toLocaleTimeString();
}
