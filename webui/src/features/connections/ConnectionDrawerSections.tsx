import { Link } from "react-router-dom";
import { DetailRow } from "./ConnectionBits";
import { formatAge, formatBeacon, formatIsoOrRelative, formatLastCheck, humanizeMethod } from "./connectionFormat";
import type { ConnectionDrawerState } from "./useConnectionDrawer";

export function ConnectionIdentitySection({ drawer }: { drawer: ConnectionDrawerState }) {
  const { conn } = drawer;
  if (!conn) return null;
  return (
    <section className="space-y-3">
      <h3 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">Identity</h3>
      <div className="grid gap-px overflow-hidden rounded-lg border bg-border">
        <DetailRow label="Target" value={conn.target_ip} mono copyValue={conn.target_ip} />
        <DetailRow label="Connection" value={conn.connection_id} mono copyValue={conn.connection_id} />
        <DetailRow label="Method" value={humanizeMethod(conn.method)} sub={conn.method} />
        <DetailRow label="OS" value={conn.os_family || "Unknown"} />
        <DetailRow label="MITRE Technique" value={conn.mitre_technique || "—"} mono={!!conn.mitre_technique} />
        <DetailRow label="Implant Path" value={conn.implant_path || "—"} mono copyValue={conn.implant_path || undefined} />
        {conn.notes && <DetailRow label="Notes" value={conn.notes} />}
      </div>
    </section>
  );
}

export function ConnectionProvenanceSection({ drawer }: { drawer: ConnectionDrawerState }) {
  const { conn } = drawer;
  if (!conn) return null;
  return (
    <section className="space-y-3">
      <h3 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">Provenance</h3>
      <div className="rounded-lg border bg-card/40 p-3 text-[13px]">
        {(() => {
          const hay = `${conn.notes ?? ""} ${conn.implant_path ?? ""}`;
          const m = hay.match(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[0-9a-f]{8,}/i);
          if (m) {
            const runId = m[0];
            return (
              <span>
                Created by run{" "}
                <Link to={`/runs/${runId}`} className="font-mono text-primary hover:underline">
                  {runId.slice(0, 8)}
                </Link>{" "}
                · <Link to={`/runs/${runId}?tab=evidence`} className="text-primary hover:underline">Open findings</Link>
              </span>
            );
          }
          return (
            <span className="text-muted-foreground">
              Provenance not recorded — created outside a linked run. See{" "}
              <Link to="/runs" className="text-primary hover:underline">
                Runs
              </Link>
              .
            </span>
          );
        })()}
      </div>
    </section>
  );
}

export function ConnectionNetworkSection({ drawer }: { drawer: ConnectionDrawerState }) {
  const { conn } = drawer;
  if (!conn) return null;
  return (
    <section className="space-y-3">
      <h3 className="text-[11px] font-semibold uppercase tracking-wide text-muted-foreground">Network</h3>
      <div className="grid gap-px overflow-hidden rounded-lg border bg-border">
        <DetailRow
          label="Callback"
          value={`${conn.callback_host}:${conn.callback_port}`}
          mono
          copyValue={`${conn.callback_host}:${conn.callback_port}`}
        />
        <DetailRow label="Listener" value={conn.listener_name || "—"} mono copyValue={conn.listener_name} />
      </div>
    </section>
  );
}

export function ConnectionTimelineSection({ drawer }: { drawer: ConnectionDrawerState }) {
  const { conn } = drawer;
  if (!conn) return null;
  return (
    <section className="space-y-3">
      <h3 className="text-[11px] font-semibold uppercase tracking-wide text-muted-foreground">Timeline</h3>
      <div className="grid gap-px overflow-hidden rounded-lg border bg-border">
        <DetailRow
          label="Created"
          value={formatIsoOrRelative(conn.created_at, conn.created_at_iso)}
          sub={`${formatAge(conn.created_at)} ago`}
        />
        <DetailRow
          label="Last Beacon"
          value={conn.last_beacon ? formatIsoOrRelative(conn.last_beacon, conn.last_beacon_iso) : "Never"}
          sub={formatBeacon(conn.last_beacon)}
        />
        <DetailRow
          label="Last Health Check"
          value={conn.last_check ? formatIsoOrRelative(conn.last_check, conn.last_check_iso) : "Never"}
          sub={conn.last_check ? formatLastCheck(conn.last_check) : undefined}
        />
      </div>
      {conn.check_output && (
        <div className="space-y-1">
          <span className="text-[10px] font-medium uppercase tracking-wide text-muted-foreground">
            Last check output
          </span>
          <pre className="max-h-28 overflow-auto rounded-md border bg-muted/40 p-2 font-mono text-xs leading-relaxed whitespace-pre-wrap break-words scrollbar-thin">
            {conn.check_output}
          </pre>
        </div>
      )}
    </section>
  );
}
