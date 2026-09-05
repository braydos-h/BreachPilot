import { useMemo } from "react";
import { Globe, RefreshCw } from "lucide-react";
import { cn } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { SkeletonRows } from "@/components/Loading";
import { WorkspaceViewer } from "@/components/WorkspaceViewer";
import { useWorkspace } from "@/api/hooks";

interface BrowserTabProps {
  runId: string;
  /** Raw audit records (the parent's audit query — browser_* rows included). */
  records: Array<Record<string, unknown>>;
  loading: boolean;
  error: unknown;
}

type BrowserStatus = "completed" | "blocked" | "started";

export interface BrowserTimelineAction {
  key: string;
  timestamp: string;
  tool: string;
  label: string;
  detail: string;
  status: BrowserStatus;
  sessionId: string;
}

export interface BrowserSessionGroup {
  sessionId: string;
  target: string;
  actions: BrowserTimelineAction[];
}

const TOOL_LABELS: Record<string, string> = {
  browser_start: "Session started",
  browser_navigate: "Navigate",
  browser_observe: "Observe page",
  browser_page_state: "Page state",
  browser_network_events: "Network events",
  browser_storage: "Storage read",
  browser_screenshot: "Screenshot",
  browser_execute_js: "Run JavaScript",
  browser_discover_forms: "Discover forms",
  browser_discover_endpoints: "Discover endpoints",
  browser_close: "Session closed",
  browser_replay: "Replay request",
  browser_submit: "Submit form",
};

const IMAGE_EXTS = new Set(["png", "jpg", "jpeg", "gif", "webp", "svg"]);

function str(value: unknown): string {
  return typeof value === "string" ? value : "";
}

function detailFor(tool: string, args: Record<string, unknown>): string {
  if (tool === "browser_navigate") return str(args.url);
  if (tool === "browser_execute_js") {
    const expr = str(args.expression);
    return expr.length > 160 ? `${expr.slice(0, 160)}…` : expr;
  }
  if (tool === "browser_start") return str(args.target);
  if (tool === "browser_network_events") return typeof args.limit === "number" ? `limit ${args.limit}` : "";
  if (tool === "browser_storage") return str(args.origin);
  return "";
}

function statusOf(record: Record<string, unknown>): BrowserStatus {
  if (record.status === "blocked" || record.approved === false) return "blocked";
  if (record.status === "completed") return "completed";
  return "started";
}

/** Collapse started/completed audit pairs; group by browser session. Pure (unit-testable). */
export function groupBrowserActivity(records: Array<Record<string, unknown>>): BrowserSessionGroup[] {
  const byCall = new Map<string, Record<string, unknown>>();
  for (const record of records) {
    const tool = str(record.tool_name);
    if (!tool.startsWith("browser_")) continue;
    const args = (record.args ?? {}) as Record<string, unknown>;
    const sessionId = str(args.session_id) || "(ad hoc)";
    byCall.set(`${tool}|${sessionId}|${JSON.stringify(args)}`, record);
  }
  const groups = new Map<string, BrowserSessionGroup>();
  for (const record of byCall.values()) {
    const tool = str(record.tool_name);
    const args = (record.args ?? {}) as Record<string, unknown>;
    const sessionId = str(args.session_id) || "(ad hoc)";
    const timestamp = str(record.timestamp);
    const action: BrowserTimelineAction = {
      key: `${timestamp}|${tool}|${JSON.stringify(args)}`,
      timestamp,
      tool,
      label: TOOL_LABELS[tool] ?? tool,
      detail: detailFor(tool, args),
      status: statusOf(record),
      sessionId,
    };
    let group = groups.get(sessionId);
    if (!group) {
      group = { sessionId, target: str(args.target) || str(record.target_ip), actions: [] };
      groups.set(sessionId, group);
    }
    if (!group.target) group.target = str(args.target) || str(record.target_ip);
    group.actions.push(action);
  }
  const ordered = [...groups.values()];
  for (const group of ordered) group.actions.sort((a, b) => (a.timestamp < b.timestamp ? -1 : 1));
  ordered.sort((a, b) => {
    const ta = a.actions[0]?.timestamp ?? "";
    const tb = b.actions[0]?.timestamp ?? "";
    return ta < tb ? -1 : 1;
  });
  return ordered;
}

/** Workspace screenshot paths grouped by browser session. Pure (unit-testable). */
export function groupBrowserScreenshots(files: Array<{ path: string }>): Map<string, string[]> {
  const grouped = new Map<string, string[]>();
  for (const file of files) {
    const segments = file.path.split("/");
    if (segments[0] !== "browser" || segments.length < 2) continue;
    const ext = ((segments[segments.length - 1] ?? "").split(".").pop() ?? "").toLowerCase();
    if (!IMAGE_EXTS.has(ext)) continue;
    const sessionId = segments[1] ?? "";
    const list = grouped.get(sessionId) ?? [];
    list.push(file.path);
    grouped.set(sessionId, list);
  }
  for (const list of grouped.values()) list.sort();
  return grouped;
}

function shortTime(iso: string): string {
  return iso.length >= 19 ? iso.slice(11, 19) : iso || "—";
}

export function BrowserTab({ runId, records, loading, error }: BrowserTabProps) {
  const workspace = useWorkspace(runId);

  const sessions = useMemo(() => groupBrowserActivity(records), [records]);
  const shotsBySession = useMemo(
    () => groupBrowserScreenshots((workspace.data?.files ?? []) as Array<{ path: string }>),
    [workspace.data],
  );

  const actionCount = useMemo(() => sessions.reduce((n, s) => n + s.actions.length, 0), [sessions]);
  const shotCount = useMemo(() => [...shotsBySession.values()].reduce((n, list) => n + list.length, 0), [shotsBySession]);
  const blockedCount = useMemo(
    () => sessions.reduce((n, s) => n + s.actions.filter((a) => a.status === "blocked").length, 0),
    [sessions],
  );

  if (loading) return <SkeletonRows count={3} />;
  if (error) return <div className="text-sm text-destructive">Failed to load browser activity.</div>;

  if (sessions.length === 0 && shotCount === 0) {
    return (
      <div className="flex flex-col items-center gap-2 py-8 text-center">
        <Globe className="h-6 w-6 text-muted-foreground" />
        <p className="text-sm font-medium">No browser activity in this run yet</p>
        <p className="max-w-md text-xs text-muted-foreground">
          When the agent drives Chromium (browser_start → navigate → observe …), its sessions, navigations, and
          screenshots appear here. Requires browser.enabled with the Playwright backend.
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
        <Badge variant="success">{sessions.length} session{sessions.length === 1 ? "" : "s"}</Badge>
        <Badge variant="success">{actionCount} action{actionCount === 1 ? "" : "s"}</Badge>
        <Badge variant="success">{shotCount} screenshot{shotCount === 1 ? "" : "s"}</Badge>
        {blockedCount > 0 && <Badge variant="danger">{blockedCount} blocked</Badge>}
        <div className="ml-auto">
          <Button size="sm" variant="ghost" onClick={() => workspace.refetch()} disabled={workspace.isFetching}>
            <RefreshCw className={cn("h-3.5 w-3.5", workspace.isFetching && "animate-spin")} />
          </Button>
        </div>
      </div>

      {sessions.map((session) => (
        <section key={session.sessionId} aria-label={`Browser session ${session.sessionId}`} className="space-y-2 rounded-md border p-3">
          <div className="flex flex-wrap items-center gap-2">
            <Globe className="h-4 w-4 text-primary" />
            <span className="font-mono text-xs font-medium">{session.sessionId}</span>
            {session.target && <span className="font-mono text-xs text-muted-foreground">target {session.target}</span>}
          </div>
          <ul className="space-y-1">
            {session.actions.map((action) => (
              <li key={action.key} className="flex items-start gap-2 text-xs">
                <span className="shrink-0 font-mono text-muted-foreground">{shortTime(action.timestamp)}</span>
                <Badge
                  variant={action.status === "blocked" ? "danger" : action.status === "completed" ? "success" : "warn"}
                >
                  {action.status === "blocked" ? "blocked" : action.status === "completed" ? "done" : "started"}
                </Badge>
                <span className="shrink-0 font-medium">{action.label}</span>
                {action.detail && (
                  <span className="min-w-0 truncate font-mono text-muted-foreground" title={action.detail}>
                    {action.detail}
                  </span>
                )}
              </li>
            ))}
          </ul>
          {(shotsBySession.get(session.sessionId) ?? []).length > 0 && (
            <div className="grid gap-2 sm:grid-cols-2">
              {(shotsBySession.get(session.sessionId) ?? []).map((path) => (
                <WorkspaceViewer key={path} runId={runId} path={path} />
              ))}
            </div>
          )}
        </section>
      ))}

      {[...shotsBySession.entries()]
        .filter(([sessionId]) => !sessions.some((s) => s.sessionId === sessionId))
        .map(([sessionId, paths]) => (
          <section key={sessionId} aria-label={`Browser screenshots ${sessionId}`} className="space-y-2 rounded-md border p-3">
            <div className="flex items-center gap-2">
              <Globe className="h-4 w-4 text-primary" />
              <span className="font-mono text-xs font-medium">{sessionId}</span>
              <span className="text-xs text-muted-foreground">(screenshots only — session rows aged out of audit)</span>
            </div>
            <div className="grid gap-2 sm:grid-cols-2">
              {paths.map((path) => (
                <WorkspaceViewer key={path} runId={runId} path={path} />
              ))}
            </div>
          </section>
        ))}
    </div>
  );
}
