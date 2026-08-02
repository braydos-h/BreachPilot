import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { Loader2, Plus, RotateCw, Trash2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { StatusBadge } from "@/components/StatusBadge";
import { CopyButton } from "@/components/CopyButton";
import { useDeleteRun, useResumeRun, useRuns } from "@/api/hooks";
import { ApiError } from "@/api/client";
import { isActiveState, isTerminalState, type RunState } from "@/api/types";
import { formatRelative, truncateId } from "@/lib/utils";

export function RunListPage() {
  const runs = useRuns(50, 0);
  const deleteRun = useDeleteRun();
  const resumeRun = useResumeRun();
  const navigate = useNavigate();
  const [pendingDelete, setPendingDelete] = useState<string | null>(null);
  const [resumeTarget, setResumeTarget] = useState<string | null>(null);

  const rows = runs.data?.runs ?? [];
  const activeRun = rows.find((r) => isActiveState(r.state));

  const onDelete = (runId: string) => {
    if (!window.confirm(`Permanently delete run ${runId} and all of its artifacts?`)) return;
    setPendingDelete(runId);
    deleteRun.mutate(
      { runId, purge: true },
      {
        onSettled: () => setPendingDelete(null),
      },
    );
  };

  const onResume = (runId: string) => {
    setResumeTarget(runId);
    resumeRun.mutate(runId, {
      onSuccess: (data) => navigate(`/runs/${data.run_id}`),
      onSettled: () => setResumeTarget(null),
    });
  };

  return (
    <div className="space-y-4 p-4 md:p-6">
      <div className="flex items-center justify-between gap-2">
        <h1 className="text-lg font-semibold">Sessions</h1>
        <div className="flex items-center gap-2">
          {runs.isFetching && <Loader2 className="h-3.5 w-3.5 animate-spin text-muted-foreground" />}
          <Button asChild size="sm" disabled={!!activeRun}>
            <Link to="/runs/new">
              <Plus className="h-4 w-4" />
              New run
            </Link>
          </Button>
        </div>
      </div>

      {activeRun && (
        <Card className="border-yellow-500/40 bg-yellow-500/5">
          <CardContent className="flex flex-wrap items-center gap-2 p-3 text-sm">
            <Badge variant="outline" className="border-yellow-500/40 text-yellow-300">Active</Badge>
            <span className="truncate font-mono text-xs">{activeRun.target}</span>
            <StatusBadge state={activeRun.state} />
            <Button asChild size="sm" variant="outline" className="ml-auto">
              <Link to={`/runs/${activeRun.id}`}>Open</Link>
            </Button>
          </CardContent>
        </Card>
      )}

      {runs.isLoading && <div className="text-sm text-muted-foreground">Loading runs...</div>}
      {runs.error && (
        <div className="text-sm text-destructive">
          {runs.error instanceof ApiError ? runs.error.message : "Failed to load runs."}
        </div>
      )}

      {!runs.isLoading && rows.length === 0 && !activeRun && (
        <div className="rounded-md border border-dashed p-8 text-center text-sm text-muted-foreground">
          No past sessions yet.{" "}
          <Link to="/" className="text-foreground underline-offset-4 hover:underline">Start one from home.</Link>
        </div>
      )}

      {rows.length > 0 && (
        <div className="overflow-x-auto rounded-md border">
          <table className="w-full border-collapse text-sm">
            <thead className="bg-muted/50 text-xs uppercase tracking-wide text-muted-foreground">
              <tr>
                <th className="p-2 text-left">ID</th>
                <th className="p-2 text-left">State</th>
                <th className="p-2 text-left">Target</th>
                <th className="p-2 text-left">Mode</th>
                <th className="p-2 text-left">Goal</th>
                <th className="p-2 text-left">Model</th>
                <th className="p-2 text-left">Created</th>
                <th className="p-2 text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => {
                const active = isActiveState(row.state);
                const terminal = isTerminalState(row.state as RunState);
                return (
                  <tr key={row.id} className="border-t hover:bg-muted/20">
                    <td className="p-2">
                      <div className="flex items-center gap-1.5">
                        <Link to={`/runs/${row.id}`} className="font-mono text-xs hover:underline" title={row.id}>
                          {truncateId(row.id)}
                        </Link>
                        <CopyButton value={row.id} size="icon" label="Copy ID" />
                      </div>
                    </td>
                    <td className="p-2"><StatusBadge state={row.state} /></td>
                    <td className="p-2 font-mono text-xs">{row.target || row.target_ip || "\u2014"}</td>
                    <td className="p-2 text-xs">{row.mode}</td>
                    <td className="p-2 text-xs">{row.goal_name || "\u2014"}</td>
                    <td className="p-2 font-mono text-xs">{row.model_alias || "\u2014"}</td>
                    <td className="p-2 text-xs text-muted-foreground" title={row.created_at}>{formatRelative(row.created_at)}</td>
                    <td className="p-2 text-right">
                      <div className="inline-flex items-center gap-1">
                        <Button asChild size="sm" variant="ghost">
                          <Link to={`/runs/${row.id}`}>Open</Link>
                        </Button>
                        {terminal && (
                          <Button
                            size="sm"
                            variant="ghost"
                            onClick={() => onResume(row.id)}
                            disabled={resumeTarget === row.id}
                            aria-label="Resume run"
                          >
                            {resumeTarget === row.id ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <RotateCw className="h-3.5 w-3.5" />}
                          </Button>
                        )}
                        <Button
                          size="sm"
                          variant="ghost"
                          onClick={() => onDelete(row.id)}
                          disabled={active || pendingDelete === row.id}
                          aria-label="Delete run"
                          className="text-muted-foreground hover:text-destructive"
                        >
                          {pendingDelete === row.id ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Trash2 className="h-3.5 w-3.5" />}
                        </Button>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
