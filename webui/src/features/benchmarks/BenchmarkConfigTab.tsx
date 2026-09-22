import { GitCommitHorizontal } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { formatDuration } from "@/features/benchmarks/MetricCards";
import type { BenchmarkRunState } from "./useBenchmarkRun";

export function BenchmarkConfigTab({ page }: { page: BenchmarkRunState }) {
  const { data, env, manifest } = page;
  if (!data || !env) return null;
  return (
    <div className="grid gap-3 lg:grid-cols-2">
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm">Configuration</CardTitle>
        </CardHeader>
        <CardContent>
          <dl className="grid grid-cols-2 gap-y-1.5 text-sm">
            <dt className="text-muted-foreground">Suite</dt>
            <dd className="font-mono text-xs">{data.config.suite}</dd>
            <dt className="text-muted-foreground">Trials</dt>
            <dd className="tabular-nums">{data.config.trials}</dd>
            <dt className="text-muted-foreground">Timeout</dt>
            <dd className="tabular-nums">{formatDuration(data.config.timeout_seconds)}</dd>
            <dt className="text-muted-foreground">Scenarios</dt>
            <dd className="font-mono text-xs">{data.config.scenario_ids.join(", ") || "all"}</dd>
            {data.config.tags.length > 0 && (
              <>
                <dt className="text-muted-foreground">Tags</dt>
                <dd className="font-mono text-xs">{data.config.tags.join(", ")}</dd>
              </>
            )}
            <dt className="text-muted-foreground">Sandbox required</dt>
            <dd>{data.config.sandbox_required ? "yes" : "no"}</dd>
            <dt className="text-muted-foreground">Replay command</dt>
            <dd className="col-span-2 font-mono text-xs text-muted-foreground break-all">
              {manifest?.replay_command ?? "n/a"}
            </dd>
          </dl>
        </CardContent>
      </Card>
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="flex items-center gap-2 text-sm">
            <GitCommitHorizontal className="h-4 w-4" />
            Environment (reproducibility pins)
          </CardTitle>
        </CardHeader>
        <CardContent>
          <dl className="grid grid-cols-2 gap-y-1.5 text-sm">
            <dt className="text-muted-foreground">Git SHA</dt>
            <dd className="font-mono text-xs">
              {env.git_sha}
              {env.git_dirty ? " (dirty)" : ""}
            </dd>
            <dt className="text-muted-foreground">Model</dt>
            <dd className="font-mono text-xs">
              {env.model_provider} / {env.model_id} ({env.model_alias})
            </dd>
            <dt className="text-muted-foreground">Model version</dt>
            <dd className="font-mono text-xs">{env.model_version}</dd>
            <dt className="text-muted-foreground">Config hash</dt>
            <dd className="font-mono text-xs">{env.config_hash}</dd>
            <dt className="text-muted-foreground">Sandbox image</dt>
            <dd className="font-mono text-xs break-all">
              {env.sandbox_image} @ {env.sandbox_image_digest}
            </dd>
            <dt className="text-muted-foreground">Sandbox</dt>
            <dd>
              {env.sandbox_enabled ? "enabled" : "disabled"}
              {env.sandbox_required ? " (required)" : ""}
            </dd>
            <dt className="text-muted-foreground">Platform</dt>
            <dd className="text-xs">
              {env.platform} · Python {env.python_version}
            </dd>
          </dl>
        </CardContent>
      </Card>
    </div>
  );
}
