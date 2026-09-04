// BreachPilot by @braydos-h — https://github.com/braydos-h/BreachPilot
// Operations overview: one read-only rollup for backends that previously had
// settings toggles but no operational surface (killchain / snapshots / eval /
// browser / provider). Enabling stays in Settings (PATCH /config).
import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { ShieldAlert } from "lucide-react";
import { apiFetch } from "@/api/client";
import { ErrorState } from "@/components/Loading";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";

interface OpsSummary {
  killchain: { enabled: boolean; goal_state: string; require_verification: boolean };
  snapshots: { enabled: boolean; provider: string; counterfactual: boolean };
  eval: { enabled: boolean; baseline_path: string; baseline_exists: boolean };
  browser: { enabled: boolean; backend: string };
  provider: { active: string };
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-center justify-between gap-2 py-1 text-sm">
      <span className="text-muted-foreground">{label}</span>
      <span className="font-mono">{value}</span>
    </div>
  );
}

export function OpsPage() {
  const query = useQuery({
    queryKey: ["ops", "summary"],
    queryFn: () => apiFetch<OpsSummary>("/ops/summary"),
    staleTime: 15_000,
  });

  if (query.isLoading && !query.data) {
    return (
      <div className="space-y-4 p-4">
        <Skeleton className="h-8 w-64" />
        <Skeleton className="h-32 w-full" />
      </div>
    );
  }
  if (query.isError || !query.data) {
    return (
      <div className="p-4">
        <ErrorState message="Could not load operations summary." onRetry={() => void query.refetch()} />
      </div>
    );
  }
  const s = query.data;
  return (
    <div className="space-y-4 p-4">
      <div>
        <h1 className="flex items-center gap-2 text-xl font-semibold">
          <ShieldAlert className="h-5 w-5 text-primary" /> Operations
        </h1>
        <p className="text-sm text-muted-foreground">
          Killchain, snapshots, eval baseline, browser, and provider status. Toggle in{" "}
          <Link to="/system" className="underline underline-offset-4">
            Settings
          </Link>
          .
        </p>
      </div>
      <div className="grid gap-4 md:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Killchain</CardTitle>
            <CardDescription>Evidence-verified stage machine (opt-in)</CardDescription>
          </CardHeader>
          <CardContent>
            <Row label="Enabled" value={String(s.killchain.enabled)} />
            <Row label="Goal" value={s.killchain.goal_state} />
            <Row label="Require verification" value={String(s.killchain.require_verification)} />
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Snapshots</CardTitle>
            <CardDescription>Pre-destructive rollback + counterfactual retry</CardDescription>
          </CardHeader>
          <CardContent>
            <Row label="Enabled" value={String(s.snapshots.enabled)} />
            <Row label="Provider" value={s.snapshots.provider} />
            <Row label="Counterfactual" value={String(s.snapshots.counterfactual)} />
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Eval baseline</CardTitle>
            <CardDescription>Graded harness regression gate</CardDescription>
          </CardHeader>
          <CardContent>
            <Row label="Enabled" value={String(s.eval.enabled)} />
            <Row label="Baseline" value={s.eval.baseline_exists ? "present" : "missing"} />
            <Row label="Path" value={s.eval.baseline_path} />
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Browser + provider</CardTitle>
            <CardDescription>Sandboxed agent + active model provider</CardDescription>
          </CardHeader>
          <CardContent>
            <Row label="Browser" value={`${s.browser.backend} (${String(s.browser.enabled)})`} />
            <Row label="Provider" value={s.provider.active} />
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
