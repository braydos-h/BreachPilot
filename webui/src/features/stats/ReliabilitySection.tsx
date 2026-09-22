// BreachPilot by @braydos-h — https://github.com/braydos-h/BreachPilot
// Stats page "Evaluation reliability" section: verified rates over
// capability counts, sourced live from the benchmark baseline (never
// hardcoded, never invented — missing baseline renders as missing).
import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { AlertTriangle, CheckCircle2, ListChecks, ShieldCheck } from "lucide-react";
import { fetchOverview } from "@/features/benchmarks/api";
import { formatPct as formatBenchmarkPct } from "@/features/benchmarks/format";
import { StatCard } from "./StatCard";
import { UnavailableCard } from "./StatsStates";

function formatRate01(value: number | null | undefined): string {
  // Benchmark rates are 0..1 fractions; the stats formatPercent takes 0..100.
  if (value == null || !Number.isFinite(value)) return "n/a";
  return formatBenchmarkPct(value);
}

export function ReliabilitySection() {
  const reliability = useQuery({
    queryKey: ["benchmarks", "overview"],
    queryFn: fetchOverview,
    staleTime: 30_000,
    gcTime: 5 * 60_000,
    refetchOnWindowFocus: false,
    retry: false,
  });
  const baseline = reliability.data?.baseline;
  const loading = reliability.isLoading && !reliability.data;

  return (
    <section aria-labelledby="eval-reliability-heading" className="space-y-3">
      <div className="flex flex-wrap items-end justify-between gap-2">
        <div>
          <h2 id="eval-reliability-heading" className="text-sm font-semibold">Evaluation reliability</h2>
          <p className="text-xs text-muted-foreground">
            Verified rates over capability counts — live baseline, full runs in{" "}
            <Link to="/benchmarks" className="text-primary underline-offset-4 hover:underline">Benchmarks</Link>,
            methodology in <span className="font-mono">docs/reliability-metrics.md</span>.
          </p>
        </div>
        {baseline?.run_id && (
          <Link to={`/benchmarks/${baseline.run_id}`} className="font-mono text-[11px] underline-offset-4 hover:underline">
            {baseline.run_id}
          </Link>
        )}
      </div>

      {reliability.error && !reliability.data && (
        <UnavailableCard title="Evaluation reliability unavailable" message="The benchmark baseline could not be loaded. Retry when the API is available." />
      )}

      {(loading || baseline) && (
        <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
          <StatCard
            icon={CheckCircle2}
            label="Verified success"
            value={baseline && baseline.exists ? formatRate01(baseline.verified_success_rate) : "—"}
            sub={baseline?.exists ? "baseline verified rate" : "No baseline saved yet"}
            tone="success"
            loading={loading}
            available={Boolean(baseline?.exists)}
          />
          <StatCard
            icon={AlertTriangle}
            label="False positives"
            value={baseline && baseline.exists ? formatRate01(baseline.false_positive_rate) : "—"}
            sub={baseline?.exists ? "claimed but unverified" : "No baseline saved yet"}
            tone={baseline?.exists && (baseline.false_positive_rate ?? 0) > 0 ? "danger" : "success"}
            loading={loading}
            available={Boolean(baseline?.exists)}
          />
          <StatCard
            icon={ShieldCheck}
            label="Scope violations"
            value={baseline?.exists && typeof baseline.scope_violation_count === "number" ? String(baseline.scope_violation_count) : "—"}
            sub="reaching network layer (must be 0)"
            tone={
              !baseline?.exists || typeof baseline.scope_violation_count !== "number"
                ? "neutral"
                : baseline.scope_violation_count > 0
                  ? "danger"
                  : "success"
            }
            loading={loading}
            available={Boolean(baseline?.exists)}
          />
          <StatCard
            icon={ListChecks}
            label="Reproduced twice"
            value={baseline && baseline.exists ? formatRate01(baseline.reproduced_twice_rate) : "—"}
            sub={baseline?.exists ? "scenarios verified on ≥2 trials" : "No baseline saved yet"}
            tone="neutral"
            loading={loading}
            available={Boolean(baseline?.exists)}
          />
        </div>
      )}

      {reliability.data && !baseline?.exists && !loading && (
        <p className="text-xs text-muted-foreground">
          No evaluation baseline yet — save one with <span className="font-mono">python main.py --benchmark xben --trials 5</span> then{" "}
          <span className="font-mono">--save-baseline</span>; rates appear here once measured.
        </p>
      )}
    </section>
  );
}
