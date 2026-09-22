import { useEffect, useMemo, useState } from "react";
import { useParams } from "react-router-dom";
import { keepPreviousData, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "@/hooks/use-toast";
import {
  cancelBenchmarkRun,
  fetchOverview,
  fetchRun,
  fetchRunEvents,
  fetchRunScenarios,
  saveBaseline,
} from "@/features/benchmarks/api";
import { isActiveState, isOrphanedRun, runStatusToBadge } from "@/features/benchmarks/format";
import type { BenchmarkEvent, RunDetail, Trial } from "@/features/benchmarks/types";
import { derivePhases, isRunActive, mergeEvents, normalizeTrial, REFRESH_MS } from "./runDetailUtils";

/** Benchmark run detail state: polled run/events/scenarios queries plus
 * merged live trials, progress, liveness, and banner derivations. */
export function useBenchmarkRun() {
  const { runId = "" } = useParams();
  const queryClient = useQueryClient();
  const [tab, setTab] = useState("overview");
  const [timelineTrial, setTimelineTrial] = useState<string>("");

  // Reset per-run UI state when navigating between runs (a stale trial filter
  // from the previous run would otherwise hide the new run's timeline).
  useEffect(() => {
    setTab("overview");
    setTimelineTrial("");
  }, [runId]);

  const run = useQuery({
    queryKey: ["benchmarks", "run", runId],
    queryFn: ({ signal }) => fetchRun(runId, signal),
    enabled: !!runId,
    placeholderData: keepPreviousData,
    staleTime: 5_000,
    gcTime: 5 * 60_000,
    // Never stop on a missing summary alone: terminal failed/cancelled runs
    // never produce one. Terminal status is the only stop signal.
    refetchInterval: (query) => {
      const data = query.state.data as RunDetail | undefined;
      if (!data) return REFRESH_MS;
      // No isPlaceholderData on QueryState in v5 — dataUpdatedAt === 0 means
      // only placeholder data has arrived, so keep polling for the real row.
      if (query.state.dataUpdatedAt === 0) return REFRESH_MS;
      return isRunActive(data.status) ? REFRESH_MS : false;
    },
  });

  const overview = useQuery({
    queryKey: ["benchmarks", "overview"],
    queryFn: fetchOverview,
    placeholderData: keepPreviousData,
    staleTime: 15_000,
    refetchInterval: (query) => {
      const active = query.state.data?.active;
      if (active?.run_id === runId && isActiveState(active.state)) return REFRESH_MS;
      if (run.data && isRunActive(run.data.status)) return REFRESH_MS;
      return false;
    },
  });

  // A run whose status still says "running" but that no runner owns (daemon
  // restarted mid-run) will never progress — detect it and stop treating the
  // page as live. Grace period: while the overview is still loading (or this
  // run's own query is placeholder data from a previous run) give the run the
  // benefit of the doubt so the live bar doesn't flash off on first paint.
  const overviewSettled = overview.isSuccess || overview.isError;
  const orphaned =
    !overview.isLoading && overviewSettled && !run.isPlaceholderData
      ? isOrphanedRun(run.data?.status, overview.data, runId)
      : false;

  // Single liveness flag for every polling query: run-local active status ORs
  // the overview's verdict instead of letting a possibly-stale overview veto
  // live updates. While the run query is still loading, assume live so the
  // page starts polling immediately; stop only on terminal status, orphaning,
  // or a settled overview that names a different active run.
  // Declared BEFORE the queries below — refetchInterval callbacks run eagerly
  // on mount, so a later declaration throws a TDZ ReferenceError.
  const runStatus = run.data?.status;
  const overviewVeto =
    overviewSettled &&
    !run.isPlaceholderData &&
    overview.data?.active != null &&
    !(overview.data.active.run_id === runId && isActiveState(overview.data.active.state));
  const live = !!runId && !orphaned && (!runStatus || isRunActive(runStatus)) && !overviewVeto;

  const events = useQuery<{ events: BenchmarkEvent[]; latest_sequence?: number }>({
    queryKey: ["benchmarks", "run-events", runId],
    queryFn: async ({ signal }): Promise<{ events: BenchmarkEvent[]; latest_sequence?: number }> => {
      const key = ["benchmarks", "run-events", runId];
      const cached = queryClient.getQueryData<{ events: BenchmarkEvent[]; latest_sequence?: number }>(key);
      // Incremental once ANY page has been cached (even an empty one — a fresh
      // run caches {events: []} and must not redo the full backfill every 2s).
      if (cached !== undefined) {
        const cursor = cached.latest_sequence ?? cached.events[cached.events.length - 1]?.sequence ?? 0;
        const data = await fetchRunEvents(runId, { after: cursor, limit: 1000, signal });
        if (data.events.length === 0) return cached;
        return {
          events: mergeEvents(cached.events, data.events),
          latest_sequence: data.latest_sequence,
        };
      }
      let cursor = 0;
      let all: BenchmarkEvent[] = [];
      let latest = 0;
      for (let page = 0; page < 5; page++) {
        const data = await fetchRunEvents(runId, { after: cursor, limit: 1000, signal });
        all = mergeEvents(all, data.events);
        latest = data.latest_sequence;
        if (data.events.length < 1000) break;
        // Advance from the last returned event's sequence, not the server's
        // global latest (which would skip the middle pages on multi-page runs).
        cursor = all[all.length - 1]?.sequence ?? data.latest_sequence;
      }
      return { events: all, latest_sequence: latest };
    },
    enabled: !!runId,
    placeholderData: keepPreviousData,
    staleTime: 2_000,
    // Polling queries must not retry with backoff at poll cadence on a
    // failing backend — surface the error inline instead (see below).
    retry: false,
    refetchInterval: () => (live ? REFRESH_MS : false),
  });

  // Live per-trial results: the runner persists each trial JSON as soon as it
  // ends, while run.json's trial list only lands at finalize. Without this the
  // progress bar/active-trial strip would show nothing during a live run.
  // Orphaned runs fetch once (no polling) to recover their completed trials.
  const runScenarios = useQuery({
    queryKey: ["benchmarks", "run-scenarios", runId],
    queryFn: ({ signal }) => fetchRunScenarios(runId, signal),
    enabled: !!runId && !!run.data && isRunActive(run.data.status),
    placeholderData: keepPreviousData,
    staleTime: 2_000,
    retry: false,
    refetchInterval: () => (live ? REFRESH_MS : false),
  });

  const isActiveRun =
    (overview.data?.active.run_id === runId && isActiveState(overview.data.active.state)) ||
    (!overviewSettled && run.data ? isRunActive(run.data.status) : false) ||
    (overviewSettled && !overviewVeto && run.data ? isRunActive(run.data.status) : false);

  const invalidateRunQueries = () => {
    void queryClient.invalidateQueries({ queryKey: ["benchmarks", "run", runId] });
    void queryClient.invalidateQueries({ queryKey: ["benchmarks", "run-events", runId] });
    void queryClient.invalidateQueries({ queryKey: ["benchmarks", "run-scenarios", runId] });
    void queryClient.invalidateQueries({ queryKey: ["benchmarks", "overview"] });
  };

  const cancelMutation = useMutation({
    mutationFn: () => cancelBenchmarkRun(runId),
    onSuccess: () => {
      toast({ title: "Cancelling benchmark run", description: "The runner stops after the current trial step." });
      invalidateRunQueries();
    },
    onError: (err) => {
      toast({
        title: "Cancel failed",
        description: err instanceof Error ? err.message : String(err),
        variant: "destructive",
      });
      invalidateRunQueries();
    },
  });

  const baselineMutation = useMutation({
    mutationFn: () => saveBaseline(runId),
    onSuccess: (res) => {
      toast({ title: "Baseline saved", description: res.path || "Regression baseline persisted." });
      invalidateRunQueries();
    },
    onError: (err) => {
      toast({
        title: "Could not save baseline",
        description: err instanceof Error ? err.message : String(err),
        variant: "destructive",
      });
    },
  });

  // Merge finalized trials with live per-trial results by trial_id (stored
  // wins per id). run.json's trials array is empty until finalize, so during
  // a live run the scenarios endpoint is the only source of completed-trial
  // progress; a wholesale either/or would hide live trials mid-finalize.
  const liveTrials = useMemo(() => (runScenarios.data?.scenarios ?? []).map(normalizeTrial), [runScenarios.data]);
  const storedTrials = useMemo(() => (run.data?.trials ?? []).map(normalizeTrial), [run.data?.trials]);
  const displayTrials: Trial[] = useMemo(() => {
    if (storedTrials.length === 0) return liveTrials;
    if (liveTrials.length === 0) return storedTrials;
    const byId = new Map<string, Trial>();
    for (const t of liveTrials) byId.set(t.trial_id, t);
    for (const t of storedTrials) byId.set(t.trial_id, t);
    return [...byId.values()];
  }, [storedTrials, liveTrials]);
  const trialsAreLive = storedTrials.length === 0 && liveTrials.length > 0;
  const activeTrial: Trial | undefined = useMemo(() => {
    const unfinished = [...displayTrials].reverse().find((t) => !t.ended_at);
    if (unfinished) return unfinished;
    return undefined;
  }, [displayTrials]);
  // The scenarios endpoint only persists finished trials, so mid-run the trial
  // list never contains the in-progress trial — fall back to the latest
  // event's trial locus so the live strip and "now:" label still render.
  const eventList = events.data?.events ?? [];
  const liveHint = useMemo(() => {
    for (let i = eventList.length - 1; i >= 0; i--) {
      const e = eventList[i];
      if (e?.trial_id || e?.scenario_id) return { trial_id: e.trial_id, scenario_id: e.scenario_id };
    }
    return undefined;
  }, [eventList]);

  const data = run.data;
  const summary = data?.summary;
  const env = data?.environment;
  const manifest = data?.replay_manifest;
  const phases = derivePhases(activeTrial, isActiveRun && !activeTrial && !!liveHint);

  const onCancel = () => cancelMutation.mutate();
  const onSaveBaseline = () => baselineMutation.mutate();

  // Stable denominator: prefer the summary's frozen total, then the config
  // (trials × scenarios) — never the growing live-trial count, which makes
  // progress move backward as results arrive.
  const totalTrials = data
    ? (summary?.trials_total ?? data.config.trials * Math.max(1, data.scenario_ids.length || displayTrials.length || 1))
    : 0;
  const completedTrials = displayTrials.filter((t) => !!t.ended_at).length;
  const progressPct = totalTrials > 0 ? Math.min(100, Math.round((completedTrials / totalTrials) * 100)) : 0;
  // Max, not last element: a single out-of-order page must never rewind time.
  const elapsedSec = eventList.reduce((m, e) => Math.max(m, e?.elapsed_seconds ?? 0), 0);
  const eventCount = eventList.length;
  const trialIds = [...new Set(displayTrials.map((t) => t.trial_id))];
  const headerBadge = orphaned ? "INTERRUPTED" : isActiveRun ? "RUNNING" : data ? runStatusToBadge(data.status) : "";

  // Instant-finish diagnosis: a completed run whose trials all failed in the
  // provision/sandbox preflight never attempted exploitation — surface the
  // remediation at the top instead of burying it in the Evidence tab.
  const provisionFailed = summary?.failure_categories?.["TARGET_PROVISION_FAILED"] ?? 0;
  const sandboxFailed = summary?.failure_categories?.["SANDBOX_FAILED"] ?? 0;
  const infraDetail =
    displayTrials.find(
      (t) => t.failure_detail && (t.failure_category === "TARGET_PROVISION_FAILED" || t.failure_category === "SANDBOX_FAILED"),
    )?.failure_detail ?? "";
  const showProvisionBanner = !!data && !isActiveRun && !orphaned && data.status === "completed" && provisionFailed > 0;
  const showSandboxBanner = !!data && !isActiveRun && !orphaned && data.status === "completed" && sandboxFailed > 0;

  return {
    runId,
    tab,
    setTab,
    timelineTrial,
    setTimelineTrial,
    run,
    overview,
    events,
    runScenarios,
    cancelMutation,
    baselineMutation,
    orphaned,
    live,
    isActiveRun,
    displayTrials,
    trialsAreLive,
    activeTrial,
    liveHint,
    eventList,
    data,
    summary,
    env,
    manifest,
    phases,
    onCancel,
    onSaveBaseline,
    totalTrials,
    completedTrials,
    progressPct,
    elapsedSec,
    eventCount,
    trialIds,
    headerBadge,
    provisionFailed,
    sandboxFailed,
    infraDetail,
    showProvisionBanner,
    showSandboxBanner,
  };
}

export type BenchmarkRunState = ReturnType<typeof useBenchmarkRun>;
