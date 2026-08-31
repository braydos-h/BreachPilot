// BreachPilot by @braydos-h — https://github.com/braydos-h/BreachPilot
// Shared overview query for every Benchmarks sub-page. One cached query
// (`["benchmarks", "overview"]`) serves the nav shell, overview, start and
// history pages without duplicate fetches; the run-completion invalidation
// lives here so whichever page is mounted keeps history fresh.
import { useEffect, useRef } from "react";
import { keepPreviousData, useQuery, useQueryClient } from "@tanstack/react-query";
import { fetchOverview } from "@/features/benchmarks/api";
import { isActiveState } from "@/features/benchmarks/format";

const REFRESH_MS = 3000;

export function useBenchmarksOverview() {
  const queryClient = useQueryClient();

  const overview = useQuery({
    queryKey: ["benchmarks", "overview"],
    queryFn: fetchOverview,
    placeholderData: keepPreviousData,
    staleTime: 15_000,
    gcTime: 5 * 60_000,
    refetchInterval: (query) => {
      const active = query.state.data?.active;
      return active && isActiveState(active.state) ? REFRESH_MS : false;
    },
  });

  const active = overview.data?.active ?? { run_id: null, state: "idle", error: "" };
  const activeBusy = !!active.run_id && isActiveState(active.state);

  // When an active run reaches a terminal state the polling intervals stop —
  // but the last 3s poll may predate the run's index entry, leaving stale
  // history. Invalidate once on the active→terminal transition.
  const prevActiveBusy = useRef(false);
  useEffect(() => {
    if (prevActiveBusy.current && !activeBusy) {
      void queryClient.invalidateQueries({ queryKey: ["benchmarks"] });
    }
    prevActiveBusy.current = activeBusy;
  }, [activeBusy, queryClient]);

  return { overview, active, activeBusy };
}
