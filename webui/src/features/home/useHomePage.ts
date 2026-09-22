import { useRuns } from "@/api/hooks";
import { isActiveState, isTerminalState } from "@/api/types";

/** Home page state: recent-run window with hero/launchpad derivations. */
export function useHomePage() {
  const runs = useRuns(50, 0);
  const rows = runs.data?.runs ?? [];
  const activeRun = rows.find((r) => isActiveState(r.state));
  const recent = rows.slice(0, 5);
  const doneCount = rows.filter((r) => isTerminalState(r.state)).length;
  const failedCount = rows.filter((r) => r.state === "failed").length;
  const returning = rows.length > 0 && !runs.isLoading;
  const lastRow = rows[0];
  const lastTarget = lastRow?.target || lastRow?.target_ip || "—";

  return { runs, rows, activeRun, recent, doneCount, failedCount, returning, lastTarget };
}

export type HomePageState = ReturnType<typeof useHomePage>;
