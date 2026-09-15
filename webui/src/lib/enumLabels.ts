// Human labels for backend enums (todo 43). Primary UI must use these;
// raw snake_case keys stay in Advanced/diagnostics + API payloads.

export const DECISION_KIND_LABELS: Record<string, string> = {
  tool_approval: "Tool needs approval",
  start_confirm: "Confirm run start",
  goal_select: "Choose a goal",
  campaign_next_step: "Continue campaign?",
};

export const OBSERVER_MODE_LABELS: Record<string, string> = {
  heuristic: "Fast checks",
  llm: "AI review",
  hybrid: "Balanced review",
};

export const RUN_MODE_LABELS: Record<string, string> = {
  recon: "Recon",
  attack: "Attack",
  fast: "Fast recon",
};

export const EXECUTION_PROFILE_LABELS: Record<string, string> = {
  standard: "Standard",
  fast: "Fast",
  deep: "Deep",
  custom: "Custom",
};

export function humanizeEnum(value: string | undefined | null, map?: Record<string, string>): string {
  if (!value) return "Not set";
  const v = String(value);
  if (map && v in map) return map[v] as string;
  const flat: Record<string, string> = {
    ...DECISION_KIND_LABELS,
    ...OBSERVER_MODE_LABELS,
    ...RUN_MODE_LABELS,
    ...EXECUTION_PROFILE_LABELS,
  };
  if (v in flat) return flat[v] as string;
  return v
    .split("_")
    .map((w) => (w ? `${w[0]?.toUpperCase()}${w.slice(1)}` : w))
    .join(" ");
}
