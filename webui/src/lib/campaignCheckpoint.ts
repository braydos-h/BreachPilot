/**
 * Pure helpers for the mid-run operator checkpoint (CAMPAIGN_NEXT_STEP).
 *
 * Kept side-effect-free so they can be tested without jsdom / React rendering
 * (matches the existing vitest node-environment logic-test setup).
 * DecisionCard.tsx imports these to render the checkpoint and encode the
 * operator's answer.
 */
import type { CampaignNextStepOption, SuggestedGoal } from "@/api/types";

/** Visual variant for the two checkpoint kinds. */
export type CheckpointVariant = "access" | "no_path";

export interface CheckpointVisual {
  title: string;
  borderClass: string;
  badgeClass: string;
}

/**
 * Map a checkpoint kind to the visual treatment DecisionCard renders.
 * - "access"  → green ("Verified access obtained")
 * - "no_path"  → amber ("No verified access yet")
 */
export function checkpointVisual(kind: CheckpointVariant): CheckpointVisual {
  if (kind === "access") {
    return {
      title: "Verified access obtained",
      borderClass: "border-emerald-500/50",
      badgeClass: "border-emerald-500/50 text-emerald-300",
    };
  }
  return {
    title: "No verified access yet",
    borderClass: "border-amber-500/50",
    badgeClass: "border-amber-500/40 text-amber-300",
  };
}

/**
 * Detect the checkpoint kind from a decision's prompt_text. The backend
 * writes "VERIFIED ACCESS OBTAINED" or "NO VERIFIED ACCESS YET" as the first
 * line. Falls back to "no_path" when the marker is missing/unknown (the safer
 * default — never falsely claims access).
 */
export function detectCheckpointKind(promptText: string | undefined): CheckpointVariant {
  const firstLine = String(promptText ?? "").split("\n", 1)[0]?.toUpperCase() ?? "";
  // Check "NO VERIFIED ACCESS" first — "VERIFIED ACCESS" is a substring of it.
  if (firstLine.startsWith("NO VERIFIED ACCESS")) return "no_path";
  if (firstLine.startsWith("VERIFIED ACCESS")) return "access";
  return "no_path";
}

/**
 * Normalize the raw options JSON of a campaign_next_step decision into typed
 * CampaignNextStepOption rows. Tolerates missing/malformed fields.
 */
export function parseCheckpointOptions(options: unknown): CampaignNextStepOption[] {
  if (!Array.isArray(options)) return [];
  return options
    .filter((o): o is Record<string, unknown> => !!o && typeof o === "object")
    .map((o) => {
      const goalsRaw = Array.isArray(o.goals) ? o.goals : [];
      const goals = goalsRaw
        .filter((g): g is Record<string, unknown> => !!g && typeof g === "object")
        .map((g) => ({
          name: String(g.name ?? ""),
          description: String(g.description ?? ""),
        }))
        .filter((g) => g.name);
      return {
        action: String(o.action ?? ""),
        label: String(o.label ?? o.action ?? ""),
        goals: goals.length > 0 ? goals : undefined,
      };
    })
    .filter((o) => o.action);
}

/**
 * Encode the operator's selection into the answer string the backend expects.
 * - A plain action → "<action>"
 * - An action with a nested goal pick → "<action>:<goalName>"
 * - An action with a custom goal → "<action>:custom:<customText>"
 *
 * Matches the encoding parsed by AssessmentService._checkpoint_hook.
 */
export function encodeCheckpointAnswer(
  option: CampaignNextStepOption,
  goalName?: string,
  customText?: string,
): string {
  const action = option.action;
  if (!action) return "";
  // Actions that carry a nested goal list need a goal suffix.
  if (option.goals && option.goals.length > 0) {
    if (goalName === "custom") {
      return `${action}:custom:${customText ?? ""}`;
    }
    return goalName ? `${action}:${goalName}` : "";
  }
  return action;
}

/**
 * Coerce a nested checkpoint goal into the SuggestedGoal shape GoalSuggestionCard
 * expects. The backend sends minimal {name, description}; the card's optional
 * fields default to neutral values.
 */
export function toSuggestedGoal(g: { name: string; description: string }): SuggestedGoal {
  return {
    name: g.name,
    description: g.description,
    exploit_likelihood: "Possible",
    success_rating: 0,
    compatible: true,
    is_ai_generated: false,
  };
}