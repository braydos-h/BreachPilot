/**
 * UI-only execution presets.
 *
 * A preset maps onto the *existing* frontend fields (power-ups + observer +
 * skills) — it never creates a new backend run parameter. Presets are resolved
 * against the capability flags so an unsupported flag is never silently
 * enabled. Once the operator manually changes one of the controlled fields,
 * the wizard switches the profile to `custom` (see RunWizard).
 */

import type { ObserverMode, SkillsMode } from "@/api/types";

export type ExecutionProfileId = "standard" | "fast" | "deep" | "custom";

export interface ExecutionProfileMeta {
  id: ExecutionProfileId;
  label: string;
  description: string;
}

export const EXECUTION_PROFILES: ExecutionProfileMeta[] = [
  { id: "standard", label: "Standard", description: "Balanced default configuration." },
  { id: "fast", label: "Fast", description: "Lower overhead, minimal optional reasoning features." },
  { id: "deep", label: "Deep", description: "More analysis and reasoning features enabled." },
  { id: "custom", label: "Custom", description: "Manually configure every option." },
];

/** The frontend fields a preset controls. */
export interface ProfileFieldValues {
  powerUps: Record<string, boolean>;
  observerMode: ObserverMode;
  skillsMode: SkillsMode;
}

const OFF: ProfileFieldValues = {
  powerUps: {
    swarm: false,
    parallel_swarm: false,
    critic: false,
    reflection: false,
    adaptive_exploits: false,
    long_session: false,
    multi_model_consult: false,
    ultrathink: false,
  },
  observerMode: "hybrid",
  skillsMode: "off",
};

/** Resolve a preset to concrete field values against the capability flags.
 *  Returns `null` for `custom` (no preset mapping). */
export function profileFieldValues(
  id: ExecutionProfileId,
  flags: string[],
): ProfileFieldValues | null {
  const on = (key: string) => flags.includes(key);
  switch (id) {
    case "standard":
      return OFF;
    case "fast":
      return { ...OFF, observerMode: "heuristic" };
    case "deep":
      return {
        powerUps: {
          swarm: on("swarm"),
          parallel_swarm: on("parallel_swarm"),
          critic: on("critic"),
          reflection: on("reflection"),
          adaptive_exploits: on("adaptive_exploits"),
          long_session: on("long_session"),
          multi_model_consult: on("multi_model_consult"),
          ultrathink: on("ultrathink"),
        },
        observerMode: "llm",
        skillsMode: "on",
      };
    case "custom":
      return null;
  }
}

export function executionProfileLabel(id: ExecutionProfileId): string {
  return EXECUTION_PROFILES.find((p) => p.id === id)?.label ?? "Custom";
}
