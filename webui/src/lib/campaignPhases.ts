// Shared vocabulary for autonomous-campaign state, mirroring
// tools/campaign/state.py. AttackPhase has 8 ordered values, but
// run_campaign_step can also write current_phase: "done" — phaseIndex()
// returns -1 for unknown values so the UI degrades to a raw badge instead of
// crashing on a state file from a different version.

export const CAMPAIGN_PHASES = [
  "recon",
  "enumeration",
  "exploit",
  "privesc",
  "lateral",
  "persistence",
  "validation",
  "report",
] as const;

export type CampaignPhase = (typeof CAMPAIGN_PHASES)[number];

export const CAMPAIGN_PHASE_LABELS: Record<CampaignPhase, string> = {
  recon: "Recon",
  enumeration: "Enumeration",
  exploit: "Exploit",
  privesc: "PrivEsc",
  lateral: "Lateral",
  persistence: "Persistence",
  validation: "Validation",
  report: "Report",
};

export function phaseIndex(phase: string): number {
  return (CAMPAIGN_PHASES as readonly string[]).indexOf(phase);
}

export function isKnownPhase(phase: string): boolean {
  return phaseIndex(phase) >= 0;
}

export const AGGRESSION_LEVELS = ["stealth", "normal", "aggressive", "maximum"] as const;

export type AggressionLevel = (typeof AGGRESSION_LEVELS)[number];

export function aggressionIndex(level: string): number {
  return (AGGRESSION_LEVELS as readonly string[]).indexOf(level);
}

/** Badge variant per aggression tier; unknown values render as outline with
 *  the raw string (label text, never colour alone, per the repo's a11y rule). */
export function aggressionVariant(level: string): "muted" | "info" | "warn" | "danger" | "outline" {
  switch (level) {
    case "stealth":
      return "muted";
    case "normal":
      return "info";
    case "aggressive":
      return "warn";
    case "maximum":
      return "danger";
    default:
      return "outline";
  }
}

export interface CampaignTimelineEntry {
  timestamp: string;
  event_type: string;
  description: string;
  metadata?: Record<string, unknown>;
}