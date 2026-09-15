// Canonical product terminology registry (todo 55).
// Single source of truth for operator-visible nouns. UI copy, route labels,
// help, and tests must import from here so copy cannot silently drift.
// Covers: 06 (Run vs Session), 08 (approval labels), 42-44 (telemetry/status).

export const CANONICAL_TERMS = {
  run: { canonical: "Run", plural: "Runs", aliases: ["Session", "Sessions", "session", "sessions"] },
  newRun: { canonical: "New run", aliases: ["New session", "Create session"] },
  evidence: { canonical: "Evidence", aliases: [] },
  finding: { canonical: "Finding", plural: "Findings", aliases: [] },
  artifact: { canonical: "Artifact", plural: "Artifacts", aliases: ["Arts"] },
  attackPath: { canonical: "Attack Path", aliases: ["Attack Graph"] },
  settings: { canonical: "Settings", aliases: ["System"] },
  approvalPolicy: { canonical: "Approval policy", aliases: ["Permission mode", "permission mode", "skip-confirm", "skip_confirm"] },
} as const;

export type CanonicalTermKey = keyof typeof CANONICAL_TERMS;

// Deprecated alias -> canonical lookup for tests/migrations.
export const DEPRECATED_ALIASES: Record<string, string> = (() => {
  const out: Record<string, string> = {};
  for (const term of Object.values(CANONICAL_TERMS)) {
    const canon = (term as { canonical: string }).canonical;
    const aliases = (term as unknown as { aliases: readonly string[] }).aliases ?? [];
    for (const alias of aliases) {
      out[alias.toLowerCase()] = canon;
    }
  }
  // Explicit terse telemetry abbreviations (todo 42).
  out["dur"] = "Duration";
  out["acts"] = "Actions";
  out["arts"] = "Artifacts";
  out["tok"] = "Tokens";
  return out;
})();

// Telemetry long labels (todo 42 — shared by outcome hub + telemetry cards).
export const TELEMETRY_LABELS = {
  duration: "Duration",
  actions: "Actions",
  tools: "Tools",
  artifacts: "Artifacts",
  tokens: "Tokens",
  calls: "Calls",
} as const;

// Approval-policy workload labels (todos 07/08). Backend enum values unchanged.
export const APPROVAL_POLICY_LABELS = {
  read_only: "Manual approvals",
  approve: "Auto-safe approvals",
  full_access: "Autonomous within scope",
} as const;

export const APPROVAL_POLICY_DESCRIPTIONS = {
  read_only: "Every decision waits for you. Nothing is auto-approved. Safest — you drive.",
  approve:
    "Automatically handles safe start and tool approvals. Destructive confirmations, goals, and campaign checkpoints still wait for you.",
  full_access:
    "Automatically handles start and tool approvals, including destructive confirmations. Goals and campaign checkpoints still wait for you. The target allowlist lock still applies.",
} as const;
