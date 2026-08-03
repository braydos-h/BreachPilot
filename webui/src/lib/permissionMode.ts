import { useCallback, useEffect, useState } from "react";
import type { DecisionListRow } from "@/api/types";

export type PermissionMode = "read_only" | "approve" | "full_access";

const STORAGE_KEY = "netattackai.permissionMode.v1";
const DEFAULT_MODE: PermissionMode = "full_access";

function readStored(): PermissionMode {
  // ponytail: always Full on load. The sidebar toggle still writes to storage,
  // but we ignore it on next mount so the menu always lands on Full.
  return DEFAULT_MODE;
}

function writeStored(mode: PermissionMode): void {
  try {
    sessionStorage.setItem(STORAGE_KEY, mode);
  } catch {
    // ignore
  }
}

export function usePermissionMode() {
  const [mode, setMode] = useState<PermissionMode>(readStored);

  useEffect(() => {
    writeStored(mode);
  }, [mode]);

  const change = useCallback((m: PermissionMode) => setMode(m), []);
  return { mode, setMode: change };
}

/**
 * Return the answer string to auto-submit for `decision` under `mode`,
 * or `null` when the mode does not cover this decision (operator must answer).
 *
 * - read_only: never auto-answers.
 * - approve: non-destructive start_confirm / tool_approval (sends "yes").
 *   Destructive decisions (those carrying required_text) are left to the operator.
 * - full_access: everything approve covers, plus destructive decisions
 *   (sends the exact required_text so the server accepts it).
 *
 * goal_select is never auto-answered in any mode — the operator must pick a
 * goal from the AI-ranked suggestions themselves.
 */
export function autoAnswerFor(decision: DecisionListRow, mode: PermissionMode): string | null {
  if (mode === "read_only") return null;
  if (decision.status !== "pending") return null;

  const requiredText = decision.required_text ?? "";
  const destructive = !!requiredText;
  const kind = decision.kind;

  if (kind === "goal_select") return null;

  if (mode === "approve" && destructive) return null;

  // start_confirm / tool_approval
  return destructive ? requiredText : "yes";
}