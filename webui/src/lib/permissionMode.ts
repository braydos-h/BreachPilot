import { useCallback, useEffect, useState } from "react";
import type { DecisionListRow } from "@/api/types";

export type PermissionMode = "read_only" | "approve";

const STORAGE_KEY = "netattackai.permissionMode.v1";
const DEFAULT_MODE: PermissionMode = "read_only";

function readStored(): PermissionMode {
  try {
    const v = sessionStorage.getItem(STORAGE_KEY);
    if (v === "approve") return "approve";
  } catch {
    // ignore
  }
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
 * - read_only: never auto-answers (operator must confirm everything).
 * - approve: non-destructive start_confirm / tool_approval only (sends "yes").
 *   Destructive decisions (those carrying required_text) are always left to
 *   the operator regardless of mode.
 *
 * goal_select is never auto-answered — the operator must pick a
 * goal from the AI-ranked suggestions themselves.
 */
export function autoAnswerFor(decision: DecisionListRow, mode: PermissionMode): string | null {
  if (mode === "read_only") return null;
  if (decision.status !== "pending") return null;

  const requiredText = decision.required_text ?? "";
  const destructive = !!requiredText;
  const kind = decision.kind;

  if (kind === "goal_select") return null;
  if (destructive) return null;

  // start_confirm / tool_approval, non-destructive
  return "yes";
}