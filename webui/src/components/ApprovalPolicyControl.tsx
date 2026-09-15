import { cn } from "@/lib/utils";
import { APPROVAL_POLICY_DESCRIPTIONS, APPROVAL_POLICY_LABELS } from "@/lib/terminology";
import type { PermissionMode } from "@/lib/permissionMode";

const OPTIONS: PermissionMode[] = ["read_only", "approve", "full_access"];

/**
 * Single Approval policy control (todo 09). Presents one understandable concept
 * on Review and maps internally to permission mode + skip-confirm (yes flag).
 * Mapping: Manual -> {mode: read_only, yes: false}; Auto-safe -> {mode: approve, yes: false};
 * Autonomous -> {mode: full_access, yes: true}. Explicit, tested, documented.
 */
export function approvalPolicyToBackend(policy: PermissionMode): { mode: PermissionMode; yes: boolean } {
  if (policy === "full_access") return { mode: "full_access", yes: true };
  if (policy === "approve") return { mode: "approve", yes: false };
  return { mode: "read_only", yes: false };
}

export function ApprovalPolicyControl({
  value,
  onChange,
}: {
  value: PermissionMode;
  onChange: (v: PermissionMode) => void;
}) {
  return (
    <fieldset>
      <legend className="text-sm font-semibold">Approval policy</legend>
      <p className="mt-0.5 text-[13px] text-muted-foreground">When should BreachPilot ask you before acting?</p>
      <div className="mt-2 grid gap-2" role="radiogroup" aria-label="Approval policy">
        {OPTIONS.map((opt) => {
          const checked = value === opt;
          return (
            <label
              key={opt}
              className={cn(
                "flex cursor-pointer items-start gap-2.5 rounded-md border px-3 py-2.5",
                checked ? "border-primary/50 bg-primary/5" : "border-border hover:bg-accent",
              )}
            >
              <input type="radio" name="approval-policy" value={opt} checked={checked} onChange={() => onChange(opt)} className="mt-0.5 h-4 w-4 accent-primary" />
              <span>
                <span className="block text-sm font-medium">{APPROVAL_POLICY_LABELS[opt]}</span>
                <span className="block text-[13px] leading-snug text-muted-foreground">{APPROVAL_POLICY_DESCRIPTIONS[opt]}</span>
              </span>
            </label>
          );
        })}
      </div>
    </fieldset>
  );
}
