import { useState } from "react";
import { ShieldAlert } from "lucide-react";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import type { PermissionMode } from "@/lib/permissionMode";

interface PermissionControlProps {
  mode: PermissionMode;
  /** Applies a mode. Full access is only applied after the operator confirms. */
  onModeChange: (mode: PermissionMode) => void | Promise<void>;
  className?: string;
}

const OPTIONS: Array<{ value: PermissionMode; label: string; hint: string }> = [
  { value: "read_only", label: "Read-only", hint: "Every decision waits for the operator." },
  { value: "approve", label: "Approve", hint: "Auto-answers non-destructive decisions." },
  {
    value: "full_access",
    label: "Full access",
    hint: "Auto-answers ALL decisions, incl. destructive confirmations.",
  },
];

/**
 * Explicit permission-mode selector (radio group — no cycling, so a mis-click
 * can never silently escalate to Full access). Read-only and Approve apply
 * immediately; Full access opens a confirmation dialog first. The displayed
 * mode only changes when `onModeChange` resolves; failures keep the old mode
 * and surface the error. The backend remains the authorization boundary — this
 * only controls how the WebUI auto-answers decisions.
 */
export function PermissionControl({ mode, onModeChange, className }: PermissionControlProps) {
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [applying, setApplying] = useState(false);
  const [error, setError] = useState<string>("");

  const choose = (next: PermissionMode) => {
    setError("");
    if (next === "full_access") {
      setConfirmOpen(true);
      return;
    }
    void onModeChange(next);
  };

  const confirmFullAccess = async () => {
    setApplying(true);
    setError("");
    try {
      await onModeChange("full_access");
      setConfirmOpen(false);
    } catch (err) {
      // Server rejected the change — retain the old displayed mode.
      setError(err instanceof Error ? err.message : "Failed to enable Full access.");
    } finally {
      setApplying(false);
    }
  };

  return (
    <div className={className}>
      <div role="radiogroup" aria-label="Permission mode" className="flex flex-col gap-1.5">
        {OPTIONS.map((opt) => {
          const checked = mode === opt.value;
          const destructive = opt.value === "full_access";
          return (
            <label
              key={opt.value}
              className={cn(
                "flex cursor-pointer items-start gap-2.5 rounded-md border px-3 py-2 transition-colors",
                checked
                  ? destructive
                    ? "border-destructive/50 bg-destructive/10"
                    : "border-primary/50 bg-primary/5"
                  : "border-border hover:bg-accent",
              )}
            >
              <input
                type="radio"
                name="permission-mode"
                value={opt.value}
                checked={checked}
                onChange={() => choose(opt.value)}
                className="mt-0.5 h-4 w-4 accent-primary"
                aria-describedby={`permission-hint-${opt.value}`}
              />
              <span className="flex flex-col gap-0.5">
                <span
                  className={cn(
                    "text-sm font-medium",
                    checked && (destructive ? "text-red-200" : "text-primary"),
                  )}
                >
                  {opt.label}
                </span>
                <span
                  id={`permission-hint-${opt.value}`}
                  className="text-[11px] leading-tight text-muted-foreground"
                >
                  {opt.hint}
                </span>
              </span>
            </label>
          );
        })}
      </div>

      {error && (
        <p role="alert" className="mt-2 flex items-center gap-1.5 text-xs text-destructive">
          <ShieldAlert className="h-3.5 w-3.5" />
          {error}
        </p>
      )}

      <Dialog
        open={confirmOpen}
        onOpenChange={(open) => {
          if (!applying) setConfirmOpen(open);
        }}
      >
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <ShieldAlert className="h-5 w-5 text-destructive" />
              Enable Full Access?
            </DialogTitle>
            <DialogDescription className="text-sm">
              Full access enables destructive operations and unrestricted run control through the
              WebUI. The backend remains the authorization boundary — the allowlist target lock
              still applies. Continue?
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setConfirmOpen(false)} disabled={applying}>
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={() => void confirmFullAccess()}
              disabled={applying}
            >
              {applying ? "Enabling…" : "Enable Full Access"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
