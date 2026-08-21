import { useState } from "react";
import { AlertTriangle, Check, Loader2, Play, ShieldAlert } from "lucide-react";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Spinner } from "@/components/Loading";
import { useAnswerDecision } from "@/api/hooks";
import { executionProfileLabel, type ExecutionProfileId } from "./profile";
import type { CreateRunResponse, ObserverMode, RunMode, SkillsMode } from "@/api/types";
import type { Step } from "./RunStepper";

interface RunReviewProps {
  mode: RunMode;
  target: string;
  goalMode: "preset" | "custom";
  goal: string;
  customGoal: string;
  model: string;
  profile: ExecutionProfileId;
  powerUpCount: number;
  skillsMode: SkillsMode;
  observerMode: ObserverMode;
  reconFirst: boolean | null;
  yes: boolean;
  isCreating: boolean;
  createError: string;
  createdRun: CreateRunResponse | null;
  onCreate: () => void;
  onEdit: (step: Step) => void;
  onCreated?: (runId: string, state: string) => void;
  onRetry: () => void;
}

function Row({
  label,
  value,
  editTo,
  onEdit,
}: {
  label: string;
  value: string;
  editTo?: Step;
  onEdit?: (step: Step) => void;
}) {
  return (
    <div className="flex items-center justify-between gap-3 py-1.5">
      <span className="shrink-0 text-xs font-medium uppercase tracking-wide text-muted-foreground">
        {label}
      </span>
      <span className="flex min-w-0 items-center gap-2">
        <span className="truncate text-right text-sm font-medium text-foreground">{value}</span>
        {editTo && onEdit && (
          <button
            type="button"
            onClick={() => onEdit(editTo)}
            className="shrink-0 rounded px-1 py-0.5 text-xs text-muted-foreground underline decoration-muted-foreground/40 underline-offset-2 transition-colors hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
          >
            Edit
          </button>
        )}
      </span>
    </div>
  );
}

const NONE = "Not selected";

/** Review & launch: a structured pre-launch summary with per-section Edit
 *  links, then the primary launch action. Once the run is created and the
 *  server asks for confirmation, the ready-to-begin gate replaces the launch
 *  button (destructive runs require typed confirmation — server-side logic
 *  unchanged). */
export function RunReview({
  mode,
  target,
  goalMode,
  goal,
  customGoal,
  model,
  profile,
  powerUpCount,
  skillsMode,
  observerMode,
  reconFirst,
  yes,
  isCreating,
  createError,
  createdRun,
  onCreate,
  onEdit,
  onCreated,
  onRetry,
}: RunReviewProps) {
  const answerDecision = useAnswerDecision(createdRun?.run_id ?? "");
  const [confirmText, setConfirmText] = useState("");
  const [submitting, setSubmitting] = useState(false);

  const goalValue = goalMode === "custom" ? customGoal.trim() || NONE : goal || NONE;
  const reconLabel = reconFirst === null ? "Auto" : reconFirst ? "On" : "Off";
  const skillsLabel = skillsMode === "off" ? "Off" : skillsMode.charAt(0).toUpperCase() + skillsMode.slice(1);
  const observerLabel = observerMode.charAt(0).toUpperCase() + observerMode.slice(1);
  const isAttack = mode === "attack";
  const launchLabel = isAttack ? "Launch Attack" : "Start Recon";

  const submitConfirm = (e: React.FormEvent, overrideAnswer?: string) => {
    e.preventDefault();
    const decision = createdRun?.decision;
    if (!decision || submitting) return;
    setSubmitting(true);
    answerDecision.mutate(
      { decisionId: decision.id, answer: overrideAnswer ?? confirmText },
      {
        onSuccess: () => onCreated?.(createdRun.run_id, "running"),
        onError: () => setSubmitting(false),
      },
    );
  };

  const gate = createdRun?.decision;
  const preview = createdRun?.preview;
  const destructive = preview?.destructive;
  const requiredText = preview?.required_confirmation_text ?? "";

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm">Review &amp; launch</CardTitle>
        </CardHeader>
        <CardContent>
          <dl className="divide-y divide-border/60">
            <Row label="Target" value={target || NONE} editTo="target" onEdit={onEdit} />
            <Row label="Mode" value={isAttack ? "Attack" : "Recon"} editTo="settings" onEdit={onEdit} />
            <Row label="Goal" value={goalValue} editTo="settings" onEdit={onEdit} />
            <Row label="Model" value={model || NONE} editTo="settings" onEdit={onEdit} />
            <Row
              label="Execution"
              value={`${executionProfileLabel(profile)} · ${powerUpCount} power-ups`}
              editTo="settings"
              onEdit={onEdit}
            />
            <Row label="Skills" value={skillsLabel} editTo="settings" onEdit={onEdit} />
            <Row label="Observer" value={observerLabel} editTo="settings" onEdit={onEdit} />
            <Row label="Recon first" value={reconLabel} editTo="settings" onEdit={onEdit} />
          </dl>

          {isAttack && (
            <div className="mt-3 flex items-start gap-2 rounded-md border border-amber-500/25 bg-amber-500/5 px-3 py-2.5">
              <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0 text-amber-300" aria-hidden />
              <p className="text-xs leading-relaxed text-amber-100/90">
                Attack runs the autonomous offensive workflow against the target. Only proceed against
                systems you own or are explicitly authorized to test. OPSEC posture applies unless the
                target is local.
              </p>
            </div>
          )}

          {createError && !createdRun && (
            <div className="mt-3 flex items-center justify-between gap-2 rounded-md border border-destructive/40 bg-destructive/10 p-3 text-sm text-red-200">
              <span>{createError}</span>
              <Button type="button" size="sm" variant="outline" onClick={onRetry}>
                Retry
              </Button>
            </div>
          )}
        </CardContent>
      </Card>

      {!createdRun && (
        <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
          <p className="text-xs text-muted-foreground">
            {yes
              ? "Launch confirmation is skipped — the run starts immediately."
              : "The run pauses at a ready-to-begin confirmation before execution."}
          </p>
          <Button
            type="button"
            size="lg"
            className={cn("gap-2", isAttack && "bg-amber-600 text-amber-950 hover:bg-amber-500")}
            onClick={onCreate}
            disabled={isCreating}
          >
            {isCreating ? (
              <>
                <Loader2 className="h-4 w-4 animate-spin" /> Creating run…
              </>
            ) : (
              <>
                <Play className="h-4 w-4" /> {launchLabel}
              </>
            )}
          </Button>
        </div>
      )}

      {isCreating && !createdRun && <Spinner label="Creating run..." className="p-2" />}

      {createdRun && !gate && (
        <p className="text-sm text-muted-foreground">
          Run created — waiting for the server to confirm readiness.
        </p>
      )}

      {gate && (
        <Card className={cn(destructive && "border-destructive/50")}>
          <CardHeader className="pb-2">
            <CardTitle className="flex items-center gap-1.5 text-sm">
              {destructive ? (
                <>
                  <AlertTriangle className="h-4 w-4 text-destructive" /> Ready-to-begin confirmation
                </>
              ) : (
                "Ready to begin?"
              )}
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            {destructive ? (
              <form className="space-y-2" onSubmit={submitConfirm}>
                <div className="flex items-start gap-2 rounded border border-destructive/40 bg-destructive/10 p-2 text-xs text-red-200">
                  <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
                  <div className="space-y-1">
                    <div>Destructive mode. Type the exact confirmation to proceed:</div>
                    <code className="rounded bg-muted px-1.5 py-0.5 font-mono">{requiredText}</code>
                  </div>
                </div>
                <Input
                  value={confirmText}
                  onChange={(e) => setConfirmText(e.target.value)}
                  placeholder={requiredText}
                  disabled={submitting}
                  autoFocus
                  autoComplete="off"
                />
                <Button type="submit" disabled={submitting || confirmText !== requiredText} className="w-full">
                  {submitting ? <Loader2 className="h-4 w-4 animate-spin" /> : <Check className="h-4 w-4" />} Confirm &amp; start
                </Button>
              </form>
            ) : (
              <div className="space-y-2">
                <p className="text-sm text-muted-foreground">Proceed with this run?</p>
                <Button
                  type="button"
                  className="w-full"
                  disabled={submitting}
                  onClick={(e) => submitConfirm(e as unknown as React.FormEvent, "yes")}
                >
                  {submitting ? <Loader2 className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />} Proceed
                </Button>
              </div>
            )}
          </CardContent>
        </Card>
      )}
    </div>
  );
}
