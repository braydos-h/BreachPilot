import { useEffect, useState } from "react";
import { Wrench } from "lucide-react";
import { useQueryClient } from "@tanstack/react-query";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { SkeletonRows } from "@/components/Loading";
import { useSandboxFix, useSandboxFixPlan, useSandboxFixStatus } from "@/api/hooks";
import { SandboxFixFooter } from "./SandboxFixFooter";
import { FixProgressView, FixPlanView } from "./SandboxFixViews";
import { FixFailedView, FixSuccessView } from "./SandboxFixResultViews";

export function SandboxFixDialog({
  open,
  onOpenChange,
  sandboxReason,
}: {
  open: boolean;
  onOpenChange: (o: boolean) => void;
  sandboxReason: string;
}) {
  const qc = useQueryClient();
  const planQuery = useSandboxFixPlan(open);
  const fixMutation = useSandboxFix();
  const [jobId, setJobId] = useState<string | null>(null);
  const statusQuery = useSandboxFixStatus(jobId);
  const job = statusQuery.data;
  const plan = planQuery.data;

  useEffect(() => {
    if (!open) {
      setJobId(null);
      fixMutation.reset();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open ]);

  useEffect(() => {
    if (job?.status === "succeeded") {
      void qc.invalidateQueries({ queryKey: ["system", "sandbox"] });
    }
    if (job?.status === "succeeded" || job?.status === "failed") {
      // Keep polls stopped already via hook's refetchInterval; also ensure sandbox status stays accurate
    }
  }, [job?.status, qc]);

  const isFixing = job ? job.status === "pending" || job.status === "running" : fixMutation.isPending;
  const isSuccess = job?.status === "succeeded";
  const isFailed = job?.status === "failed";

  const handleStartFix = async () => {
    try {
      const result = await fixMutation.mutateAsync();
      setJobId(result.job_id);
    } catch {
      // error handled via fixMutation.error
    }
  };

  const handleRetry = async () => {
    fixMutation.reset();
    setJobId(null);
    try {
      const result = await fixMutation.mutateAsync();
      setJobId(result.job_id);
    } catch {
      // handled
    }
  };

  const mode = isFixing ? "fixing" : isSuccess ? "success" : isFailed ? "failed" : "plan";

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-2xl max-h-[90vh] overflow-hidden flex flex-col">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2 text-lg">
            <Wrench className="h-5 w-5" />
            Fix Docker sandbox
          </DialogTitle>
          <DialogDescription className="text-sm text-left">
            BreachPilot is currently executing commands directly on this machine because the Docker sandbox could not start.
          </DialogDescription>
        </DialogHeader>

        <div className="flex-1 overflow-y-auto space-y-4 pr-1">
          {sandboxReason && (
            <div className="rounded-md border border-amber-500/20 bg-amber-500/5 px-3 py-2 text-sm">
              <span className="font-medium">Reason: </span>
              <span className="text-muted-foreground">{sandboxReason}</span>
            </div>
          )}

          {planQuery.isLoading && !isFixing && !isSuccess && !isFailed && (
            <div className="space-y-2">
              <SkeletonRows count={3} />
              <p className="text-xs text-muted-foreground">Loading remediation plan…</p>
            </div>
          )}

          {planQuery.error && !isFixing && !isSuccess && !isFailed && (
            <div className="rounded-md border border-destructive/40 bg-destructive/10 px-3 py-2 text-xs text-destructive">
              Failed to load plan: {(planQuery.error as Error).message}
            </div>
          )}

          {!isFixing && !isSuccess && !isFailed && plan && (
            <>
              <FixPlanView plan={plan} />
              {fixMutation.error && (
                <div className="rounded-md border border-destructive/40 bg-destructive/10 px-3 py-2 text-xs text-destructive">
                  {(fixMutation.error as Error).message}
                </div>
              )}
            </>
          )}

          {isFixing && <FixProgressView job={job} plan={plan} />}
          {isSuccess && job && <FixSuccessView job={job} />}
          {isFailed && job && <FixFailedView job={job} />}
        </div>

        <SandboxFixFooter
          mode={mode as "plan" | "fixing" | "success" | "failed"}
          onClose={() => onOpenChange(false)}
          onStart={() => void handleStartFix()}
          onRetry={() => void handleRetry()}
          startDisabled={planQuery.isLoading || !plan || fixMutation.isPending}
          starting={fixMutation.isPending}
        />
      </DialogContent>
    </Dialog>
  );
}
