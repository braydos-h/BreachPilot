import { useState } from "react";
import { RefreshCw, ShieldAlert, ShieldCheck, ShieldX, Wrench } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { useSandboxStatus } from "@/api/hooks";
import { SandboxFixDialog } from "./SandboxFixDialog";

export const SANDBOX_REPAIR_HINT =
  "Start Docker and build the sandbox image (docker build -t breachpilot-sandbox:latest docker/sandbox), then restart BreachPilot to verify containment before starting another assessment.";

/**
 * Sandbox posture banner for the home screen. Surfaced at startup so the
 * operator always knows the effective execution mode before launching a run.
 */
export function SandboxBanner() {
  const sandbox = useSandboxStatus();
  const [fixOpen, setFixOpen] = useState(false);
  if (sandbox.isLoading) return null;
  if (sandbox.error || !sandbox.data) {
    return (
      <div className="flex flex-wrap items-center justify-between gap-2 rounded-md border border-amber-500/40 bg-amber-500/5 px-3 py-2 text-xs" role="status" data-testid="sandbox-banner-status-unavailable">
        <span>Sandbox status could not be loaded. Check the server status before starting an assessment.</span>
        <Button size="sm" variant="outline" onClick={() => sandbox.refetch()} disabled={sandbox.isFetching}>
          <RefreshCw className="mr-1.5 h-3.5 w-3.5" />
          Refresh status
        </Button>
      </div>
    );
  }
  const s = sandbox.data;
  const reason: string = s.fallback_reason || s.docker_error || "";
  if (s.mode === "contained") {
    return (
      <p className="flex items-center gap-1.5 text-xs text-muted-foreground" data-testid="sandbox-banner-contained">
        <ShieldCheck className="h-3.5 w-3.5 text-emerald-400" />
        Sandbox active — commands run inside the disposable Docker worker.
      </p>
    );
  }
  if (s.mode === "blocked") {
    return (
      <>
        <Card className="border-red-500/40 bg-red-500/5" data-testid="sandbox-banner-blocked">
          <CardContent className="p-3 text-sm">
            <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
              <div className="space-y-1 flex-1">
                <div className="flex flex-wrap items-center gap-2">
                  <ShieldX className="h-4 w-4 text-red-300" />
                  <Badge variant="danger">Sandbox required</Badge>
                  <span className="font-medium text-red-200">Attack execution is blocked until containment is available.</span>
                </div>
                {reason && <p className="text-xs text-muted-foreground">Reason: {reason}</p>}
                <p className="text-xs text-red-200/80">{SANDBOX_REPAIR_HINT}</p>
              </div>
              <div className="flex shrink-0 sm:self-center">
                <Button
                  variant="outline"
                  size="sm"
                  className="gap-1.5 border-red-500/40 text-red-200 hover:bg-red-500/10"
                  onClick={() => setFixOpen(true)}
                  aria-label="Fix sandbox"
                >
                  <Wrench className="h-4 w-4" />
                  Fix sandbox
                </Button>
              </div>
            </div>
          </CardContent>
        </Card>
        <SandboxFixDialog open={fixOpen} onOpenChange={setFixOpen} sandboxReason={reason} />
      </>
    );
  }
  return (
    <>
      <Card className="border-amber-500/40 bg-amber-500/5" data-testid="sandbox-banner-unknown">
        <CardContent className="p-3 text-sm">
          <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
            <div className="space-y-1 flex-1">
              <div className="flex flex-wrap items-center gap-2">
                <ShieldAlert className="h-4 w-4 text-amber-300" />
                <Badge variant="warn">Sandbox status unknown</Badge>
                <span className="font-medium text-amber-200">Verify sandbox status before starting an assessment.</span>
              </div>
              {reason && <p className="text-xs text-muted-foreground">Reason: {reason}</p>}
              <p className="text-xs text-amber-200/80">Refresh the system status. The server accepts only contained or blocked modes.</p>
            </div>
            <div className="flex shrink-0 sm:self-center">
              <Button
                variant="outline"
                size="sm"
                className="gap-1.5 border-amber-500/40 text-amber-200 hover:bg-amber-500/10"
                onClick={() => sandbox.refetch()}
                aria-label="Refresh sandbox status"
              >
                <RefreshCw className="h-4 w-4" />
                Refresh status
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>
    </>
  );
}
