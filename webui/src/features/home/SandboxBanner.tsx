import { useState } from "react";
import { Info, ShieldAlert, ShieldCheck, ShieldX, Wrench } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { useSandboxStatus } from "@/api/hooks";
import { SandboxFixDialog } from "./SandboxFixDialog";

export const FALLBACK_HINT =
  "Start Docker and build the sandbox image (docker build -t breachpilot-sandbox:latest docker/sandbox) to contain execution — until then commands run directly on this machine.";

/**
 * Sandbox posture banner for the home screen. Surfaced at startup so the
 * operator always knows the effective execution mode before launching a run.
 */
export function SandboxBanner() {
  const sandbox = useSandboxStatus();
  const [fixOpen, setFixOpen] = useState(false);
  if (sandbox.isLoading || sandbox.error || !sandbox.data) return null;
  const s = sandbox.data;
  const reason: string = s.fallback_reason || s.docker_error || "";
  const knownMode = ["contained", "disabled", "native_fallback", "blocked"].includes(s.mode ?? "");
  if (!knownMode) return null;

  if (s.mode === "contained") {
    return (
      <p className="flex items-center gap-1.5 text-xs text-muted-foreground" data-testid="sandbox-banner-contained">
        <ShieldCheck className="h-3.5 w-3.5 text-emerald-400" />
        Sandbox active — commands run inside the disposable Docker worker.
      </p>
    );
  }
  if (s.mode === "disabled") {
    return (
      <p className="flex items-center gap-1.5 text-xs text-muted-foreground" data-testid="sandbox-banner-disabled">
        <Info className="h-3.5 w-3.5" />
        Sandbox disabled — commands execute directly on the host (legacy mode). Enable it in settings for containment.
      </p>
    );
  }
  if (s.mode === "native_fallback") {
    return (
      <>
        <Card className="border-amber-500/40 bg-amber-500/5" data-testid="sandbox-banner-fallback">
          <CardContent className="p-3 text-sm">
            <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
              <div className="space-y-1 flex-1">
                <div className="flex flex-wrap items-center gap-2">
                  <ShieldAlert className="h-4 w-4 text-amber-300" />
                  <Badge variant="warn">Sandbox unavailable</Badge>
                  <span className="font-medium text-amber-200">
                    Running natively — execution is NOT contained.
                  </span>
                </div>
                {reason && <p className="text-xs text-muted-foreground">Reason: {reason}</p>}
                <p className="text-xs text-amber-200/80">{FALLBACK_HINT}</p>
                <p className="text-xs text-amber-200/60">Commands are currently executing directly on this host.</p>
              </div>
              <div className="flex shrink-0 sm:self-center">
                <Button
                  variant="outline"
                  size="sm"
                  className="gap-1.5 border-amber-500/40 text-amber-200 hover:bg-amber-500/10"
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
      <Card className="border-red-500/40 bg-red-500/5" data-testid="sandbox-banner-blocked">
        <CardContent className="p-3 text-sm">
          <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
            <div className="space-y-1 flex-1">
              <div className="flex flex-wrap items-center gap-2">
                <ShieldX className="h-4 w-4 text-red-300" />
                <Badge variant="danger">Sandbox required</Badge>
                <span className="font-medium text-red-200">
                  Execution is blocked — the sandbox is unavailable and fallback is disabled.
                </span>
              </div>
              {reason && <p className="text-xs text-muted-foreground">Reason: {reason}</p>}
              <p className="text-xs text-red-200/80">
                Start Docker and build the sandbox image, or set sandbox.fallback_native: true in config.yaml to allow
                uncontained native execution.
              </p>
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
