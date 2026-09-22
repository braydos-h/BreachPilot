import type { ReactNode } from "react";
import { AlertTriangle, CheckCircle2, Circle, Loader2, XCircle } from "lucide-react";
import type { SandboxFixJobResponse, SandboxFixPlanResponse } from "@/api/hooks";

export function FixPlanView({ plan }: { plan: SandboxFixPlanResponse }) {
  return (
    <>
      <div className="space-y-2">
        <h3 className="text-sm font-semibold">What BreachPilot will do</h3>
        {plan.steps.length === 0 ? (
          <p className="text-xs text-muted-foreground">No remediation steps are required. Docker and the sandbox image appear ready.</p>
        ) : (
          <ol className="space-y-2">
            {plan.steps.map((step, idx) => (
              <li key={step.id} className="flex gap-2 text-sm">
                <span className="font-mono text-xs text-muted-foreground mt-0.5">{idx + 1}.</span>
                <div className="flex-1">
                  <div className="font-medium text-sm">{step.title}</div>
                  <div className="text-xs text-muted-foreground">{step.description}</div>
                  {step.command_preview && (
                    <code className="mt-1 block rounded bg-muted px-2 py-1 text-xs font-mono break-all">
                      {step.command_preview}
                    </code>
                  )}
                  {step.requires_admin && (
                    <span className="mt-1 inline-flex items-center gap-1 text-[11px] text-amber-300">
                      <AlertTriangle className="h-3 w-3" /> Requires administrator privileges
                    </span>
                  )}
                  {step.manual && (
                    <span className="mt-1 block text-[11px] text-amber-300">Manual step – you may need to complete this by hand.</span>
                  )}
                </div>
              </li>
            ))}
          </ol>
        )}
        <p className="text-xs text-muted-foreground">
          After verification, BreachPilot will need to restart before the sandbox becomes active (boot-time decision).
        </p>
      </div>

      <div className="rounded-md border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-xs">
        <p className="font-medium text-amber-200">This may install software, start a system service, build a Docker image, and request administrator privileges.</p>
        <p className="mt-1 text-muted-foreground">
          Commands shown above will be executed on this host. BreachPilot will use explicit argument lists (no shell with untrusted input) and apply timeouts. Review the steps before continuing.
        </p>
      </div>
    </>
  );
}

export function FixProgressView({
  job,
  plan,
}: {
  job: SandboxFixJobResponse | undefined;
  plan: SandboxFixPlanResponse | undefined;
}) {
  const displaySteps = job?.steps ?? plan?.steps ?? [];
  return (
    <div className="space-y-3">
      <div className="flex items-center gap-2 text-sm font-medium">
        <Loader2 className="h-4 w-4 animate-spin" />
        Fixing sandbox...
      </div>
      <ul className="space-y-1.5">
        {displaySteps.map((s) => {
          const status = (s as unknown as { status: string }).status;
          let icon: ReactNode;
          if (status === "succeeded") icon = <CheckCircle2 className="h-4 w-4 text-emerald-400" />;
          else if (status === "running") icon = <Loader2 className="h-4 w-4 animate-spin text-blue-400" />;
          else if (status === "failed") icon = <XCircle className="h-4 w-4 text-red-400" />;
          else if (status === "pending") icon = <Circle className="h-4 w-4 text-muted-foreground/50" />;
          else icon = <Circle className="h-4 w-4 text-muted-foreground/30" />;
          const isRunning = status === "running";
          return (
            <li key={s.id} className="flex gap-2 text-sm items-start">
              <span className="mt-0.5">{icon}</span>
              <div className="flex-1">
                <div className={`text-sm ${isRunning ? "font-medium text-foreground" : status === "succeeded" ? "text-emerald-300" : status === "failed" ? "text-red-300" : "text-muted-foreground"}`}>
                  {s.title}
                  {isRunning && <span className="ml-2 text-xs text-blue-400">→ running</span>}
                  {status === "succeeded" && <span className="ml-2 text-xs text-emerald-400">✓ done</span>}
                </div>
                {isRunning && s.description && <p className="text-xs text-muted-foreground">{s.description}</p>}
                {(s as { output?: string }).output && isRunning && (
                  <p className="text-xs font-mono text-muted-foreground mt-1 break-all whitespace-pre-wrap">
                    {String((s as { output?: string }).output).slice(0, 500)}
                  </p>
                )}
              </div>
            </li>
          );
        })}
      </ul>
      {job?.steps?.some((s) => s.output || s.error) && (
        <details className="rounded border bg-muted/20 px-3 py-2">
          <summary className="cursor-pointer text-xs font-medium">Details / Command output</summary>
          <div className="mt-2 space-y-2 max-h-48 overflow-auto">
            {job.steps.map((s) => (
              <div key={s.id} className="text-xs">
                <div className="font-medium">{s.title} — {s.status}</div>
                {s.command_preview && <code className="block rounded bg-background px-2 py-1 font-mono break-all">{s.command_preview}</code>}
                {s.output && <pre className="mt-1 whitespace-pre-wrap break-all text-muted-foreground">{s.output.slice(0, 2000)}</pre>}
                {s.error && <pre className="mt-1 whitespace-pre-wrap break-all text-red-300">{s.error.slice(0, 2000)}</pre>}
              </div>
            ))}
          </div>
        </details>
      )}
    </div>
  );
}
