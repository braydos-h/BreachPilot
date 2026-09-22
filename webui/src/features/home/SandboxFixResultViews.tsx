import { CheckCircle2, XCircle } from "lucide-react";
import type { SandboxFixJobResponse } from "@/api/hooks";

export function FixSuccessView({ job }: { job: SandboxFixJobResponse }) {
  return (
    <div className="space-y-3">
      <div className="flex items-center gap-2 text-sm font-medium text-emerald-300">
        <CheckCircle2 className="h-5 w-5" />
        Docker is ready
      </div>
      <p className="text-sm text-muted-foreground">
        The BreachPilot sandbox can now be used, but the current server was started in native fallback mode. Restart BreachPilot to activate containment.
      </p>
      <p className="text-xs text-muted-foreground">
        Current boot mode remains <span className="font-mono">native_fallback</span> until restart – the UI will not falsely claim this process is now contained.
      </p>
      <div className="rounded-md border border-emerald-500/20 bg-emerald-500/5 px-3 py-2 text-xs">
        To apply the fix: stop the current BreachPilot daemon and start it again (e.g., close the terminal and run <code className="font-mono">python main.py</code> again). After restart, the banner should show <span className="font-medium text-emerald-300">Sandbox active</span>.
      </div>
      <ul className="space-y-1">
        {job.steps.map((s) => (
          <li key={s.id} className="flex items-center gap-2 text-xs">
            <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" />
            <span className="text-muted-foreground">{s.title}</span>
          </li>
        ))}
      </ul>
      <details className="rounded border bg-muted/20 px-3 py-2">
        <summary className="cursor-pointer text-xs font-medium">Details</summary>
        <div className="mt-2 space-y-1">
          {job.steps.map((s) => (
            <div key={s.id} className="text-xs">
              <div className="font-medium">{s.title}</div>
              {s.output && <pre className="whitespace-pre-wrap break-all text-muted-foreground">{s.output.slice(0, 1000)}</pre>}
            </div>
          ))}
        </div>
      </details>
    </div>
  );
}

export function FixFailedView({ job }: { job: SandboxFixJobResponse }) {
  const failedStep = job?.steps?.find((s) => s.status === "failed");
  return (
    <div className="space-y-3">
      <div className="flex items-center gap-2 text-sm font-medium text-red-300">
        <XCircle className="h-5 w-5" />
        Sandbox fix failed
      </div>
      {failedStep ? (
        <div className="rounded-md border border-red-500/30 bg-red-500/5 px-3 py-2 text-sm">
          <p className="font-medium">Failed step: {failedStep.title}</p>
          {failedStep.command_preview && (
            <code className="mt-1 block rounded bg-background px-2 py-1 text-xs font-mono break-all">{failedStep.command_preview}</code>
          )}
          {(failedStep.error || failedStep.output) && (
            <pre className="mt-1 whitespace-pre-wrap break-all text-xs text-muted-foreground">
              {String(failedStep.error || failedStep.output).slice(0, 2000)}
            </pre>
          )}
        </div>
      ) : (
        <div className="rounded-md border border-red-500/30 bg-red-500/5 px-3 py-2 text-sm">
          <p>{job.error || "An unknown error occurred during remediation."}</p>
        </div>
      )}
      {job.error && !failedStep && (
        <p className="text-xs text-muted-foreground">Error: {job.error}</p>
      )}
      <details className="rounded border bg-muted/20 px-3 py-2">
        <summary className="cursor-pointer text-xs font-medium">Details / Command output</summary>
        <div className="mt-2 space-y-2">
          {job.steps.map((s) => (
            <div key={s.id} className="text-xs">
              <div className="font-medium">{s.title} — {s.status}</div>
              {s.command_preview && <code className="block rounded bg-background px-2 py-1 font-mono break-all">{s.command_preview}</code>}
              {s.output && <pre className="whitespace-pre-wrap break-all text-muted-foreground">{s.output.slice(0, 1000)}</pre>}
              {s.error && <pre className="whitespace-pre-wrap break-all text-red-300">{s.error.slice(0, 1000)}</pre>}
            </div>
          ))}
        </div>
      </details>
    </div>
  );
}
