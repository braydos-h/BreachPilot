import { useEffect, useState } from "react";
import { Check, Loader2 } from "lucide-react";
import { cn } from "@/lib/utils";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

/** Live startup state for run creation. `phase: "sending"` = POST in flight;
 *  `"preparing"` = run accepted, backend preparation in progress. */
export interface RunStartupState {
  phase: "sending" | "preparing";
  /** Latest backend preparation stage id ("" until the first event arrives). */
  backendStage: string;
  /** Latest backend preparation message (safe, operator-facing). */
  message: string;
  /** Date.now() of the launch click — drives the slow-startup hint. */
  startedAt: number;
}

/** Backend preparation stages grouped into three user-facing steps. */
const STAGE_GROUPS: { id: string; label: string; stages: string[] }[] = [
  {
    id: "runtime",
    label: "Preparing runtime",
    stages: ["config", "plugins", "router", "model", "skills"],
  },
  {
    id: "target",
    label: "Resolving target",
    stages: ["target_validate", "target_resolve"],
  },
  {
    id: "settings",
    label: "Loading run settings",
    stages: ["goals", "exploit_settings", "filesystem"],
  },
];

function stepState(index: number, activeIndex: number | null, done: boolean): "done" | "active" | "pending" {
  if (done) return "done";
  if (activeIndex === null || index < activeIndex) return "done";
  if (index === activeIndex) return "active";
  return "pending";
}

/** Startup panel shown from the instant Launch is clicked until the run is
 *  prepared. Real backend stage events drive the steps when available; the
 *  elapsed-time hint degrades gracefully (2s/10s) instead of leaving one
 *  unchanged spinner. No fake percentages. */
export function RunStartupProgress({ startup }: { startup: RunStartupState }) {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now()), 500);
    return () => clearInterval(timer);
  }, []);

  const elapsedSec = Math.max(0, (now - startup.startedAt) / 1000);
  const knownStage = STAGE_GROUPS.some((g) => g.stages.includes(startup.backendStage));
  const doneAll = startup.backendStage === "done";

  // Active user-facing step: the group containing the backend stage, the
  // runtime group as the default while the backend is still working, or
  // null while the POST itself is still in flight.
  const activeIndex = doneAll
    ? STAGE_GROUPS.length // everything prepared → "Waiting for agent" is active
    : knownStage
      ? STAGE_GROUPS.findIndex((g) => g.stages.includes(startup.backendStage))
      : startup.phase === "preparing"
        ? 0
        : null;

  const slowHint =
    elapsedSec >= 10
      ? "Still preparing — first-time initialization or network resolution can take longer."
      : elapsedSec >= 2
        ? "Preparing the runtime…"
        : "This can take a little longer the first time BreachPilot starts.";

  const steps: { key: string; label: string; detail: string; state: "done" | "active" | "pending" }[] = [
    {
      key: "received",
      label: startup.phase === "sending" ? "Sending request…" : "Request received",
      detail: "",
      state: startup.phase === "sending" ? "active" : "done",
    },
    ...STAGE_GROUPS.map((group, index) => ({
      key: group.id,
      label: group.label,
      detail:
        stepState(index, activeIndex, doneAll) === "active" && startup.message
          ? startup.backendStage === "done"
            ? ""
            : startup.message
          : "",
      state: stepState(index, activeIndex, doneAll),
    })),
    {
      key: "agent",
      label: "Waiting for agent",
      detail: "",
      state: stepState(STAGE_GROUPS.length, activeIndex, doneAll),
    },
  ];

  return (
    <Card className="border-primary/30">
      <CardHeader className="pb-2">
        <CardTitle className="flex items-center gap-2 text-sm">
          <Loader2 className="h-4 w-4 animate-spin text-primary" aria-hidden />
          Starting your run
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        <ol className="space-y-1.5" aria-live="polite">
          {steps.map((step) => (
            <li key={step.key} className="flex items-start gap-2 text-sm">
              {step.state === "done" ? (
                <Check className="mt-0.5 h-4 w-4 shrink-0 text-emerald-400" aria-hidden />
              ) : step.state === "active" ? (
                <Loader2 className="mt-0.5 h-4 w-4 shrink-0 animate-spin text-primary" aria-hidden />
              ) : (
                <span
                  className="mt-1 h-2 w-2 shrink-0 rounded-full border border-muted-foreground/50"
                  aria-hidden
                />
              )}
              <span className="min-w-0">
                <span
                  className={cn(
                    "font-medium",
                    step.state === "done" && "text-muted-foreground",
                    step.state === "pending" && "text-muted-foreground/70",
                  )}
                >
                  {step.label}
                </span>
                {step.detail && (
                  <span className="block text-xs text-muted-foreground">{step.detail}</span>
                )}
              </span>
            </li>
          ))}
        </ol>
        <p className="text-xs text-muted-foreground">{slowHint}</p>
      </CardContent>
    </Card>
  );
}
