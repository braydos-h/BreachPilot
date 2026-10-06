import { memo, useId, useState } from "react";
import { ChevronDown, ChevronRight, Wrench } from "lucide-react";
import { cn } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";
import { CopyButton } from "@/components/CopyButton";
import { safeStringify } from "@/lib/format";

interface ToolCallCardProps {
  toolName: string;
  arguments?: unknown;
  result?: string;
  error?: string;
  operational_status?: string;
  exploit_outcome?: string;
  verified_success?: boolean;
  started: boolean;
  completed: boolean;
  timestamp?: string;
  className?: string;
}

function normalizedLabel(value: string | undefined): string {
  const normalized = value?.trim().replace(/[_-]+/g, " ").toLowerCase();
  return normalized || "unknown";
}

export const ToolCallCard = memo(function ToolCallCard({
  toolName,
  arguments: args,
  result,
  error,
  operational_status,
  exploit_outcome,
  verified_success,
  started,
  completed,
  timestamp,
  className,
}: ToolCallCardProps) {
  const panelId = useId();
  const [expanded, setExpanded] = useState(!completed);

  const argText = args ? safeStringify(args) : "";
  const resultText = result ?? "";
  const errorText = error ?? "";
  const outcomeLabel = normalizedLabel(exploit_outcome);
  const verificationRelevant = verified_success === true || outcomeLabel !== "none";
  // Only the explicit structured field grants verified status; result text is
  // always display-only evidence and must never change this label.
  const verificationLabel = verified_success === true ? "Verified" : outcomeLabel === "none" ? "Not applicable" : "Not verified";

  return (
    <div
      className={cn(
        "rounded-md border bg-card/50 p-3 text-sm",
        completed && errorText && "border-destructive/40",
        !completed && started && "border-primary/30",
        className,
      )}
    >
      <button
        type="button"
        className="flex w-full items-center gap-2 text-left"
        onClick={() => setExpanded((v) => !v)}
        aria-expanded={expanded}
        aria-controls={expanded ? panelId : undefined}
      >
        {expanded ? <ChevronDown className="h-3.5 w-3.5" /> : <ChevronRight className="h-3.5 w-3.5" />}
        <Wrench className="h-3.5 w-3.5 text-muted-foreground" />
        <span className="font-mono text-xs">{toolName}</span>
        {completed && verificationRelevant && (
          <Badge
            variant={verified_success === true ? "success" : "warn"}
          >
            {verificationLabel}
          </Badge>
        )}
        <Badge
          variant={
            completed
              ? (errorText ? "danger" : "success")
              : started
                ? "warn"
                : "muted"
          }
          className={cn("ml-auto", !completed && started && "animate-pulse-ring")}
        >
          {completed ? (errorText ? "error" : "done") : started ? "running" : "queued"}
        </Badge>
      </button>
      {expanded && (
        <div id={panelId} className="mt-2 space-y-2">
          {completed && (
            <dl className="flex flex-wrap gap-x-4 gap-y-1 rounded bg-muted/30 px-2 py-1.5 text-xs">
              <div className="flex gap-1">
                <dt className="text-muted-foreground">Operational status:</dt>
                <dd>{normalizedLabel(operational_status)}</dd>
              </div>
              <div className="flex gap-1">
                <dt className="text-muted-foreground">Reported outcome:</dt>
                <dd>{outcomeLabel}</dd>
              </div>
              <div className="flex gap-1">
                <dt className="text-muted-foreground">Verification:</dt>
                <dd>{verificationLabel}</dd>
              </div>
            </dl>
          )}
          {argText && (
            <div>
              <div className="flex items-center justify-between">
                <span className="text-xs uppercase tracking-wide text-muted-foreground">Arguments</span>
                <CopyButton value={argText} label="Copy" size="sm" />
              </div>
              <pre className="mt-1 max-h-60 overflow-auto rounded bg-muted/40 p-2 font-mono text-xs scrollbar-thin">
                {argText}
              </pre>
            </div>
          )}
          {errorText && (
            <div>
              <div className="flex items-center justify-between">
                <span className="text-xs uppercase tracking-wide text-muted-foreground">Error</span>
                <CopyButton value={errorText} label="Copy" size="sm" />
              </div>
              <pre
                className={cn(
                  "mt-1 max-h-72 overflow-auto rounded bg-muted/40 p-2 font-mono text-xs whitespace-pre-wrap break-words scrollbar-thin",
                  "text-red-300",
                )}
              >
                {errorText}
              </pre>
            </div>
          )}
          {resultText && (
            <div>
              <div className="flex items-center justify-between">
                <span className="text-xs uppercase tracking-wide text-muted-foreground">Result</span>
                <CopyButton value={resultText} label="Copy" size="sm" />
              </div>
              <pre className="mt-1 max-h-72 overflow-auto rounded bg-muted/40 p-2 font-mono text-xs whitespace-pre-wrap break-words scrollbar-thin">
                {resultText}
              </pre>
            </div>
          )}
          {timestamp && <div className="text-xs text-muted-foreground">{timestamp}</div>}
        </div>
      )}
    </div>
  );
});
