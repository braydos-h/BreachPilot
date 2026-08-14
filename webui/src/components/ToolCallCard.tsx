import { memo, useState } from "react";
import { ChevronDown, ChevronRight, Wrench } from "lucide-react";
import { cn } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";
import { CopyButton } from "@/components/CopyButton";

interface ToolCallCardProps {
  toolName: string;
  arguments?: unknown;
  result?: string;
  error?: string;
  started: boolean;
  completed: boolean;
  timestamp?: string;
  className?: string;
}

export const ToolCallCard = memo(function ToolCallCard({
  toolName,
  arguments: args,
  result,
  error,
  started,
  completed,
  timestamp,
  className,
}: ToolCallCardProps) {
  const [expanded, setExpanded] = useState(!completed);

  const argText = args ? safeStringify(args) : "";
  const resultText = result ?? "";
  const errorText = error ?? "";

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
      >
        {expanded ? <ChevronDown className="h-3.5 w-3.5" /> : <ChevronRight className="h-3.5 w-3.5" />}
        <Wrench className="h-3.5 w-3.5 text-muted-foreground" />
        <span className="font-mono text-xs">{toolName}</span>
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
        <div className="mt-2 space-y-2">
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
          {(resultText || errorText) && (
            <div>
              <div className="flex items-center justify-between">
                <span className="text-xs uppercase tracking-wide text-muted-foreground">
                  {errorText ? "Error" : "Result"}
                </span>
                {(resultText || errorText) && <CopyButton value={resultText || errorText} label="Copy" size="sm" />}
              </div>
              <pre
                className={cn(
                  "mt-1 max-h-72 overflow-auto rounded bg-muted/40 p-2 font-mono text-xs whitespace-pre-wrap break-words scrollbar-thin",
                  errorText && "text-red-300",
                )}
              >
                {errorText || resultText}
              </pre>
            </div>
          )}
          {timestamp && <div className="text-xs text-muted-foreground">{timestamp}</div>}
        </div>
      )}
    </div>
  );
});

function safeStringify(value: unknown): string {
  try {
    return typeof value === "string" ? value : JSON.stringify(value, null, 2);
  } catch {
    return String(value);
  }
}