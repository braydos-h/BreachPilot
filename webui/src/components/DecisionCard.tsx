import { useMemo, useState } from "react";
import { AlertTriangle, Check, Loader2, Pencil } from "lucide-react";
import { cn } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { CopyButton } from "@/components/CopyButton";
import { GoalSuggestionCard } from "@/components/GoalSuggestionCard";
import { useAnswerDecision } from "@/api/hooks";
import { ApiError } from "@/api/client";
import type { DecisionListRow, SuggestedGoal } from "@/api/types";

interface DecisionCardProps {
  decision: DecisionListRow;
  runId: string;
  className?: string;
}

export function DecisionCard({ decision, runId, className }: DecisionCardProps) {
  const answer = useAnswerDecision(runId);
  const [text, setText] = useState("");
  const [customMode, setCustomMode] = useState(false);
  const [customText, setCustomText] = useState("");
  const [submitted, setSubmitted] = useState(false);

  const kind = decision.kind;
  const isAnswered = decision.status !== "pending";
  const requiredText = decision.required_text ?? "";
  const isDestructive = !!requiredText && kind !== "goal_select";
  const options = normalizeOptions(decision.options_json ?? decision.options);
  const aiGoals = options.filter((o) => o.is_ai_generated === true);
  const presetGoals = options.filter((o) => o.is_ai_generated !== true);

  const effectiveError = useMemo(() => {
    if (!answer.error) return "";
    if (answer.error instanceof ApiError) return answer.error.message;
    return "Failed to submit answer.";
  }, [answer.error]);

  const onSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (submitted || isAnswered) return;
    setSubmitted(true);
    answer.mutate(
      { decisionId: decision.id, answer: text },
      {
        onError: () => setSubmitted(false),
      },
    );
  };

  return (
    <div
      className={cn(
        "rounded-md border bg-card/60 p-3 text-sm",
        isAnswered ? "opacity-80" : isDestructive ? "border-destructive/50" : "border-yellow-500/40",
        className,
      )}
    >
      <div className="flex items-center gap-2">
        <Badge
          variant="outline"
          className={cn(
            kind === "tool_approval" && "border-destructive/40 text-red-300",
            kind === "start_confirm" && "border-yellow-500/40 text-yellow-300",
            kind === "goal_select" && "text-muted-foreground",
          )}
        >
          {kind}
        </Badge>
        <span className="ml-auto text-xs text-muted-foreground">{decision.status}</span>
      </div>

      <div className="mt-2 whitespace-pre-wrap break-words text-sm">
        {decision.prompt_text || "Operator input required."}
      </div>

      {isDestructive && (
        <div className="mt-2 flex items-start gap-2 rounded border border-destructive/40 bg-destructive/10 p-2 text-xs text-red-200">
          <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
          <div className="space-y-1">
            <div>Destructive action. Type the exact confirmation to proceed:</div>
            <div className="flex items-center gap-2">
              <code className="rounded bg-muted px-1.5 py-0.5 font-mono">{requiredText}</code>
              <CopyButton value={requiredText} label="Copy" size="sm" />
            </div>
          </div>
        </div>
      )}

      {kind === "goal_select" && options.length > 0 && !isAnswered && (
        <form className="mt-3 space-y-2" onSubmit={onSubmit}>
          <div className="space-y-1.5">
            {aiGoals.length > 0 && (
              <>
                <div className="text-xs uppercase tracking-wide text-muted-foreground">AI-generated goals</div>
                {aiGoals.map((opt, i) => (
                  <GoalSuggestionCard
                    key={`ai-${i}`}
                    goal={opt}
                    selected={text === opt.name}
                    onClick={() => { setText(opt.name ?? ""); setCustomMode(false); setCustomText(""); }}
                  />
                ))}
              </>
            )}
            {presetGoals.length > 0 && (
              <>
                <div className="pt-1 text-xs uppercase tracking-wide text-muted-foreground">Preset goals</div>
                {presetGoals.map((opt, i) => (
                  <GoalSuggestionCard
                    key={`pre-${i}`}
                    goal={opt}
                    selected={text === opt.name}
                    onClick={() => { setText(opt.name ?? ""); setCustomMode(false); setCustomText(""); }}
                  />
                ))}
              </>
            )}
            <button
              type="button"
              onClick={() => { setCustomMode(true); setText(""); }}
              className={cn(
                "flex w-full items-center gap-2 rounded-md border p-2.5 text-left text-sm transition-colors hover:bg-accent",
                customMode && "border-primary bg-accent ring-1 ring-primary",
              )}
            >
              <Pencil className="h-4 w-4 shrink-0 text-muted-foreground" />
              <span>Custom goal (type your own)</span>
            </button>
            {customMode && (
              <Input
                value={customText}
                onChange={(e) => { setCustomText(e.target.value); setText(e.target.value); }}
                placeholder="Describe your custom goal..."
                autoFocus
                disabled={submitted}
              />
            )}
          </div>
          {effectiveError && <p className="text-xs text-destructive">{effectiveError}</p>}
          <Button type="submit" disabled={!text || submitted} className="w-full">
            {submitted ? <Loader2 className="h-4 w-4 animate-spin" /> : <Check className="h-4 w-4" />}
            Submit selection
          </Button>
        </form>
      )}

      {kind !== "goal_select" && !isAnswered && (
        <form className="mt-3 space-y-2" onSubmit={onSubmit}>
          <Label htmlFor={`answer-${decision.id}`}>
            {isDestructive ? "Confirmation text" : "Answer"}
          </Label>
          {kind === "tool_approval" && decision.prompt_text && decision.prompt_text.length > 120 ? (
            <Textarea
              id={`answer-${decision.id}`}
              value={text}
              onChange={(e) => setText(e.target.value)}
              placeholder={isDestructive ? requiredText : "y / yes"}
              disabled={submitted}
            />
          ) : (
            <Input
              id={`answer-${decision.id}`}
              value={text}
              onChange={(e) => setText(e.target.value)}
              placeholder={isDestructive ? requiredText : "y / yes"}
              disabled={submitted}
              autoComplete="off"
            />
          )}
          {effectiveError && <p className="text-xs text-destructive">{effectiveError}</p>}
          <Button type="submit" disabled={submitted || (isDestructive ? text !== requiredText : !text)} className="w-full">
            {submitted ? <Loader2 className="h-4 w-4 animate-spin" /> : <Check className="h-4 w-4" />}
            Submit answer
          </Button>
        </form>
      )}

      {isAnswered && (
        <div className="mt-3 text-xs text-muted-foreground">
          Answered: <span className="font-mono text-foreground">{decision.answer || "\u2014"}</span>
          {decision.answered_at && <div className="mt-0.5">{decision.answered_at}</div>}
        </div>
      )}
    </div>
  );
}

function normalizeOptions(options: unknown): SuggestedGoal[] {
  if (!Array.isArray(options)) return [];
  return options
    .filter((o): o is Record<string, unknown> => !!o && typeof o === "object")
    .map((o) => ({
      name: o.name as string | undefined,
      description: o.description as string | undefined,
      exploit_likelihood: (o.exploit_likelihood as string) ?? "Possible",
      success_rating: Number(o.success_rating ?? 0),
      rationale: o.rationale as string | undefined,
      compatible: o.compatible !== false,
      blocked_reason: o.blocked_reason as string | undefined,
      risk_requirement: o.risk_requirement as string | undefined,
      is_ai_generated: o.is_ai_generated === true,
    }));
}