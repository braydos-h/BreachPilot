import { useMemo, useState } from "react";
import { AlertTriangle, Check, Loader2, Pencil, ShieldAlert } from "lucide-react";
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
import {
  checkpointVisual,
  detectCheckpointKind,
  parseCheckpointOptions,
  encodeCheckpointAnswer,
  toSuggestedGoal,
} from "@/lib/campaignCheckpoint";

interface DecisionCardProps {
  decision: DecisionListRow;
  runId: string;
  className?: string;
  autoAnswering?: boolean;
}

export function DecisionCard({ decision, runId, className, autoAnswering = false }: DecisionCardProps) {
  const answer = useAnswerDecision(runId);
  const [text, setText] = useState("");
  const [customMode, setCustomMode] = useState(false);
  const [customText, setCustomText] = useState("");
  const [submitted, setSubmitted] = useState(false);
  const [denying, setDenying] = useState(false);

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

  const submitAnswer = (value: string) => {
    if (submitted || denying || isAnswered || autoAnswering || !value) return;
    setSubmitted(true);
    answer.mutate(
      { decisionId: decision.id, answer: value },
      {
        onError: () => setSubmitted(false),
      },
    );
  };

  const onSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    submitAnswer(text);
  };

  const pickGoal = (name: string) => {
    setText(name);
    setCustomMode(false);
    setCustomText("");
    submitAnswer(name);
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

      {autoAnswering && !isAnswered && (
        <div className="mt-2 flex items-center gap-2 rounded border border-primary/40 bg-primary/10 p-2 text-xs text-primary">
          <Loader2 className="h-3.5 w-3.5 animate-spin" />
          <span>Auto-answering via permission mode…</span>
          {isDestructive && <ShieldAlert className="ml-auto h-3.5 w-3.5" />}
        </div>
      )}

      {kind === "goal_select" && options.length > 0 && !isAnswered && !autoAnswering && (
        <form className="mt-3 space-y-2" onSubmit={onSubmit}>
          <div className="space-y-1.5">
            {aiGoals.length > 0 && (
              <>
                <div className="text-xs uppercase tracking-wide text-muted-foreground">AI-generated goals</div>
                {aiGoals.map((opt, i) => {
                  const name = opt.name;
                  return (
                  <GoalSuggestionCard
                    key={`ai-${i}`}
                    goal={opt}
                    selected={text === name}
                    onClick={name ? () => pickGoal(name) : undefined}
                  />
                  );
                })}
              </>
            )}
            {presetGoals.length > 0 && (
              <>
                <div className="pt-1 text-xs uppercase tracking-wide text-muted-foreground">Preset goals</div>
                {presetGoals.map((opt, i) => {
                  const name = opt.name;
                  return (
                  <GoalSuggestionCard
                    key={`pre-${i}`}
                    goal={opt}
                    selected={text === name}
                    onClick={name ? () => pickGoal(name) : undefined}
                  />
                  );
                })}
              </>
            )}
            <button
              type="button"
              onClick={() => { setCustomMode(true); setText(""); setCustomText(""); }}
              aria-pressed={customMode}
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
          {customMode ? (
            <Button type="submit" disabled={!customText.trim() || submitted} className="w-full">
              {submitted ? <Loader2 className="h-4 w-4 animate-spin" /> : <Check className="h-4 w-4" />}
              Submit custom goal
            </Button>
          ) : (
            <p className="text-center text-[11px] text-muted-foreground">
              Click a goal to start it. Or pick custom to type your own.
            </p>
          )}
        </form>
      )}

      {kind === "campaign_next_step" && !isAnswered && !autoAnswering && (
        <CampaignCheckpointForm
          decision={decision}
          submitted={submitted}
          onSubmitAnswer={(value: string) => submitAnswer(value)}
        />
      )}

      {kind !== "goal_select" && kind !== "campaign_next_step" && !isAnswered && !autoAnswering && (
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
          <div className="flex gap-2">
            <Button type="submit" disabled={submitted || denying || (isDestructive ? text !== requiredText : !text)} className="flex-1">
              {submitted ? <Loader2 className="h-4 w-4 animate-spin" /> : <Check className="h-4 w-4" />}
              Submit answer
            </Button>
            {kind === "tool_approval" && (
              <Button
                type="button"
                variant="outline"
                disabled={submitted || denying}
                onClick={() => {
                  setDenying(true);
                  answer.mutate(
                    { decisionId: decision.id, answer: "deny" },
                    { onError: () => { setDenying(false); /* leave form armed */ } },
                  );
                }}
                className="text-destructive hover:text-destructive"
              >
                {denying ? <Loader2 className="h-4 w-4 animate-spin" /> : null}
                Deny
              </Button>
            )}
          </div>
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

// ── Mid-run operator checkpoint (CAMPAIGN_NEXT_STEP) ──────────────────────────
// Renders the evidence summary with a visually distinct border (green for
// "Verified access obtained", amber for "No verified access yet") and offers
// the operator's choices as action buttons. Goal-bearing options reuse the
// existing GoalSuggestionCard to pick a nested goal.

interface CampaignCheckpointFormProps {
  decision: DecisionListRow;
  submitted: boolean;
  onSubmitAnswer: (value: string) => void;
}

function CampaignCheckpointForm({ decision, submitted, onSubmitAnswer }: CampaignCheckpointFormProps) {
  const promptText = decision.prompt_text ?? "";
  const kind = detectCheckpointKind(promptText);
  const visual = checkpointVisual(kind);
  const options = useMemo(() => parseCheckpointOptions(decision.options_json ?? decision.options), [decision.options_json, decision.options]);
  const [expandedAction, setExpandedAction] = useState<string | null>(null);
  const [customText, setCustomText] = useState("");

  const submit = (value: string) => {
    if (submitted || !value) return;
    onSubmitAnswer(value);
  };

  return (
    <div className={cn("mt-3 space-y-3 rounded-md border p-3", visual.borderClass)}>
      <div className="flex items-center gap-2">
        <Badge variant="outline" className={visual.badgeClass}>
          {visual.title}
        </Badge>
        <span className="text-xs text-muted-foreground">campaign checkpoint</span>
      </div>

      {/* Evidence summary — the backend's prompt_text, preserved as-is */}
      <pre className="whitespace-pre-wrap break-words rounded bg-muted/40 p-2 font-mono text-xs">
        {promptText || "Operator checkpoint."}
      </pre>

      <div className="space-y-2">
        {options.map((opt) => {
          const hasGoals = !!opt.goals && opt.goals.length > 0;
          const isExpanded = expandedAction === opt.action;
          return (
            <div key={opt.action} className="space-y-2">
              <Button
                type="button"
                variant={hasGoals ? "outline" : "default"}
                size="sm"
                className="w-full justify-start"
                disabled={submitted}
                aria-expanded={hasGoals ? isExpanded : undefined}
                aria-controls={hasGoals ? `checkpoint-actions-${opt.action}` : undefined}
                onClick={() => {
                  if (hasGoals) {
                    setExpandedAction(isExpanded ? null : opt.action);
                    setCustomText("");
                    return;
                  }
                  submit(encodeCheckpointAnswer(opt));
                }}
              >
                {submitted && expandedAction === opt.action ? <Loader2 className="h-4 w-4 animate-spin" /> : <Check className="h-4 w-4" />}
                {opt.label}
              </Button>
              {hasGoals && isExpanded && (
                <div id={`checkpoint-actions-${opt.action}`} className="space-y-1.5 rounded-md border bg-card/40 p-2">
                  {opt.goals!.map((g) => (
                    <GoalSuggestionCard
                      key={g.name}
                      goal={toSuggestedGoal(g)}
                      onClick={submitted ? undefined : () => submit(encodeCheckpointAnswer(opt, g.name))}
                    />
                  ))}
                  {/* Custom goal entry — the backend's "custom" pseudo-goal */}
                  <button
                    type="button"
                    onClick={() => {
                      setExpandedAction(opt.action);
                      setCustomText("");
                    }}
                    className={cn(
                      "flex w-full items-center gap-2 rounded-md border p-2.5 text-left text-sm transition-colors hover:bg-accent",
                      customText && "border-primary bg-accent ring-1 ring-primary",
                    )}
                  >
                    <Pencil className="h-4 w-4 shrink-0 text-muted-foreground" />
                    <span>Custom goal (type your own)</span>
                  </button>
                  {customText !== "" || expandedAction === opt.action ? (
                    <div className="space-y-2">
                      <Input
                        value={customText}
                        onChange={(e) => setCustomText(e.target.value)}
                        placeholder="Describe your custom goal..."
                        autoFocus
                        disabled={submitted}
                      />
                      <Button
                        type="button"
                        size="sm"
                        className="w-full"
                        disabled={!customText.trim() || submitted}
                        onClick={() => submit(encodeCheckpointAnswer(opt, "custom", customText))}
                      >
                        {submitted ? <Loader2 className="h-4 w-4 animate-spin" /> : <Check className="h-4 w-4" />}
                        Submit custom goal
                      </Button>
                    </div>
                  ) : null}
                </div>
              )}
            </div>
          );
        })}
      </div>
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