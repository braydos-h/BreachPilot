import { useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { Flag, Loader2, Play, SkipForward, Square } from "lucide-react";
import { CampaignView } from "@/components/OrchestrationViews";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { SegmentedControl } from "@/components/ui/segmented";
import { useCallTool, queryKeys } from "@/api/hooks";
import { ApiError } from "@/api/client";
import { AGGRESSION_LEVELS } from "@/lib/campaignPhases";

const CAMPAIGN_GOALS = [
  "initial_access",
  "privilege_escalation",
  "full_compromise",
  "lateral_movement",
] as const;

/** The control card is only useful when the exploit MCP session actually
 *  exposes the campaign tools (depends on the run's tool gate). */
const REQUIRED_TOOL = "start_autonomous_campaign";

interface CampaignTabProps {
  loading: boolean;
  error: unknown;
  state: unknown;
  runId: string;
  /** Run target (IP or domain) — pre-fills the start dialog. */
  target: string;
  runActive: boolean;
  /** Tool names the run's exploit session currently exposes. */
  tools: string[];
}

export function CampaignTab({ loading, error, state, runId, target, runActive, tools }: CampaignTabProps) {
  const showControls = runActive && tools.includes(REQUIRED_TOOL);
  return (
    <div className="space-y-2">
      {showControls && <CampaignControls runId={runId} target={target} />}
      <CampaignView loading={loading} error={error} state={state} />
    </div>
  );
}

function CampaignControls({ runId, target }: { runId: string; target: string }) {
  const qc = useQueryClient();
  const callTool = useCallTool(runId);
  const [goal, setGoal] = useState<string>("full_compromise");
  const [aggression, setAggression] = useState<string>("normal");
  const [campaignId, setCampaignId] = useState("");
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [lastResult, setLastResult] = useState("");
  const [errorText, setErrorText] = useState("");

  const onSettled = () => setConfirmOpen(false);
  const onError = (err: unknown) => {
    setConfirmOpen(false);
    // 403 = the exploit policy denied the call (read_only session, disabled
    // tool, or the mission scope gate). Everything else surfaces its message.
    setErrorText(
      err instanceof ApiError
        ? err.status === 403
          ? "The exploit policy denied this call."
          : err.message
        : "Tool call failed.",
    );
  };
  const onSuccess = (data: { result: string }, tool: string) => {
    setErrorText("");
    setLastResult(`[${tool}] ${data.result || "(no output)"}`);
    if (tool === "start_autonomous_campaign") {
      const match = /^CAMPAIGN_STARTED:\s*(\S+)/m.exec(data.result);
      if (match) setCampaignId(match[1]);
    }
    // Campaign state changes server-side on start/step/stop.
    void qc.invalidateQueries({ queryKey: queryKeys.runCampaign(runId) });
    setConfirmOpen(false);
  };

  const start = () =>
    callTool.mutate(
      {
        tool: "start_autonomous_campaign",
        arguments: { target_ip: target, goal, aggression_level: aggression },
      },
      { onSuccess: (data) => onSuccess(data, "start_autonomous_campaign"), onError, onSettled },
    );
  const step = () =>
    callTool.mutate(
      { tool: "run_campaign_step", arguments: { campaign_id: campaignId } },
      { onSuccess: (data) => onSuccess(data, "run_campaign_step"), onError },
    );
  const stop = () =>
    callTool.mutate(
      { tool: "stop_campaign", arguments: { campaign_id: campaignId } },
      { onSuccess: (data) => onSuccess(data, "stop_campaign"), onError },
    );

  const busy = callTool.isPending;

  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="flex items-center gap-2 text-sm">
          <Flag className="h-4 w-4" /> Manual campaign control
        </CardTitle>
        <p className="text-[10px] text-muted-foreground">
          Manually started campaigns run in the exploit workspace and are tracked separately from
          the attack_states.json snapshot below. The target-IP allowlist lock still applies.
        </p>
      </CardHeader>
      <CardContent className="space-y-3 text-xs">
        <div className="flex flex-wrap items-end gap-3">
          <div className="space-y-1">
            <Label className="text-[10px] text-muted-foreground">Goal</Label>
            <select
              value={goal}
              onChange={(e) => setGoal(e.target.value)}
              className="h-8 rounded-md border bg-background px-2 text-xs"
              aria-label="Campaign goal"
            >
              {CAMPAIGN_GOALS.map((g) => (
                <option key={g} value={g}>{g}</option>
              ))}
            </select>
          </div>
          <div className="space-y-1">
            <Label className="text-[10px] text-muted-foreground">Aggression</Label>
            <SegmentedControl
              value={aggression}
              onChange={setAggression}
              options={AGGRESSION_LEVELS.map((a) => ({ value: a, label: a }))}
              label="Campaign aggression"
            />
          </div>
          <Button size="sm" onClick={() => setConfirmOpen(true)} disabled={busy}>
            <Play className="h-3.5 w-3.5" /> Start campaign
          </Button>
        </div>

        <div className="flex flex-wrap items-end gap-2">
          <div className="min-w-0 flex-1 space-y-1">
            <Label htmlFor="campaign-id" className="text-[10px] text-muted-foreground">
              Campaign ID
            </Label>
            <Input
              id="campaign-id"
              value={campaignId}
              onChange={(e) => setCampaignId(e.target.value.trim())}
              placeholder="campaign-20260504_120000-abc12345"
              className="h-8 font-mono text-xs"
              spellCheck={false}
            />
          </div>
          <Button size="sm" variant="outline" onClick={step} disabled={!campaignId || busy}>
            {busy ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <SkipForward className="h-3.5 w-3.5" />}
            Step
          </Button>
          <Button size="sm" variant="destructive" onClick={stop} disabled={!campaignId || busy}>
            <Square className="h-3.5 w-3.5" /> Stop
          </Button>
        </div>

        {errorText && <p className="text-destructive" role="alert">{errorText}</p>}

        {lastResult && (
          <details>
            <summary className="cursor-pointer text-muted-foreground">Last tool result</summary>
            <pre className="mt-1 max-h-48 overflow-auto rounded-md border bg-muted/30 p-2 font-mono text-[10px] whitespace-pre-wrap">
              {lastResult}
            </pre>
          </details>
        )}
      </CardContent>

      <Dialog open={confirmOpen} onOpenChange={setConfirmOpen}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Flag className="h-4 w-4 text-primary" /> Start autonomous campaign?
            </DialogTitle>
            <DialogDescription className="text-sm">
              Launches a fully autonomous kill chain ({goal}, {aggression}) against{" "}
              <span className="font-mono">{target}</span> in a background thread. Each step can run
              for minutes.
            </DialogDescription>
          </DialogHeader>
          <p className="text-xs text-muted-foreground">
            The run&apos;s target-IP allowlist lock still applies — the campaign cannot touch hosts
            outside it. Aggression levels above <Badge variant="warn" className="text-[10px]">aggressive</Badge>{" "}
            escalate noise and risk on the target.
          </p>
          <DialogFooter>
            <Button variant="outline" onClick={() => setConfirmOpen(false)}>Cancel</Button>
            <Button onClick={start} disabled={busy}>
              {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />}
              Start campaign
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </Card>
  );
}