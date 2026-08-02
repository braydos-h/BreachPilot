import { Link } from "react-router-dom";
import { Activity, ScanSearch, Zap, ArrowRight } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { StatusBadge } from "@/components/StatusBadge";
import { useRuns } from "@/api/hooks";
import { isActiveState } from "@/api/types";

export function HomePage() {
  const runs = useRuns(50, 0);
  const activeRun = runs.data?.runs.find((r) => isActiveState(r.state));

  return (
    <div className="mx-auto max-w-3xl space-y-6 p-4 md:p-6">
      <div className="space-y-1">
        <h1 className="text-xl font-semibold">NetAttackAI</h1>
        <p className="text-sm text-muted-foreground">
          AI-driven penetration testing console. Choose how to start an assessment.
        </p>
      </div>

      {activeRun && (
        <Card className="border-yellow-500/40 bg-yellow-500/5">
          <CardContent className="flex flex-wrap items-center gap-2 p-3 text-sm">
            <Activity className="h-4 w-4 animate-pulse text-yellow-300" />
            <Badge variant="outline" className="border-yellow-500/40 text-yellow-300">Active</Badge>
            <span className="truncate font-mono text-xs">{activeRun.target}</span>
            <StatusBadge state={activeRun.state} />
            <Button asChild size="sm" variant="outline" className="ml-auto">
              <Link to={`/runs/${activeRun.id}`}>Open run</Link>
            </Button>
          </CardContent>
        </Card>
      )}

      <div className="grid gap-3 sm:grid-cols-2">
        <Link
          to="/runs/new?path=recon"
          className="flex flex-col items-start gap-3 rounded-lg border bg-card/40 p-6 text-left transition-colors hover:border-primary hover:bg-accent focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
        >
          <div className="rounded-md border bg-secondary/40 p-2.5"><ScanSearch className="h-7 w-7" /></div>
          <div className="space-y-1">
            <div className="text-base font-medium">Recon & Suggest Goals</div>
            <p className="text-xs text-muted-foreground">
              Scan the target first, see what's open, then pick a goal from AI-ranked suggestions.
            </p>
          </div>
          <span className="mt-1 inline-flex items-center gap-1 text-xs text-muted-foreground">
            Start <ArrowRight className="h-3 w-3" />
          </span>
        </Link>
        <Link
          to="/runs/new?path=attack"
          className="flex flex-col items-start gap-3 rounded-lg border bg-card/40 p-6 text-left transition-colors hover:border-primary hover:bg-accent focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
        >
          <div className="rounded-md border bg-secondary/40 p-2.5"><Zap className="h-7 w-7" /></div>
          <div className="space-y-1">
            <div className="text-base font-medium">Start New Session</div>
            <p className="text-xs text-muted-foreground">
              Go straight to attack mode with a preset or custom goal.
            </p>
          </div>
          <span className="mt-1 inline-flex items-center gap-1 text-xs text-muted-foreground">
            Start <ArrowRight className="h-3 w-3" />
          </span>
        </Link>
      </div>

      <div className="flex items-center justify-between rounded-md border bg-card/30 px-4 py-3">
        <div>
          <div className="text-sm font-medium">Past sessions</div>
          <p className="text-xs text-muted-foreground">Review, resume, or delete previous runs.</p>
        </div>
        <Button asChild size="sm" variant="outline">
          <Link to="/sessions">View sessions</Link>
        </Button>
      </div>
    </div>
  );
}