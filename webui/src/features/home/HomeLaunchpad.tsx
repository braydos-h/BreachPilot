import { Link } from "react-router-dom";
import { Activity, ArrowRight, ScanSearch, Target } from "lucide-react";
import type { ReactNode } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { StatusBadge } from "@/components/StatusBadge";
import { Badge } from "@/components/ui/badge";
import type { HomePageState } from "./useHomePage";

export function HomeLaunchpad({ page }: { page: HomePageState }) {
  const { activeRun } = page;
  return (
    <section aria-label="Operator launchpad" className="grid gap-3 sm:grid-cols-2">
      {activeRun ? (
        <Card className="border-amber-500/40 bg-amber-500/5">
          <CardContent className="flex flex-wrap items-center gap-2 p-3 text-sm">
            <Activity className="h-4 w-4 text-amber-200" aria-hidden />
            <Badge variant="warn">Needs attention</Badge>
            <span className="truncate font-mono text-[13px]">{activeRun.target}</span>
            <StatusBadge state={activeRun.state} />
            <Button asChild size="sm" variant="outline" className="ml-auto">
              <Link to={`/runs/${activeRun.id}`}>Resume active</Link>
            </Button>
          </CardContent>
        </Card>
      ) : (
        <Card>
          <CardContent className="p-3 text-sm">
            <div className="font-medium">No active runs</div>
            <p className="mt-0.5 text-[13px] text-muted-foreground">Start a new assessment or verify readiness first.</p>
            <div className="mt-2 flex gap-2">
              <Button asChild size="sm">
                <Link to="/runs/new">New run</Link>
              </Button>
              <Button asChild size="sm" variant="outline">
                <Link to="/system">Run local self-test</Link>
              </Button>
            </div>
          </CardContent>
        </Card>
      )}
      <Card>
        <CardContent className="p-3 text-sm">
          <div className="font-medium">Explore without a target</div>
          <p className="mt-0.5 text-[13px] text-muted-foreground">Demo data is synthetic — no real target. Ideal first look.</p>
          <div className="mt-2 flex gap-2">
            <Button asChild size="sm" variant="outline">
              <Link to="/runs">Explore a demo run</Link>
            </Button>
            <Button asChild size="sm" variant="ghost">
              <Link to="/runs/new">Start a real run</Link>
            </Button>
          </div>
        </CardContent>
      </Card>
    </section>
  );
}

const ACCENTS = {
  cyan: {
    ring: "hover:border-primary/50 hover:glow-primary",
    icon: "text-primary",
  },
} as const;

export function HomeActions() {
  return (
    <section className="grid gap-3 sm:grid-cols-2 animate-fade-in-up" style={{ animationDelay: "0.1s" }}>
      <ActionCard
        to="/runs/new?path=recon"
        icon={<ScanSearch className="h-6 w-6" />}
        title="Recon & Suggest Goals"
        desc="Scan the target first, see what's open, then pick a goal from AI-ranked suggestions."
        accent="cyan"
      />
      <ActionCard
        to="/runs/new?path=attack"
        icon={<Target className="h-6 w-6" />}
        title="Attack"
        desc="Run a full exploitation session against a target with a preset or custom goal."
        accent="cyan"
      />
    </section>
  );
}

function ActionCard({
  to,
  icon,
  title,
  desc,
  accent,
}: {
  to: string;
  icon: ReactNode;
  title: string;
  desc: string;
  accent: keyof typeof ACCENTS;
}) {
  const a = ACCENTS[accent];
  return (
    <Link
      to={to}
      className={`group relative flex flex-col items-start gap-2 rounded-lg border bg-card/40 p-4 text-left transition-all hover:bg-accent focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring ${a.ring}`}
    >
      <div className={`rounded-md border bg-secondary/40 p-2 ${a.icon}`}>
        {icon}
      </div>
      <div className="space-y-0.5">
        <div className="text-sm font-medium">{title}</div>
        <p className="text-xs text-muted-foreground">{desc}</p>
      </div>
      <span className="mt-0.5 inline-flex items-center gap-1 text-xs text-muted-foreground transition-transform group-hover:translate-x-0.5">
        Start <ArrowRight className="h-3 w-3" />
      </span>
    </Link>
  );
}
