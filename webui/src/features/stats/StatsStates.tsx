import { Link } from "react-router-dom";
import { Activity, AlertTriangle, Cpu } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { Skeleton } from "@/components/Loading";

export function RunAnalyticsSkeleton() {
  return (
    <div className="grid gap-4 xl:grid-cols-[minmax(0,1.25fr)_minmax(22rem,0.75fr)]" role="status" aria-label="Loading run analytics">
      <Card>
        <CardHeader><Skeleton className="h-4 w-32" /><Skeleton className="h-3 w-56" /></CardHeader>
        <CardContent><Skeleton className="h-64 w-full" /></CardContent>
      </Card>
      <Card>
        <CardHeader><Skeleton className="h-4 w-40" /><Skeleton className="h-3 w-64" /></CardHeader>
        <CardContent className="space-y-4"><Skeleton className="h-6 w-full" /><Skeleton className="h-6 w-full" /><Skeleton className="h-6 w-full" /><Skeleton className="h-6 w-full" /></CardContent>
      </Card>
    </div>
  );
}

export function TelemetrySkeleton() {
  return (
    <div className="grid gap-4 xl:grid-cols-[minmax(0,1.25fr)_minmax(22rem,0.75fr)]" role="status" aria-label="Loading LLM telemetry">
      <Card><CardContent className="p-4"><Skeleton className="h-64 w-full" /></CardContent></Card>
      <Card><CardContent className="grid gap-3 p-4 sm:grid-cols-2"><Skeleton className="h-20 w-full" /><Skeleton className="h-20 w-full" /><Skeleton className="h-20 w-full" /><Skeleton className="h-20 w-full" /><Skeleton className="h-20 w-full" /><Skeleton className="h-20 w-full" /></CardContent></Card>
    </div>
  );
}

export function EmptyRunsState() {
  return (
    <Card>
      <CardContent className="flex flex-col items-center justify-center gap-3 p-8 text-center">
        <span className="flex h-10 w-10 items-center justify-center rounded-full bg-primary/10 text-primary"><Activity className="h-5 w-5" /></span>
        <div>
          <h2 className="font-medium">No run data yet</h2>
          <p className="mt-1 text-sm text-muted-foreground">Start a run and activity will appear here.</p>
        </div>
        <Button asChild size="sm"><Link to="/runs/new">Start a run</Link></Button>
      </CardContent>
    </Card>
  );
}

export function EmptyTelemetryState() {
  return (
    <Card>
      <CardContent className="flex flex-col items-center justify-center gap-3 p-8 text-center">
        <span className="flex h-10 w-10 items-center justify-center rounded-full bg-primary/10 text-primary"><Cpu className="h-5 w-5" /></span>
        <div>
          <h2 className="font-medium">No LLM telemetry yet</h2>
          <p className="mt-1 text-sm text-muted-foreground">Usage and performance will appear after the first model call.</p>
        </div>
      </CardContent>
    </Card>
  );
}

export function UnavailableCard({ title, message }: { title: string; message: string }) {
  return (
    <Card className="border-destructive/30">
      <CardContent className="flex items-center gap-3 p-4 text-sm">
        <AlertTriangle className="h-4 w-4 shrink-0 text-destructive" aria-hidden="true" />
        <div>
          <div className="font-medium">{title}</div>
          <div className="mt-0.5 text-muted-foreground">{message}</div>
        </div>
      </CardContent>
    </Card>
  );
}
