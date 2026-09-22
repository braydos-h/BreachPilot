import { Plus, RefreshCw, ShieldAlert, ShieldCheck, Sparkles, Zap } from "lucide-react";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { Skeleton } from "@/components/Loading";
import type { SkillsPageState } from "./useSkillsPage";

export function SkillsHeader({ page }: { page: SkillsPageState }) {
  const { skills, total, enabledCount, autoCount, blockedCount, setAddOpen } = page;
  return (
    <header className="flex flex-col gap-4">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
        <div className="flex min-w-0 items-start gap-3">
          <div className="hidden h-10 w-10 shrink-0 items-center justify-center rounded-xl border bg-card shadow-sm sm:flex" aria-hidden>
            <Sparkles className="h-5 w-5 text-foreground" />
          </div>
          <div className="min-w-0">
            <h1 className="text-xl font-semibold leading-tight tracking-tight">Skills</h1>
            <p className="mt-1 max-w-2xl text-sm leading-relaxed text-muted-foreground">
              Manage the methodologies and specialist knowledge available to BreachPilot.
            </p>
          </div>
        </div>
        <div className="flex shrink-0 items-center gap-2">
          <Tooltip>
            <TooltipTrigger asChild>
              <Button
                size="sm"
                variant="outline"
                onClick={() => skills.refetch()}
                disabled={skills.isFetching}
                aria-label="Refresh skills catalog"
                className="h-9 w-9 p-0 sm:h-8 sm:w-8"
              >
                <RefreshCw className={cn("h-4 w-4", skills.isFetching && "animate-spin")} />
              </Button>
            </TooltipTrigger>
            <TooltipContent>Refresh catalog</TooltipContent>
          </Tooltip>
          <Button size="sm" onClick={() => setAddOpen(true)} className="h-9 gap-1.5 sm:h-8">
            <Plus className="h-4 w-4" />
            Add skill
          </Button>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-px overflow-hidden rounded-xl border bg-border sm:grid-cols-4">
        <HeaderStat label="Total" value={total} icon={Sparkles} loading={skills.isLoading} />
        <HeaderStat label="Enabled" value={enabledCount} icon={ShieldCheck} accent="emerald" loading={skills.isLoading} />
        <HeaderStat label="Auto" value={autoCount} icon={Zap} accent="zinc" loading={skills.isLoading} />
        <HeaderStat label="Blocked" value={blockedCount} icon={ShieldAlert} accent="red" loading={skills.isLoading} />
      </div>
    </header>
  );
}

function HeaderStat({
  label,
  value,
  icon: Icon,
  accent,
  loading,
}: {
  label: string;
  value: number;
  icon: typeof Sparkles;
  accent?: "emerald" | "red" | "zinc";
  loading?: boolean;
}) {
  const accentCls =
    accent === "emerald"
      ? "text-emerald-600 dark:text-emerald-300"
      : accent === "red"
        ? "text-red-600 dark:text-red-300"
        : accent === "zinc"
          ? "text-zinc-500 dark:text-zinc-400"
          : "text-foreground";
  return (
    <div className="bg-card/60 px-4 py-3">
      <div className="flex items-center gap-1.5 text-[10px] uppercase tracking-wide text-muted-foreground">
        <Icon className="h-3 w-3" /> {label}
      </div>
      <div className={cn("mt-1 font-mono text-xl font-semibold tabular-nums", accentCls)}>
        {loading ? <Skeleton className="h-6 w-12" /> : value}
      </div>
    </div>
  );
}
