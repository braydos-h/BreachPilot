import { ArrowDown, ArrowUp, ArrowUpDown, Layers } from "lucide-react";
import { cn } from "@/lib/utils";
import { Card } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { CopyButton } from "@/components/CopyButton";
import type { SortDir, SortKey } from "./connectionFormat";

export function ConnectionsHeaderStat({
  label,
  value,
  accent,
  Icon,
  loading,
}: {
  label: string;
  value: number;
  accent?: "emerald" | "amber" | "red";
  Icon: typeof Layers;
  loading: boolean;
}) {
  const accentClass =
    accent === "emerald"
      ? "text-emerald-600 dark:text-emerald-300"
      : accent === "amber"
        ? "text-amber-600 dark:text-amber-300"
        : accent === "red"
          ? "text-red-600 dark:text-red-300"
          : "text-foreground";
  return (
    <div className="flex items-center gap-2.5 bg-card px-4 py-3">
      <Icon className={cn("h-4 w-4 shrink-0", accent ? accentClass : "text-muted-foreground")} aria-hidden />
      <div className="min-w-0">
        <div className={cn("font-mono text-xl font-semibold leading-none tabular-nums", accentClass)}>
          {loading ? <Skeleton className="h-6 w-10" /> : value}
        </div>
        <div className="text-[10px] uppercase tracking-wide text-muted-foreground">{label}</div>
      </div>
    </div>
  );
}

export function SortTh({
  label,
  sortKey,
  activeKey,
  dir,
  onSort,
}: {
  label: string;
  sortKey: SortKey;
  activeKey: SortKey;
  dir: SortDir;
  onSort: (k: SortKey) => void;
}) {
  const active = activeKey === sortKey;
  return (
    <th scope="col" className="whitespace-nowrap px-3 py-2.5 text-left">
      <button
        type="button"
        onClick={() => onSort(sortKey)}
        className={cn(
          "inline-flex items-center gap-1 text-[11px] font-medium uppercase tracking-wide transition-colors hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-1",
          active ? "text-foreground" : "text-muted-foreground",
        )}
        aria-label={`Sort by ${label} ${active && dir === "asc" ? "descending" : "ascending"}`}
      >
        {label}
        <span aria-hidden className={cn("ml-0.5", active ? "opacity-100" : "opacity-40")}>
          {active ? (
            dir === "asc" ? (
              <ArrowUp className="h-3 w-3" />
            ) : (
              <ArrowDown className="h-3 w-3" />
            )
          ) : (
            <ArrowUpDown className="h-3 w-3" />
          )}
        </span>
      </button>
    </th>
  );
}

export function DetailRow({
  label,
  value,
  sub,
  mono,
  copyValue,
}: {
  label: string;
  value: string;
  sub?: string;
  mono?: boolean;
  copyValue?: string;
}) {
  return (
    <div className="flex items-start justify-between gap-3 bg-card px-3 py-2.5 last:rounded-b-lg">
      <div className="min-w-0 flex-1">
        <div className="text-[10px] font-medium uppercase tracking-wide text-muted-foreground">{label}</div>
        <div className={cn("mt-0.5 break-all text-sm", mono && "font-mono text-xs")}>{value}</div>
        {sub && <div className="mt-0.5 font-mono text-[10px] text-muted-foreground">{sub}</div>}
      </div>
      {copyValue && <CopyButton value={copyValue} size="icon" label={`Copy ${label}`} className="h-7 w-7 shrink-0" />}
    </div>
  );
}

export function ConnectionsSkeleton() {
  return (
    <div className="space-y-3" role="status" aria-label="Loading connections">
      <div className="overflow-hidden rounded-lg border">
        <div className="divide-y">
          <div className="flex items-center gap-3 bg-muted/20 px-3 py-2.5">
            {Array.from({ length: 7 }).map((_, i) => (
              <Skeleton key={i} className="h-3 flex-1" />
            ))}
          </div>
          {Array.from({ length: 5 }).map((_, i) => (
            <div key={i} className="flex items-center gap-3 px-3 py-3">
              <Skeleton className="h-4 w-24" />
              <Skeleton className="h-4 w-28" />
              <Skeleton className="h-5 w-16" />
              <Skeleton className="h-4 w-32" />
              <Skeleton className="h-4 flex-1" />
              <Skeleton className="h-4 w-20" />
              <Skeleton className="h-4 w-12" />
            </div>
          ))}
        </div>
      </div>
      <div className="grid gap-3 md:hidden">
        {Array.from({ length: 3 }).map((_, i) => (
          <Card key={i} className="p-3">
            <div className="space-y-2">
              <div className="flex justify-between">
                <Skeleton className="h-4 w-24" />
                <Skeleton className="h-5 w-14" />
              </div>
              <Skeleton className="h-3 w-full" />
              <Skeleton className="h-12 w-full" />
            </div>
          </Card>
        ))}
      </div>
    </div>
  );
}
