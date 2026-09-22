import { Hash } from "lucide-react";
import { cn } from "@/lib/utils";
import type { SkillSummary } from "@/api/types";
import { STATE_META, skillState, type SkillsConfig } from "./skillsConfig";
import { SkillRowActions } from "./SkillRowActions";

export function SkillCatalogRow({
  skill,
  skillsCfg,
  selected,
  patchPending,
  dimmed,
  onSelect,
  onEnable,
  onAuto,
  onBlock,
  onDelete,
}: {
  skill: SkillSummary;
  skillsCfg: SkillsConfig;
  selected: boolean;
  patchPending: boolean;
  dimmed: boolean;
  onSelect: () => void;
  onEnable: () => void;
  onAuto: () => void;
  onBlock: () => void;
  onDelete: () => void;
}) {
  const st = skillState(skill.name, skillsCfg);
  const meta = STATE_META[st];
  return (
    <div
      className={cn(
        "group relative flex flex-col rounded-lg border text-left transition-all",
        selected
          ? "border-primary/40 bg-primary/[0.06] shadow-sm"
          : "border-border bg-card hover:border-primary/20 hover:bg-accent/30",
        dimmed && "opacity-80",
      )}
    >
      <button
        type="button"
        onClick={onSelect}
        className="flex flex-col gap-1.5 p-3 text-left focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-inset rounded-lg"
        aria-pressed={selected}
        aria-label={`Select ${skill.name}`}
      >
        <div className="flex items-start justify-between gap-2">
          <span className="truncate font-mono text-sm font-semibold leading-none">{skill.name}</span>
          <span
            className={cn(
              "mt-0.5 inline-flex items-center gap-1.5 rounded-full border px-2 py-0.5 text-[10px] font-medium leading-none",
              st === "enabled"
                ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300"
                : st === "blocked"
                  ? "border-red-500/30 bg-red-500/10 text-red-600 dark:text-red-300"
                  : "border-border bg-muted text-muted-foreground",
            )}
          >
            <span className={cn("h-1.5 w-1.5 rounded-full", meta.dot)} aria-hidden />
            {meta.label}
          </span>
        </div>
        <p className="line-clamp-2 text-xs leading-relaxed text-muted-foreground">
          {skill.description || "No description"}
        </p>
        {skill.tags.length > 0 && (
          <div className="flex flex-wrap gap-1">
            {skill.tags.slice(0, 3).map((t) => (
              <span
                key={t}
                className="inline-flex items-center rounded bg-muted px-1.5 py-0.5 text-[10px] font-medium text-muted-foreground"
              >
                {t}
              </span>
            ))}
            {skill.tags.length > 3 && (
              <span className="text-[10px] text-muted-foreground">+{skill.tags.length - 3}</span>
            )}
          </div>
        )}
      </button>
      <div className="flex items-center justify-between gap-1 border-t bg-muted/20 px-2 py-1.5">
        <span className="flex items-center gap-1 text-[11px] text-muted-foreground">
          <Hash className="h-3 w-3" />
          <span className="truncate">{skill.tags.length} tags</span>
        </span>
        <SkillRowActions
          state={st}
          onEnable={onEnable}
          onAuto={onAuto}
          onBlock={onBlock}
          onDelete={onDelete}
          disabled={patchPending}
        />
      </div>
      {selected && (
        <div className="pointer-events-none absolute inset-y-0 left-0 w-0.5 rounded-l-lg bg-primary" aria-hidden />
      )}
    </div>
  );
}
