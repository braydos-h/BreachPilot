import { Check, ChevronDown, Loader2, ShieldAlert, ShieldCheck, Trash2, Zap } from "lucide-react";
import type { SkillDetail } from "@/api/types";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { CopyButton } from "@/components/CopyButton";
import { STATE_META, skillState, type SkillsConfig } from "./skillsConfig";
import { SkillDetailMeta } from "./SkillDetailMeta";

export function SkillDetailHeader({
  detail,
  cfg,
  patchPending,
  removePending,
  onEnable,
  onAuto,
  onBlock,
  onDelete,
}: {
  detail: SkillDetail;
  cfg: SkillsConfig;
  patchPending?: boolean;
  removePending?: boolean;
  onEnable: () => void;
  onAuto: () => void;
  onBlock: () => void;
  onDelete: () => void;
}) {
  const st = skillState(detail.name, cfg);
  const meta = STATE_META[st];
  const StateIcon = meta.icon;
  return (
    <div className="sticky top-0 z-10 border-b bg-card/80 backdrop-blur supports-[backdrop-filter]:bg-card/70">
      <div className="space-y-3 p-4">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="min-w-0 flex-1">
            <div className="flex flex-wrap items-center gap-2">
              <h2 className="truncate font-mono text-base font-semibold">{detail.name}</h2>
              {detail.version && (
                <Badge variant="outline" className="shrink-0 text-[10px] tabular-nums">
                  v{detail.version}
                </Badge>
              )}
              <Badge variant={meta.variant} className="gap-1 text-[10px]">
                <StateIcon className="h-3 w-3" /> {meta.label}
              </Badge>
            </div>
            <p className="mt-1.5 line-clamp-3 text-sm leading-relaxed text-muted-foreground">
              {detail.description || "No description provided."}
            </p>
          </div>
          <div className="flex shrink-0 items-center gap-1.5">
            <CopyButton value={detail.body} label="Copy Markdown" size="sm" className="h-8" />
            <Popover>
              <PopoverTrigger asChild>
                <Button variant="outline" size="sm" className="h-8 gap-1.5" disabled={patchPending}>
                  <StateIcon className="h-3.5 w-3.5" />
                  {meta.label}
                  <ChevronDown className="h-3 w-3 opacity-50" />
                </Button>
              </PopoverTrigger>
              <PopoverContent align="end" className="w-44 p-1">
                <div className="p-1">
                  <div className="px-2 py-1 text-[11px] font-semibold uppercase tracking-wide text-muted-foreground">
                    Change state
                  </div>
                  <button
                    type="button"
                    disabled={patchPending || st === "enabled"}
                    onClick={onEnable}
                    className="flex w-full items-center gap-2 rounded-sm px-2 py-1.5 text-xs hover:bg-accent disabled:opacity-50"
                  >
                    <ShieldCheck className="h-3.5 w-3.5 text-emerald-500" /> Enabled{" "}
                    {st === "enabled" && <Check className="ml-auto h-3 w-3" />}
                  </button>
                  <button
                    type="button"
                    disabled={patchPending || st === "auto"}
                    onClick={onAuto}
                    className="flex w-full items-center gap-2 rounded-sm px-2 py-1.5 text-xs hover:bg-accent disabled:opacity-50"
                  >
                    <Zap className="h-3.5 w-3.5 text-zinc-500" /> Auto{" "}
                    {st === "auto" && <Check className="ml-auto h-3 w-3" />}
                  </button>
                  <button
                    type="button"
                    disabled={patchPending || st === "blocked"}
                    onClick={onBlock}
                    className="flex w-full items-center gap-2 rounded-sm px-2 py-1.5 text-xs hover:bg-accent disabled:opacity-50"
                  >
                    <ShieldAlert className="h-3.5 w-3.5 text-red-500" /> Blocked{" "}
                    {st === "blocked" && <Check className="ml-auto h-3 w-3" />}
                  </button>
                </div>
              </PopoverContent>
            </Popover>
            <Button
              variant="ghost"
              size="sm"
              className="h-8 w-8 p-0 text-destructive hover:bg-destructive/10 hover:text-destructive"
              onClick={onDelete}
              disabled={removePending || patchPending}
              aria-label="Delete skill"
            >
              {removePending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Trash2 className="h-4 w-4" />}
            </Button>
          </div>
        </div>

        <SkillDetailMeta detail={detail} />
      </div>
    </div>
  );
}
