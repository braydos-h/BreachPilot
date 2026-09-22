import { AlertTriangle, BookOpen, Loader2 } from "lucide-react";
import { cn } from "@/lib/utils";
import { ApiError } from "@/api/client";
import type { SkillDetail } from "@/api/types";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { SkillDetailBody } from "./SkillDetailBody";
import { SkillDetailHeader } from "./SkillDetailHeader";
import { SkillReferences } from "./SkillReferences";
import type { SkillsConfig } from "./skillsConfig";
import type { SkillsPageState } from "./useSkillsPage";

export function SkillDetailPanel({ page }: { page: SkillsPageState }) {
  const {
    selected,
    detail,
    skillsCfg,
    patch,
    remove,
    total,
    enabledCount,
    autoCount,
    masterEnabled,
    onEnable,
    onAuto,
    onBlock,
    setConfirmDelete,
  } = page;
  return (
    <Card className={cn("flex min-h-[480px] flex-col overflow-hidden", !masterEnabled && "opacity-90")}>
      {!selected ? (
        <div className="flex flex-1 flex-col items-center justify-center gap-3 p-8 text-center">
          <div className="flex h-12 w-12 items-center justify-center rounded-xl border bg-muted/40">
            <BookOpen className="h-6 w-6 text-muted-foreground" />
          </div>
          <div className="space-y-1">
            <p className="text-sm font-semibold">Select a skill</p>
            <p className="max-w-sm text-sm leading-relaxed text-muted-foreground">
              Choose a skill from the catalog to inspect its methodology, sections, and references. Use search and
              filters to narrow the list.
            </p>
          </div>
          {total > 0 && (
            <p className="text-xs text-muted-foreground">
              {total} skills available · {enabledCount} enabled · {autoCount} auto
            </p>
          )}
        </div>
      ) : detail.isLoading ? (
        <div className="flex flex-1 items-center justify-center gap-2 p-8 text-sm text-muted-foreground">
          <Loader2 className="h-4 w-4 animate-spin" /> Loading skill…
        </div>
      ) : detail.error ? (
        <div className="flex flex-1 flex-col items-center justify-center gap-3 p-8 text-center">
          <AlertTriangle className="h-6 w-6 text-destructive" />
          <p className="text-sm font-medium text-destructive">Failed to load skill</p>
          <p className="text-xs text-muted-foreground">
            {detail.error instanceof ApiError ? detail.error.message : "Could not fetch skill details."}
          </p>
          <Button size="sm" variant="outline" onClick={() => detail.refetch()}>
            Retry
          </Button>
        </div>
      ) : detail.data ? (
        <SkillDetailView
          detail={detail.data}
          cfg={skillsCfg}
          patchPending={patch.isPending}
          removePending={remove.isPending && remove.variables === selected}
          onEnable={() => onEnable(detail.data!.name)}
          onAuto={() => onAuto(detail.data!.name)}
          onBlock={() => onBlock(detail.data!.name)}
          onDelete={() => setConfirmDelete(detail.data!.name)}
        />
      ) : null}
    </Card>
  );
}

export function SkillDetailView({
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
  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <SkillDetailHeader
        detail={detail}
        cfg={cfg}
        patchPending={patchPending}
        removePending={removePending}
        onEnable={onEnable}
        onAuto={onAuto}
        onBlock={onBlock}
        onDelete={onDelete}
      />
      <div className="min-h-0 flex-1 overflow-auto scrollbar-thin">
        <div className="space-y-4 p-4">
          <SkillDetailBody detail={detail} />
          <SkillReferences detail={detail} />
        </div>
      </div>
    </div>
  );
}
