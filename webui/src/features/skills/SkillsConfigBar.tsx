import { AlertTriangle, ChevronDown, ChevronUp, Loader2, Settings2, Shield } from "lucide-react";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import type { SkillsPageState } from "./useSkillsPage";

export function SkillsConfigBar({ page }: { page: SkillsPageState }) {
  const { config, skills, skillsCfg, patch, masterEnabled, showFilters, setShowFilters, patchSkills } = page;
  return (
    <Card className={cn("overflow-hidden", !masterEnabled && "border-amber-500/30")}>
      <div className="flex items-center justify-between gap-3 border-b bg-muted/20 px-4 py-3">
        <div className="flex items-center gap-2.5">
          <div
            className={cn(
              "flex h-7 w-7 items-center justify-center rounded-md border",
              masterEnabled
                ? "bg-primary text-primary-foreground"
                : "bg-amber-500/10 text-amber-600 border-amber-500/20",
            )}
          >
            <Settings2 className="h-3.5 w-3.5" />
          </div>
          <div>
            <div className="text-sm font-semibold leading-none">Skills Configuration</div>
            <div className="text-xs text-muted-foreground">Control how skills are loaded and injected at runtime</div>
          </div>
        </div>
        <Button
          variant="ghost"
          size="sm"
          className="h-7 gap-1.5 text-xs"
          onClick={() => setShowFilters((v) => !v)}
          aria-expanded={showFilters}
          aria-controls="skills-config-panel"
        >
          {showFilters ? <ChevronUp className="h-3.5 w-3.5" /> : <ChevronDown className="h-3.5 w-3.5" />}
          {showFilters ? "Hide" : "Configure"}
        </Button>
      </div>
      <div id="skills-config-panel" className={cn(!showFilters && "hidden")}>
        <div className="grid gap-0 sm:grid-cols-3 sm:divide-x">
          <div className="relative bg-primary/[0.04] p-4">
            <div className="absolute inset-y-0 left-0 w-0.5 bg-primary" aria-hidden />
            <div className="flex items-start justify-between gap-3">
              <div className="space-y-1">
                <div className="flex items-center gap-1.5">
                  <Shield className="h-3.5 w-3.5 text-primary" />
                  <Label className="text-sm font-semibold">Skills enabled</Label>
                </div>
                <p className="text-xs leading-relaxed text-muted-foreground">
                  Master switch. When off, no skill hints are injected or looked up.
                </p>
              </div>
              <Switch
                checked={masterEnabled}
                onCheckedChange={(v) => patchSkills({ enabled: v })}
                disabled={patch.isPending || config.isLoading}
                aria-label="Toggle skills enabled"
              />
            </div>
            {patch.isPending && (
              <span className="mt-2 inline-flex items-center gap-1 text-[11px] text-muted-foreground">
                <Loader2 className="h-3 w-3 animate-spin" /> Saving…
              </span>
            )}
          </div>
          <div className="p-4">
            <div className="flex items-start justify-between gap-3">
              <div className="space-y-1">
                <Label className="text-xs font-medium">Allow model lookup</Label>
                <p className="text-xs leading-relaxed text-muted-foreground">
                  Let the model fetch skill methodology on demand via load_runtime_skill.
                </p>
              </div>
              <Switch
                checked={skillsCfg.allow_model_lookup ?? false}
                onCheckedChange={(v) => patchSkills({ allow_model_lookup: v })}
                disabled={patch.isPending || !masterEnabled}
                aria-label="Toggle model lookup"
              />
            </div>
          </div>
          <div className="p-4">
            <div className="flex items-start justify-between gap-3">
              <div className="space-y-1">
                <Label className="text-xs font-medium">Inject startup context</Label>
                <p className="text-xs leading-relaxed text-muted-foreground">
                  Bake selected skill hints into the system prompt at run start.
                </p>
              </div>
              <Switch
                checked={skillsCfg.inject_startup_context ?? false}
                onCheckedChange={(v) => patchSkills({ inject_startup_context: v })}
                disabled={patch.isPending || !masterEnabled}
                aria-label="Toggle inject startup context"
              />
            </div>
          </div>
        </div>
        {(skills.data?.error || config.error) && (
          <div className="flex items-center gap-2 border-t bg-destructive/5 px-4 py-2.5 text-xs text-destructive">
            <AlertTriangle className="h-3.5 w-3.5 shrink-0" />
            {skills.data?.error ?? "Could not load config."}
          </div>
        )}
      </div>
      {!masterEnabled && !showFilters && (
        <div className="flex items-center gap-2 border-t bg-amber-500/5 px-4 py-2 text-xs text-amber-700 dark:text-amber-300">
          <AlertTriangle className="h-3.5 w-3.5" />
          Skills system is disabled. The catalog is still browsable, but no skills will be injected or looked up at
          runtime.
        </div>
      )}
    </Card>
  );
}
