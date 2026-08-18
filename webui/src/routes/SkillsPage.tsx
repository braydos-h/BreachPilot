import { useMemo, useState } from "react";
import { Loader2, Plus, RefreshCw, Search, Trash2 } from "lucide-react";
import { cn } from "@/lib/utils";
import { ApiError } from "@/api/client";
import {
  useConfig,
  useInstallSkill,
  usePatchConfig,
  useRemoveSkill,
  useSkillDetail,
  useSkillSearch,
  useSkills,
} from "@/api/hooks";
import type { SkillSummary } from "@/api/types";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Textarea } from "@/components/ui/textarea";
import { useToast } from "@/hooks/use-toast";
import { SkeletonRows } from "@/components/Loading";

interface SkillsConfig {
  enabled?: boolean;
  default_enabled?: string[];
  exclude_names?: string[];
  allow_model_lookup?: boolean;
  inject_startup_context?: boolean;
  roots?: string[];
}

function readSkillsConfig(cfg: unknown): SkillsConfig {
  if (cfg && typeof cfg === "object") {
    const skills = (cfg as Record<string, unknown>).skills;
    if (skills && typeof skills === "object") {
      return skills as SkillsConfig;
    }
  }
  return {};
}

type SkillState = "enabled" | "blocked" | "auto";

function skillState(name: string, cfg: SkillsConfig): SkillState {
  if ((cfg.exclude_names ?? []).includes(name)) return "blocked";
  if ((cfg.default_enabled ?? []).includes(name)) return "enabled";
  return "auto";
}

export function SkillsPage() {
  const config = useConfig();
  const skills = useSkills();
  const [query, setQuery] = useState("");
  const search = useSkillSearch(query, query.trim().length > 0);
  const [selected, setSelected] = useState<string | null>(null);
  const detail = useSkillDetail(selected);
  const patch = usePatchConfig();
  const install = useInstallSkill();
  const remove = useRemoveSkill();
  const { toast } = useToast();
  const [addOpen, setAddOpen] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState<string | null>(null);
  const [draftName, setDraftName] = useState("");
  const [draftMarkdown, setDraftMarkdown] = useState("");
  const [draftError, setDraftError] = useState("");

  const skillsCfg = useMemo(() => readSkillsConfig(config.data), [config.data]);
  const list = query.trim() ? search.data?.results ?? [] : skills.data?.skills ?? [];
  const normalized = list.map((s) => ({
    name: s.name,
    description: s.description,
    tags: "tags" in s ? (s as SkillSummary).tags : [],
  }));

  const patchSkills = (next: Partial<SkillsConfig>) => {
    patch.mutate({ skills: next } as Record<string, unknown>, {
      onError: (err) => {
        toast({
          title: "Config update failed",
          description: err instanceof ApiError ? err.message : "Could not update skills config.",
          variant: "destructive",
        });
      },
    });
  };

  const onEnable = (name: string) => {
    const enabled = new Set(skillsCfg.default_enabled ?? []);
    const exclude = new Set(skillsCfg.exclude_names ?? []);
    enabled.add(name);
    exclude.delete(name);
    patchSkills({
      default_enabled: Array.from(enabled),
      exclude_names: Array.from(exclude),
    });
  };

  const onDisable = (name: string) => {
    const enabled = new Set(skillsCfg.default_enabled ?? []);
    enabled.delete(name);
    patchSkills({ default_enabled: Array.from(enabled) });
  };

  const onBlock = (name: string) => {
    const enabled = new Set(skillsCfg.default_enabled ?? []);
    enabled.delete(name);
    const exclude = new Set(skillsCfg.exclude_names ?? []);
    exclude.add(name);
    patchSkills({
      default_enabled: Array.from(enabled),
      exclude_names: Array.from(exclude),
    });
  };

  const onDelete = (name: string) => {
    // Also drop it from any config lists so toggles don't reference a gone skill.
    const enabled = new Set(skillsCfg.default_enabled ?? []);
    const exclude = new Set(skillsCfg.exclude_names ?? []);
    enabled.delete(name);
    exclude.delete(name);
    remove.mutate(name, {
      onSuccess: () => {
        if (selected === name) setSelected(null);
        if (enabled.size !== (skillsCfg.default_enabled ?? []).length ||
            exclude.size !== (skillsCfg.exclude_names ?? []).length) {
          patchSkills({
            default_enabled: Array.from(enabled),
            exclude_names: Array.from(exclude),
          });
        }
        toast({ title: "Skill deleted", description: `Removed "${name}" from disk.` });
      },
      onError: (err) => {
        toast({
          title: "Delete failed",
          description: err instanceof ApiError ? err.message : `Could not delete "${name}".`,
          variant: "destructive",
        });
      },
    });
  };

  const onInstall = () => {
    setDraftError("");
    const name = draftName.trim();
    if (!/^[a-z0-9][a-z0-9-]{1,63}$/.test(name)) {
      setDraftError("Name must be 2-64 chars: lowercase letters, digits, hyphens.");
      return;
    }
    if (!draftMarkdown.trim()) {
      setDraftError("Markdown body is required.");
      return;
    }
    install.mutate(
      { name, markdown: draftMarkdown },
      {
        onSuccess: () => {
          setAddOpen(false);
          setDraftName("");
          setDraftMarkdown("");
          setSelected(name);
          toast({ title: "Skill installed", description: `"${name}" added to the catalog.` });
        },
        onError: (err) => {
          setDraftError(err instanceof ApiError ? err.message : "Install failed.");
        },
      },
    );
  };

  return (
    <div className="space-y-4 p-4 md:p-6">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h1 className="text-lg font-semibold">Skills</h1>
        <div className="flex items-center gap-2">
          <Button size="sm" variant="ghost" onClick={() => skills.refetch()} disabled={skills.isFetching}>
            <RefreshCw className={cn("h-3.5 w-3.5", skills.isFetching && "animate-spin")} />
          </Button>
          <Button size="sm" onClick={() => setAddOpen(true)}>
            <Plus className="h-4 w-4" />
            Add skill
          </Button>
        </div>
      </div>

      <Card>
        <CardHeader><CardTitle className="text-sm">Skill activation</CardTitle></CardHeader>
        <CardContent className="space-y-3">
          <ToggleRow
            label="Skills enabled"
            description="Master switch. When off, no skill hints are injected or looked up."
            checked={skillsCfg.enabled ?? true}
            onChange={(v) => patchSkills({ enabled: v })}
            disabled={patch.isPending}
          />
          <ToggleRow
            label="Allow model lookup"
            description="Let the model fetch skill methodology on demand via load_runtime_skill."
            checked={skillsCfg.allow_model_lookup ?? false}
            onChange={(v) => patchSkills({ allow_model_lookup: v })}
            disabled={patch.isPending}
          />
          <ToggleRow
            label="Inject startup context"
            description="Bake selected skill hints into the system prompt at run start (on = full skills mode, off = hints-only)."
            checked={skillsCfg.inject_startup_context ?? false}
            onChange={(v) => patchSkills({ inject_startup_context: v })}
            disabled={patch.isPending}
          />
          {(skills.data?.error || config.error) && (
            <p className="text-xs text-destructive">
              {skills.data?.error ?? "Could not load config."}
            </p>
          )}
        </CardContent>
      </Card>

      <div className="grid gap-3 md:grid-cols-[280px_minmax(0,1fr)]">
        <Card>
          <CardHeader>
            <div className="flex items-center gap-2">
              <Search className="h-3.5 w-3.5 text-muted-foreground" />
              <Input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search skills" className="h-8" />
            </div>
          </CardHeader>
          <CardContent className="space-y-1">
            {skills.isLoading && <SkeletonRows count={4} />}
            {skills.error && (
              <div className="flex items-center gap-2 text-sm text-destructive">
                <span>Failed to load skills.</span>
                <Button size="sm" variant="outline" onClick={() => skills.refetch()}>Retry</Button>
              </div>
            )}
            {list.length === 0 && !skills.isLoading && !skills.error && <p className="text-xs text-muted-foreground">No skills.</p>}
            {normalized.map((s) => (
              <SkillRow
                key={s.name}
                skill={s}
                state={skillState(s.name, skillsCfg)}
                selected={selected === s.name}
                onSelect={() => setSelected(s.name)}
                onEnable={() => onEnable(s.name)}
                onDisable={() => onDisable(s.name)}
                onBlock={() => onBlock(s.name)}
                onDelete={() => setConfirmDelete(s.name)}
                pending={patch.isPending || remove.isPending}
                removing={remove.isPending && remove.variables === s.name}
              />
            ))}
          </CardContent>
        </Card>

        <Card>
          <CardHeader><CardTitle className="text-sm">{selected ?? "Select a skill"}</CardTitle></CardHeader>
          <CardContent>
            {!selected && <p className="text-sm text-muted-foreground">Choose a skill to view its body, sections, and references.</p>}
            {selected && detail.isLoading && (
              <div className="flex items-center gap-2 text-sm text-muted-foreground"><Loader2 className="h-4 w-4 animate-spin" />Loading...</div>
            )}
            {selected && detail.error && <div className="text-sm text-destructive">Failed to load skill.</div>}
            {detail.data && (
              <div className="space-y-3 text-sm">
                <p className="text-muted-foreground">{detail.data.description}</p>
                {detail.data.domain && (
                  <div className="text-xs">Domain: {detail.data.domain}{detail.data.subdomain ? ` / ${detail.data.subdomain}` : ""}</div>
                )}
                {detail.data.tags.length > 0 && (
                  <div className="flex flex-wrap gap-1">
                    {detail.data.tags.map((t) => <Badge key={t} variant="outline" className="text-[10px]">{t}</Badge>)}
                  </div>
                )}
                {detail.data.nist_csf.length > 0 && (
                  <div className="text-xs"><span className="text-muted-foreground">NIST CSF:</span> {detail.data.nist_csf.join(", ")}</div>
                )}
                {detail.data.mitre_attack.length > 0 && (
                  <div className="text-xs"><span className="text-muted-foreground">MITRE ATT&amp;CK:</span> {detail.data.mitre_attack.join(", ")}</div>
                )}
                <pre className="max-h-[50vh] overflow-auto rounded-md border bg-muted/30 p-3 font-mono text-xs whitespace-pre-wrap break-words scrollbar-thin">
                  {detail.data.body}
                </pre>
                {detail.data.references.length > 0 && (
                  <details>
                    <summary className="cursor-pointer text-xs text-muted-foreground">References</summary>
                    <ul className="mt-1 list-disc space-y-0.5 pl-4 text-xs">
                      {detail.data.references.map((r) => <li key={r} className="font-mono">{r}</li>)}
                    </ul>
                  </details>
                )}
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      <Dialog open={addOpen} onOpenChange={setAddOpen}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle>Add skill</DialogTitle>
          </DialogHeader>
          <div className="space-y-3">
            <div className="space-y-1.5">
              <Label htmlFor="skill-name" className="text-xs">Name</Label>
              <Input
                id="skill-name"
                value={draftName}
                onChange={(e) => setDraftName(e.target.value)}
                placeholder="my-skill-name"
                className="font-mono"
              />
              <p className="text-xs text-muted-foreground">2-64 chars, lowercase letters / digits / hyphens. Used as the directory name.</p>
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="skill-markdown" className="text-xs">SKILL.md markdown</Label>
              <Textarea
                id="skill-markdown"
                value={draftMarkdown}
                onChange={(e) => setDraftMarkdown(e.target.value)}
                placeholder={"---\nname: my-skill-name\ndescription: What this skill advises\ntags:\n  - example\n---\n\n## When to use\n..."}
                className="min-h-[16rem] font-mono text-xs"
              />
            </div>
            {draftError && <p className="text-xs text-destructive">{draftError}</p>}
          </div>
          <DialogFooter>
            <Button variant="ghost" onClick={() => setAddOpen(false)}>Cancel</Button>
            <Button onClick={onInstall} disabled={install.isPending}>
              {install.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              Install
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={confirmDelete !== null} onOpenChange={(open) => { if (!open) setConfirmDelete(null); }}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Delete skill?</DialogTitle>
            <DialogDescription>
              Delete skill <span className="font-mono">{confirmDelete}</span> from disk? This removes its SKILL.md directory and cannot be undone.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setConfirmDelete(null)}>Cancel</Button>
            <Button
              variant="destructive"
              disabled={remove.isPending}
              onClick={() => {
                if (confirmDelete) onDelete(confirmDelete);
                setConfirmDelete(null);
              }}
            >
              {remove.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              Delete
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

interface SkillRowProps {
  skill: SkillSummary;
  state: SkillState;
  selected: boolean;
  onSelect: () => void;
  onEnable: () => void;
  onDisable: () => void;
  onBlock: () => void;
  onDelete: () => void;
  pending: boolean;
  removing: boolean;
}

function SkillRow({ skill, state, selected, onSelect, onEnable, onDisable, onBlock, onDelete, pending, removing }: SkillRowProps) {
  return (
    <div
      className={cn(
        "rounded-md border px-2 py-1.5 text-xs transition-colors",
        selected ? "border-primary bg-accent" : "hover:bg-accent/50",
      )}
    >
      <button type="button" onClick={onSelect} className="flex w-full flex-col items-start text-left">
        <span className="font-mono">{skill.name}</span>
        <span className="text-muted-foreground line-clamp-2">{skill.description}</span>
      </button>
      <div className="mt-1.5 flex flex-wrap items-center gap-1">
        {state === "enabled" && <Badge variant="success" className="text-[10px]">enabled</Badge>}
        {state === "blocked" && <Badge variant="danger" className="text-[10px]">blocked</Badge>}
        {state === "auto" && <Badge variant="muted" className="text-[10px]">auto</Badge>}
        <div className="ml-auto flex items-center gap-0.5">
          {state !== "enabled" && (
            <Button size="sm" variant="ghost" className="h-6 px-2 text-[11px]" onClick={onEnable} disabled={pending}>
              Enable
            </Button>
          )}
          {state === "enabled" && (
            <Button size="sm" variant="ghost" className="h-6 px-2 text-[11px]" onClick={onDisable} disabled={pending}>
              Disable
            </Button>
          )}
          {state !== "blocked" && (
            <Button size="sm" variant="ghost" className="h-6 px-2 text-[11px]" onClick={onBlock} disabled={pending}>
              Block
            </Button>
          )}
          <Button
            size="sm"
            variant="ghost"
            className="h-6 px-2 text-[11px] text-destructive hover:text-destructive"
            onClick={onDelete}
            disabled={pending}
          >
            {removing ? <Loader2 className="h-3 w-3 animate-spin" /> : <Trash2 className="h-3 w-3" />}
          </Button>
        </div>
      </div>
    </div>
  );
}

interface ToggleRowProps {
  label: string;
  description: string;
  checked: boolean;
  onChange: (value: boolean) => void;
  disabled?: boolean;
}

function ToggleRow({ label, description, checked, onChange, disabled }: ToggleRowProps) {
  return (
    <div className="flex items-center justify-between gap-3">
      <div className="space-y-0.5">
        <Label className="text-xs">{label}</Label>
        <p className="text-xs text-muted-foreground">{description}</p>
      </div>
      <Switch checked={checked} onCheckedChange={onChange} disabled={disabled} />
    </div>
  );
}