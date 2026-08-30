import { useEffect, useMemo, useState } from "react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import {
  AlertTriangle,
  BookOpen,
  Check,
  ChevronDown,
  ChevronUp,
  ExternalLink,
  FileText,
  Hash,
  Layers,
  Loader2,
  MoreHorizontal,
  Plus,
  RefreshCw,
  Search,
  Settings2,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Tag,
  Trash2,
  X,
  Zap,
} from "lucide-react";
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
import type { SkillDetail, SkillSummary } from "@/api/types";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
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
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@/components/ui/popover";
import { Separator } from "@/components/ui/separator";
import { useToast } from "@/hooks/use-toast";
import { CopyButton } from "@/components/CopyButton";
import { Skeleton } from "@/components/Loading";

// ── config helpers ──────────────────────────────────────────────────────────

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

const STATE_META: Record<
  SkillState,
  { label: string; variant: "success" | "danger" | "muted"; dot: string; icon: typeof ShieldCheck }
> = {
  enabled: { label: "Enabled", variant: "success", dot: "bg-emerald-500", icon: ShieldCheck },
  blocked: { label: "Blocked", variant: "danger", dot: "bg-red-500", icon: ShieldAlert },
  auto: { label: "Auto", variant: "muted", dot: "bg-zinc-400", icon: Zap },
};

function isValidUrl(v: string): boolean {
  try {
    const u = new URL(v);
    return u.protocol === "http:" || u.protocol === "https:";
  } catch {
    return false;
  }
}

const SKILL_TEMPLATE = `---
name: my-skill-name
description: What this skill advises
tags:
  - example
  - methodology
domain: reconnaissance
subdomain: scanning
version: "0.1.0"
nist_csf:
  - PR.AC
mitre_attack:
  - T1595
references:
  - https://example.com/methodology
---

## When to use

Describe the trigger conditions for this skill.

## Methodology

Step-by-step guidance for the agent.

## References

- https://example.com
`;

// ── shared markdown ─────────────────────────────────────────────────────────

function SkillMarkdown({ children }: { children: string }) {
  return (
    <div
      className={cn(
        "prose prose-invert max-w-none",
        "prose-p:my-3 prose-p:leading-relaxed prose-p:text-[13.5px]",
        "prose-headings:font-semibold prose-headings:tracking-tight prose-headings:text-foreground",
        "prose-h1:text-xl prose-h1:mt-6 prose-h1:mb-3 prose-h1:border-b prose-h1:border-border prose-h1:pb-2",
        "prose-h2:text-[15px] prose-h2:mt-6 prose-h2:mb-2 prose-h2:border-b prose-h2:border-border/60 prose-h2:pb-1.5",
        "prose-h3:text-[13px] prose-h3:mt-4 prose-h3:mb-1.5 prose-h3:uppercase prose-h3:tracking-wide prose-h3:text-muted-foreground",
        "prose-a:text-primary prose-a:underline-offset-4 hover:prose-a:underline prose-a:break-words",
        "prose-strong:text-foreground prose-strong:font-semibold",
        "prose-code:text-[12.5px] prose-code:font-mono prose-code:rounded prose-code:bg-muted prose-code:px-1 prose-code:py-0.5 prose-code:font-medium prose-code:before:content-none prose-code:after:content-none",
        "prose-pre:rounded-lg prose-pre:border prose-pre:bg-[#0a0a0a] prose-pre:p-0 prose-pre:overflow-hidden",
        "prose-pre:prose-code:bg-transparent prose-pre:prose-code:p-0 prose-pre:prose-code:rounded-none",
        "prose-ul:my-3 prose-ul:list-disc prose-ul:pl-5 prose-li:my-1 prose-li:text-[13.5px] prose-li:leading-relaxed",
        "prose-ol:my-3 prose-ol:list-decimal prose-ol:pl-5",
        "prose-li:marker:text-muted-foreground",
        "prose-blockquote:border-l-2 prose-blockquote:border-primary/40 prose-blockquote:bg-muted/40 prose-blockquote:rounded-r-md prose-blockquote:px-3 prose-blockquote:py-2 prose-blockquote:text-muted-foreground prose-blockquote:not-italic",
        "prose-table:my-4 prose-table:w-full prose-table:overflow-hidden prose-table:rounded-md prose-table:border prose-table:text-sm",
        "prose-th:bg-muted/60 prose-th:px-3 prose-th:py-2 prose-th:text-left prose-th:font-medium prose-th:text-xs prose-th:uppercase prose-th:tracking-wide",
        "prose-td:px-3 prose-td:py-2 prose-td:border-t prose-td:text-[13px]",
        "prose-hr:my-6 prose-hr:border-border",
        "prose-img:rounded-lg prose-img:border",
      )}
    >
      <ReactMarkdown
        remarkPlugins={[remarkGfm]}
        components={{
          a: ({ children, href, ...props }) => (
            <a href={href} target="_blank" rel="noopener noreferrer" {...props}>
              {children}
            </a>
          ),
          pre: ({ children, ...props }) => (
            <pre className="overflow-x-auto p-3 text-xs leading-relaxed scrollbar-thin" {...props}>
              {children}
            </pre>
          ),
          table: ({ children, ...props }) => (
            <div className="overflow-x-auto">
              <table {...props}>{children}</table>
            </div>
          ),
        }}
      >
        {children}
      </ReactMarkdown>
    </div>
  );
}

// ── page ───────────────────────────────────────────────────────────────────

type StatusFilter = "all" | SkillState;
type SortKey = "default" | "name" | "state";

const STATUS_OPTIONS: Array<{ value: StatusFilter; label: string }> = [
  { value: "all", label: "All" },
  { value: "enabled", label: "Enabled" },
  { value: "auto", label: "Auto" },
  { value: "blocked", label: "Blocked" },
];

export function SkillsPage() {
  const config = useConfig();
  const skills = useSkills();
  const [query, setQuery] = useState("");
  const [tag, setTag] = useState<string | null>(null);
  const [status, setStatus] = useState<StatusFilter>("all");
  const [sort, setSort] = useState<SortKey>("default");
  const [showFilters, setShowFilters] = useState(true);
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
  const [previewTab, setPreviewTab] = useState<"write" | "preview">("write");

  const skillsCfg = useMemo(() => readSkillsConfig(config.data), [config.data]);

  const tagByName = useMemo(() => {
    const map = new Map<string, string[]>();
    for (const s of skills.data?.skills ?? []) map.set(s.name, s.tags);
    return map;
  }, [skills.data]);

  const topTags = useMemo(() => {
    const counts = new Map<string, number>();
    for (const s of skills.data?.skills ?? []) {
      for (const t of s.tags) counts.set(t, (counts.get(t) ?? 0) + 1);
    }
    return Array.from(counts.entries())
      .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
      .slice(0, 20);
  }, [skills.data]);

  const filtered = useMemo(() => {
    let base: SkillSummary[];
    if (query.trim()) {
      const results = search.data?.results ?? [];
      base = results.map((r) => ({
        name: r.name,
        description: r.description,
        tags: tagByName.get(r.name) ?? [],
      }));
    } else {
      base = skills.data?.skills ?? [];
    }
    let out = base;
    if (tag) out = out.filter((s) => (tagByName.get(s.name) ?? []).includes(tag));
    if (status !== "all") out = out.filter((s) => skillState(s.name, skillsCfg) === status);
    if (sort === "name") out = [...out].sort((a, b) => a.name.localeCompare(b.name));
    else if (sort === "state") {
      const order: Record<SkillState, number> = { enabled: 0, auto: 1, blocked: 2 };
      out = [...out].sort((a, b) => order[skillState(a.name, skillsCfg)] - order[skillState(b.name, skillsCfg)] || a.name.localeCompare(b.name));
    }
    return out;
  }, [query, search.data, skills.data, tag, tagByName, status, skillsCfg, sort]);

  const total = skills.data?.skills.length ?? 0;
  const enabledCount = skillsCfg.default_enabled?.length ?? 0;
  const blockedCount = skillsCfg.exclude_names?.length ?? 0;
  const autoCount = Math.max(0, total - enabledCount - blockedCount);
  const isSearching = query.trim().length > 0 && search.isFetching;
  const masterEnabled = skillsCfg.enabled ?? true;

  const hasActiveFilters = tag !== null || status !== "all" || query.trim().length > 0;

  const clearFilters = () => {
    setTag(null);
    setStatus("all");
    setQuery("");
    setSort("default");
  };

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
    patchSkills({ default_enabled: Array.from(enabled), exclude_names: Array.from(exclude) });
  };

  const onAuto = (name: string) => {
    const enabled = new Set(skillsCfg.default_enabled ?? []);
    const exclude = new Set(skillsCfg.exclude_names ?? []);
    enabled.delete(name);
    exclude.delete(name);
    patchSkills({ default_enabled: Array.from(enabled), exclude_names: Array.from(exclude) });
  };

  const onBlock = (name: string) => {
    const enabled = new Set(skillsCfg.default_enabled ?? []);
    enabled.delete(name);
    const exclude = new Set(skillsCfg.exclude_names ?? []);
    exclude.add(name);
    patchSkills({ default_enabled: Array.from(enabled), exclude_names: Array.from(exclude) });
  };

  const onDelete = (name: string) => {
    const enabled = new Set(skillsCfg.default_enabled ?? []);
    const exclude = new Set(skillsCfg.exclude_names ?? []);
    enabled.delete(name);
    exclude.delete(name);
    remove.mutate(name, {
      onSuccess: () => {
        if (selected === name) setSelected(null);
        if (enabled.size !== (skillsCfg.default_enabled ?? []).length || exclude.size !== (skillsCfg.exclude_names ?? []).length) {
          patchSkills({ default_enabled: Array.from(enabled), exclude_names: Array.from(exclude) });
        }
        toast({ title: "Skill deleted", description: `Removed "${name}" from disk.` });
        setConfirmDelete(null);
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
      setDraftError("Name must be 2–64 chars: lowercase letters, digits, hyphens.");
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
          setDraftError("");
          setSelected(name);
          setPreviewTab("write");
          toast({ title: "Skill installed", description: `"${name}" added to the catalog.` });
        },
        onError: (err) => {
          setDraftError(err instanceof ApiError ? err.message : "Install failed.");
        },
      },
    );
  };

  // Auto-select first skill on load if none selected and not searching
  useEffect(() => {
    if (!selected && !query.trim() && !hasActiveFilters && filtered.length > 0 && !skills.isLoading) {
      // don't auto-select to avoid jarring; user chooses
    }
  }, [selected, query, hasActiveFilters, filtered.length, skills.isLoading]);

  return (
    <TooltipProvider delayDuration={200}>
      <div className="mx-auto flex max-w-[1600px] flex-col gap-4 p-4 md:p-6">
        {/* Header */}
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

          {/* Stat strip */}
          <div className="grid grid-cols-2 gap-px overflow-hidden rounded-xl border bg-border sm:grid-cols-4">
            <HeaderStat label="Total" value={total} icon={Layers} loading={skills.isLoading} />
            <HeaderStat label="Enabled" value={enabledCount} icon={ShieldCheck} accent="emerald" loading={skills.isLoading} />
            <HeaderStat label="Auto" value={autoCount} icon={Zap} accent="zinc" loading={skills.isLoading} />
            <HeaderStat label="Blocked" value={blockedCount} icon={ShieldAlert} accent="red" loading={skills.isLoading} />
          </div>
        </header>

        {/* Configuration bar */}
        <Card className={cn("overflow-hidden", !masterEnabled && "border-amber-500/30")}>
          <div className="flex items-center justify-between gap-3 border-b bg-muted/20 px-4 py-3">
            <div className="flex items-center gap-2.5">
              <div className={cn("flex h-7 w-7 items-center justify-center rounded-md border", masterEnabled ? "bg-primary text-primary-foreground" : "bg-amber-500/10 text-amber-600 border-amber-500/20")}>
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
                    <p className="text-xs leading-relaxed text-muted-foreground">Master switch. When off, no skill hints are injected or looked up.</p>
                  </div>
                  <Switch
                    checked={masterEnabled}
                    onCheckedChange={(v) => patchSkills({ enabled: v })}
                    disabled={patch.isPending || config.isLoading}
                    aria-label="Toggle skills enabled"
                  />
                </div>
                {patch.isPending && <span className="mt-2 inline-flex items-center gap-1 text-[11px] text-muted-foreground"><Loader2 className="h-3 w-3 animate-spin" /> Saving…</span>}
              </div>
              <div className="p-4">
                <div className="flex items-start justify-between gap-3">
                  <div className="space-y-1">
                    <Label className="text-xs font-medium">Allow model lookup</Label>
                    <p className="text-xs leading-relaxed text-muted-foreground">Let the model fetch skill methodology on demand via load_runtime_skill.</p>
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
                    <p className="text-xs leading-relaxed text-muted-foreground">Bake selected skill hints into the system prompt at run start.</p>
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
              Skills system is disabled. The catalog is still browsable, but no skills will be injected or looked up at runtime.
            </div>
          )}
        </Card>

        {/* Main workspace */}
        <div className="grid min-h-0 flex-1 gap-4 lg:grid-cols-[360px_minmax(0,1fr)] lg:items-start">
          {/* Catalog */}
          <Card className={cn("flex max-h-[520px] flex-col overflow-hidden lg:sticky lg:top-4 lg:max-h-[calc(100vh-8rem)]", !masterEnabled && "opacity-90")}>
            <div className="shrink-0 space-y-3 border-b bg-card p-3">
              {/* Search */}
              <div className="relative">
                <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
                <Input
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  placeholder="Search skills…"
                  aria-label="Search skills"
                  className="h-9 pl-8 pr-8 text-sm"
                />
                {query ? (
                  <button
                    type="button"
                    onClick={() => setQuery("")}
                    aria-label="Clear search"
                    className="absolute right-1 top-1/2 -translate-y-1/2 rounded p-1.5 text-muted-foreground hover:bg-accent hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                  >
                    <X className="h-3.5 w-3.5" />
                  </button>
                ) : null}
                {isSearching && <Loader2 className="absolute right-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 animate-spin text-muted-foreground" />}
              </div>

              {/* Status + sort row */}
              <div className="flex items-center gap-2">
                <div className="flex flex-1 items-center rounded-md border bg-muted/30 p-0.5" role="group" aria-label="Filter by state">
                  {STATUS_OPTIONS.map((o) => (
                    <button
                      key={o.value}
                      type="button"
                      aria-pressed={status === o.value}
                      onClick={() => setStatus(o.value)}
                      className={cn(
                        "flex-1 rounded-sm px-2 py-1 text-xs font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring",
                        status === o.value ? "bg-background shadow-sm text-foreground" : "text-muted-foreground hover:text-foreground",
                      )}
                    >
                      {o.label}
                    </button>
                  ))}
                </div>
                <Select value={sort} onValueChange={(v) => setSort(v as SortKey)}>
                  <SelectTrigger className="h-7 w-[128px] shrink-0 text-xs" aria-label="Sort skills">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="default">Default order</SelectItem>
                    <SelectItem value="name">Name A→Z</SelectItem>
                    <SelectItem value="state">State</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              {/* Tag filter */}
              <div className="flex items-center gap-1.5">
                <Popover>
                  <PopoverTrigger asChild>
                    <Button variant="outline" size="sm" className="h-7 gap-1.5 text-xs">
                      <Tag className="h-3 w-3" />
                      {tag ? tag : "All tags"}
                      <ChevronDown className="h-3 w-3 opacity-50" />
                    </Button>
                  </PopoverTrigger>
                  <PopoverContent align="start" className="w-64 p-2">
                    <div className="max-h-64 space-y-1 overflow-auto scrollbar-thin">
                      <button
                        type="button"
                        onClick={() => setTag(null)}
                        className={cn("flex w-full items-center justify-between rounded-md px-2.5 py-1.5 text-xs transition-colors", tag === null ? "bg-primary text-primary-foreground" : "hover:bg-accent")}
                      >
                        All tags <span className="tabular-nums text-muted-foreground">{total}</span>
                      </button>
                      {topTags.map(([t, count]) => (
                        <button
                          key={t}
                          type="button"
                          onClick={() => setTag(t)}
                          className={cn("flex w-full items-center justify-between rounded-md px-2.5 py-1.5 text-xs transition-colors", tag === t ? "bg-primary text-primary-foreground" : "hover:bg-accent")}
                        >
                          <span className="truncate">{t}</span>
                          <span className="ml-2 shrink-0 tabular-nums opacity-60">{count}</span>
                        </button>
                      ))}
                      {topTags.length === 0 && <p className="px-2 py-2 text-xs text-muted-foreground">No tags</p>}
                    </div>
                  </PopoverContent>
                </Popover>
                {tag && (
                  <Button variant="ghost" size="sm" className="h-7 px-2 text-xs" onClick={() => setTag(null)}>
                    <X className="mr-1 h-3 w-3" /> Clear
                  </Button>
                )}
                {hasActiveFilters && !tag && (
                  <Button variant="ghost" size="sm" className="ml-auto h-7 px-2 text-xs" onClick={clearFilters}>
                    Clear filters
                  </Button>
                )}
              </div>

              {/* Result count */}
              <div className="flex items-center justify-between text-xs">
                <span className="tabular-nums text-muted-foreground">
                  {skills.isLoading ? "Loading…" : hasActiveFilters ? `${filtered.length} of ${total} skills` : `${total} skills`}
                </span>
                {hasActiveFilters && <span className="text-muted-foreground/60">filtered</span>}
              </div>
            </div>

            {/* List */}
            <div className="min-h-0 flex-1 overflow-auto scrollbar-thin">
              <div className="space-y-1 p-2">
                {skills.isLoading && (
                  <div className="space-y-2 p-1">
                    {Array.from({ length: 6 }).map((_, i) => (
                      <div key={i} className="space-y-2 rounded-lg border p-3">
                        <Skeleton className="h-3 w-28" />
                        <Skeleton className="h-3 w-full" />
                        <Skeleton className="h-3 w-2/3" />
                      </div>
                    ))}
                  </div>
                )}
                {skills.error && !skills.isLoading && (
                  <div className="flex flex-col items-center gap-2 rounded-lg border border-destructive/30 bg-destructive/5 p-4 text-center">
                    <AlertTriangle className="h-5 w-5 text-destructive" />
                    <p className="text-sm font-medium text-destructive">Failed to load skills</p>
                    <p className="text-xs text-muted-foreground">{skills.error instanceof ApiError ? skills.error.message : "Could not reach the skills endpoint."}</p>
                    <Button size="sm" variant="outline" onClick={() => skills.refetch()} className="mt-1">
                      Retry
                    </Button>
                  </div>
                )}
                {!skills.isLoading && !skills.error && total === 0 && (
                  <div className="flex flex-col items-center gap-3 rounded-lg border border-dashed p-6 text-center">
                    <div className="flex h-10 w-10 items-center justify-center rounded-full bg-muted">
                      <Sparkles className="h-5 w-5 text-muted-foreground" />
                    </div>
                    <div className="space-y-1">
                      <p className="text-sm font-medium">No skills installed</p>
                      <p className="text-xs text-muted-foreground">Add your first skill to extend the agent with specialist methodology.</p>
                    </div>
                    <Button size="sm" onClick={() => setAddOpen(true)}>
                      <Plus className="h-4 w-4" /> Add skill
                    </Button>
                  </div>
                )}
                {!skills.isLoading && !skills.error && total > 0 && filtered.length === 0 && (
                  <div className="flex flex-col items-center gap-2 rounded-lg border border-dashed p-6 text-center">
                    <Search className="h-6 w-6 text-muted-foreground/40" />
                    <p className="text-sm font-medium">No results</p>
                    <p className="text-xs text-muted-foreground">
                      {query.trim() ? `No skills match “${query.trim()}”` : tag || status !== "all" ? "No skills match the current filters." : "No skills match."}
                    </p>
                    {hasActiveFilters && (
                      <Button size="sm" variant="outline" onClick={clearFilters} className="mt-1">
                        Clear filters
                      </Button>
                    )}
                  </div>
                )}
                {!skills.isLoading && filtered.map((s) => {
                  const st = skillState(s.name, skillsCfg);
                  const meta = STATE_META[st];
                  const isSelected = selected === s.name;
                  const isPatching = patch.isPending;
                  return (
                    <div
                      key={s.name}
                      className={cn(
                        "group relative flex flex-col rounded-lg border text-left transition-all",
                        isSelected ? "border-primary/40 bg-primary/[0.06] shadow-sm" : "border-border bg-card hover:border-primary/20 hover:bg-accent/30",
                        !masterEnabled && "opacity-80",
                      )}
                    >
                      <button
                        type="button"
                        onClick={() => setSelected(s.name)}
                        className="flex flex-col gap-1.5 p-3 text-left focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-inset rounded-lg"
                        aria-pressed={isSelected}
                        aria-label={`Select ${s.name}`}
                      >
                        <div className="flex items-start justify-between gap-2">
                          <span className="truncate font-mono text-sm font-semibold leading-none">{s.name}</span>
                          <span className={cn("mt-0.5 inline-flex items-center gap-1.5 rounded-full border px-2 py-0.5 text-[10px] font-medium leading-none", st === "enabled" ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300" : st === "blocked" ? "border-red-500/30 bg-red-500/10 text-red-600 dark:text-red-300" : "border-border bg-muted text-muted-foreground")}>
                            <span className={cn("h-1.5 w-1.5 rounded-full", meta.dot)} aria-hidden />
                            {meta.label}
                          </span>
                        </div>
                        <p className="line-clamp-2 text-xs leading-relaxed text-muted-foreground">{s.description || "No description"}</p>
                        {s.tags.length > 0 && (
                          <div className="flex flex-wrap gap-1">
                            {s.tags.slice(0, 3).map((t) => (
                              <span key={t} className="inline-flex items-center rounded bg-muted px-1.5 py-0.5 text-[10px] font-medium text-muted-foreground">
                                {t}
                              </span>
                            ))}
                            {s.tags.length > 3 && <span className="text-[10px] text-muted-foreground">+{s.tags.length - 3}</span>}
                          </div>
                        )}
                      </button>
                      <div className="flex items-center justify-between gap-1 border-t bg-muted/20 px-2 py-1.5">
                        <span className="flex items-center gap-1 text-[11px] text-muted-foreground">
                          <Hash className="h-3 w-3" />
                          <span className="truncate">{s.tags.length} tags</span>
                        </span>
                        <SkillRowActions
                          state={st}
                          onEnable={() => onEnable(s.name)}
                          onAuto={() => onAuto(s.name)}
                          onBlock={() => onBlock(s.name)}
                          onDelete={() => setConfirmDelete(s.name)}
                          disabled={isPatching}
                        />
                      </div>
                      {isSelected && <div className="pointer-events-none absolute inset-y-0 left-0 w-0.5 rounded-l-lg bg-primary" aria-hidden />}
                    </div>
                  );
                })}
              </div>
            </div>
          </Card>

          {/* Detail */}
          <Card className={cn("flex min-h-[480px] flex-col overflow-hidden", !masterEnabled && "opacity-90")}>
            {!selected ? (
              <div className="flex flex-1 flex-col items-center justify-center gap-3 p-8 text-center">
                <div className="flex h-12 w-12 items-center justify-center rounded-xl border bg-muted/40">
                  <BookOpen className="h-6 w-6 text-muted-foreground" />
                </div>
                <div className="space-y-1">
                  <p className="text-sm font-semibold">Select a skill</p>
                  <p className="max-w-sm text-sm leading-relaxed text-muted-foreground">Choose a skill from the catalog to inspect its methodology, sections, and references. Use search and filters to narrow the list.</p>
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
                <p className="text-xs text-muted-foreground">{detail.error instanceof ApiError ? detail.error.message : "Could not fetch skill details."}</p>
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
        </div>

        {/* Add skill dialog */}
        <Dialog open={addOpen} onOpenChange={(o) => { setAddOpen(o); if (!o) { setDraftError(""); setPreviewTab("write"); } }}>
          <DialogContent className="flex max-h-[92vh] max-w-5xl flex-col gap-0 overflow-hidden p-0 sm:rounded-xl">
            <DialogHeader className="shrink-0 border-b px-6 py-4 text-left">
              <DialogTitle className="flex items-center gap-2 text-base">
                <div className="flex h-7 w-7 items-center justify-center rounded-md bg-primary text-primary-foreground">
                  <Plus className="h-4 w-4" />
                </div>
                Add skill
              </DialogTitle>
              <DialogDescription className="text-xs">Create a new skill directory with a SKILL.md file. The name becomes the directory name on disk.</DialogDescription>
            </DialogHeader>

            <div className="flex min-h-0 flex-1 flex-col">
              {/* Name row */}
              <div className="shrink-0 space-y-3 border-b bg-muted/20 px-6 py-4">
                <div className="flex flex-col gap-3 sm:flex-row sm:items-end sm:gap-4">
                  <div className="flex-1 space-y-1.5">
                    <Label htmlFor="skill-name" className="text-xs font-medium">
                      Skill name
                    </Label>
                    <Input
                      id="skill-name"
                      value={draftName}
                      onChange={(e) => setDraftName(e.target.value)}
                      placeholder="my-skill-name"
                      className="h-9 font-mono text-sm"
                      spellCheck={false}
                      autoComplete="off"
                    />
                  </div>
                  <div className="flex items-center gap-2">
                    <Button variant="outline" size="sm" className="h-9 text-xs" onClick={() => setDraftMarkdown((v) => (v.trim() ? v : SKILL_TEMPLATE))}>
                      Insert template
                    </Button>
                    <div className="hidden items-center gap-1 rounded-md border bg-background p-0.5 sm:flex" role="tablist" aria-label="Editor mode">
                      <button
                        type="button"
                        role="tab"
                        aria-selected={previewTab === "write"}
                        onClick={() => setPreviewTab("write")}
                        className={cn("rounded-sm px-3 py-1 text-xs font-medium transition-colors", previewTab === "write" ? "bg-primary text-primary-foreground shadow-sm" : "text-muted-foreground hover:text-foreground")}
                      >
                        Write
                      </button>
                      <button
                        type="button"
                        role="tab"
                        aria-selected={previewTab === "preview"}
                        onClick={() => setPreviewTab("preview")}
                        className={cn("rounded-sm px-3 py-1 text-xs font-medium transition-colors", previewTab === "preview" ? "bg-primary text-primary-foreground shadow-sm" : "text-muted-foreground hover:text-foreground")}
                      >
                        Preview
                      </button>
                    </div>
                  </div>
                </div>
                <p className="text-xs text-muted-foreground">2–64 characters · lowercase letters, digits, hyphens · must start with a letter or digit</p>
                {draftError && <p className="rounded-md border border-destructive/30 bg-destructive/10 px-3 py-2 text-xs text-destructive">{draftError}</p>}
              </div>

              {/* Editor */}
              <div className="min-h-0 flex-1 overflow-hidden">
                {/* Mobile tabs */}
                <div className="flex items-center gap-1 border-b bg-muted/20 px-2 py-1 sm:hidden">
                  <button
                    type="button"
                    onClick={() => setPreviewTab("write")}
                    className={cn("flex-1 rounded-md px-3 py-1.5 text-xs font-medium", previewTab === "write" ? "bg-background shadow-sm" : "text-muted-foreground")}
                  >
                    Write
                  </button>
                  <button
                    type="button"
                    onClick={() => setPreviewTab("preview")}
                    className={cn("flex-1 rounded-md px-3 py-1.5 text-xs font-medium", previewTab === "preview" ? "bg-background shadow-sm" : "text-muted-foreground")}
                  >
                    Preview
                  </button>
                </div>

                <div className="grid h-full min-h-0 grid-cols-1 lg:grid-cols-2">
                  <div className={cn("flex min-h-0 flex-col border-r", previewTab === "preview" ? "hidden lg:flex" : "flex")}>
                    <div className="flex items-center justify-between border-b bg-muted/30 px-3 py-1.5">
                      <span className="text-xs font-medium text-muted-foreground">SKILL.md</span>
                      <span className="text-[11px] tabular-nums text-muted-foreground">{draftMarkdown.length} chars</span>
                    </div>
                    <Textarea
                      value={draftMarkdown}
                      onChange={(e) => setDraftMarkdown(e.target.value)}
                      placeholder={SKILL_TEMPLATE}
                      className="min-h-[320px] flex-1 resize-none rounded-none border-0 font-mono text-xs leading-relaxed focus-visible:ring-0 focus-visible:ring-offset-0 lg:min-h-0"
                      spellCheck={false}
                    />
                  </div>
                  <div className={cn("min-h-0 overflow-auto bg-card p-4 scrollbar-thin", previewTab === "write" ? "hidden lg:block" : "block")}>
                    <div className="mb-3 flex items-center gap-2 text-xs font-medium text-muted-foreground">
                      <FileText className="h-3.5 w-3.5" /> Preview
                    </div>
                    {draftMarkdown.trim() ? (
                      <div className="rounded-lg border bg-muted/20 p-4">
                        <SkillMarkdown>{draftMarkdown}</SkillMarkdown>
                      </div>
                    ) : (
                      <div className="rounded-lg border border-dashed p-6 text-center text-sm text-muted-foreground">Start writing to see a live preview here. The preview uses the same renderer as the detail view.</div>
                    )}
                  </div>
                </div>
              </div>
            </div>

            <DialogFooter className="shrink-0 border-t bg-muted/20 px-6 py-3">
              <Button variant="ghost" onClick={() => setAddOpen(false)} disabled={install.isPending}>
                Cancel
              </Button>
              <Button onClick={onInstall} disabled={install.isPending} className="min-w-[96px]">
                {install.isPending ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : null}
                Install
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>

        {/* Delete confirm */}
        <Dialog open={confirmDelete !== null} onOpenChange={(open) => { if (!open) setConfirmDelete(null); }}>
          <DialogContent className="sm:max-w-md">
            <DialogHeader>
              <DialogTitle className="flex items-center gap-2 text-base">
                <span className="flex h-8 w-8 items-center justify-center rounded-full bg-destructive/10 text-destructive">
                  <Trash2 className="h-4 w-4" />
                </span>
                Delete skill?
              </DialogTitle>
              <DialogDescription asChild>
                <div className="space-y-3 pt-1 text-left">
                  <p className="text-sm leading-relaxed">
                    Delete <span className="font-mono font-medium text-foreground">{confirmDelete}</span> from disk? This removes its directory and SKILL.md and cannot be undone.
                  </p>
                  <div className="rounded-md border border-amber-500/20 bg-amber-500/5 p-3 text-xs leading-relaxed text-amber-800 dark:text-amber-200">
                    References in <span className="font-mono">default_enabled</span> and <span className="font-mono">exclude_names</span> will be cleaned up automatically.
                  </div>
                </div>
              </DialogDescription>
            </DialogHeader>
            <DialogFooter className="gap-2 sm:gap-0">
              <Button variant="outline" onClick={() => setConfirmDelete(null)} disabled={remove.isPending}>
                Cancel
              </Button>
              <Button
                variant="destructive"
                disabled={remove.isPending}
                onClick={() => { if (confirmDelete) onDelete(confirmDelete); }}
                className="min-w-[96px]"
              >
                {remove.isPending ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Trash2 className="h-4 w-4" />}
                Delete
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </div>
    </TooltipProvider>
  );
}

// ── header stat ────────────────────────────────────────────────────────────

function HeaderStat({ label, value, icon: Icon, accent, loading }: { label: string; value: number; icon: typeof Sparkles; accent?: "emerald" | "red" | "zinc"; loading?: boolean }) {
  const accentCls =
    accent === "emerald" ? "text-emerald-600 dark:text-emerald-300" :
    accent === "red" ? "text-red-600 dark:text-red-300" :
    accent === "zinc" ? "text-zinc-500 dark:text-zinc-400" :
    "text-foreground";
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

// ── row actions popover ────────────────────────────────────────────────────

function SkillRowActions({ state, onEnable, onAuto, onBlock, onDelete, disabled }: { state: SkillState; onEnable: () => void; onAuto: () => void; onBlock: () => void; onDelete: () => void; disabled?: boolean }) {
  const [open, setOpen] = useState(false);
  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <Button variant="ghost" size="sm" className="h-6 w-6 p-0" disabled={disabled} aria-label="Skill actions">
          <MoreHorizontal className="h-3.5 w-3.5" />
        </Button>
      </PopoverTrigger>
      <PopoverContent align="end" className="w-44 p-1">
        <div className="p-1">
          <div className="px-2 py-1 text-[11px] font-semibold uppercase tracking-wide text-muted-foreground">State</div>
          <button type="button" disabled={disabled || state === "enabled"} onClick={() => { onEnable(); setOpen(false); }} className="flex w-full items-center gap-2 rounded-sm px-2 py-1.5 text-xs hover:bg-accent disabled:opacity-50">
            <ShieldCheck className="h-3.5 w-3.5 text-emerald-500" /> Enable {state === "enabled" && <Check className="ml-auto h-3 w-3" />}
          </button>
          <button type="button" disabled={disabled || state === "auto"} onClick={() => { onAuto(); setOpen(false); }} className="flex w-full items-center gap-2 rounded-sm px-2 py-1.5 text-xs hover:bg-accent disabled:opacity-50">
            <Zap className="h-3.5 w-3.5 text-zinc-500" /> Set to Auto {state === "auto" && <Check className="ml-auto h-3 w-3" />}
          </button>
          <button type="button" disabled={disabled || state === "blocked"} onClick={() => { onBlock(); setOpen(false); }} className="flex w-full items-center gap-2 rounded-sm px-2 py-1.5 text-xs hover:bg-accent disabled:opacity-50">
            <ShieldAlert className="h-3.5 w-3.5 text-red-500" /> Block {state === "blocked" && <Check className="ml-auto h-3 w-3" />}
          </button>
          <Separator className="my-1" />
          <button type="button" disabled={disabled} onClick={() => { onDelete(); setOpen(false); }} className="flex w-full items-center gap-2 rounded-sm px-2 py-1.5 text-xs text-destructive hover:bg-destructive/10">
            <Trash2 className="h-3.5 w-3.5" /> Delete
          </button>
        </div>
      </PopoverContent>
    </Popover>
  );
}

// ── detail view ────────────────────────────────────────────────────────────

function SkillDetailView({ detail, cfg, patchPending, removePending, onEnable, onAuto, onBlock, onDelete }: { detail: SkillDetail; cfg: SkillsConfig; patchPending?: boolean; removePending?: boolean; onEnable: () => void; onAuto: () => void; onBlock: () => void; onDelete: () => void }) {
  const st = skillState(detail.name, cfg);
  const meta = STATE_META[st];
  const StateIcon = meta.icon;
  const sectionEntries = Object.entries(detail.sections ?? {});
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});
  const allExpanded = sectionEntries.length > 0 && sectionEntries.every(([k]) => expanded[k]);

  const toggleAll = (v: boolean) => {
    const next: Record<string, boolean> = {};
    for (const [k] of sectionEntries) next[k] = v;
    setExpanded(next);
  };

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      {/* Sticky header */}
      <div className="sticky top-0 z-10 border-b bg-card/80 backdrop-blur supports-[backdrop-filter]:bg-card/70">
        <div className="space-y-3 p-4">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div className="min-w-0 flex-1">
              <div className="flex flex-wrap items-center gap-2">
                <h2 className="truncate font-mono text-base font-semibold">{detail.name}</h2>
                {detail.version && <Badge variant="outline" className="shrink-0 text-[10px] tabular-nums">v{detail.version}</Badge>}
                <Badge variant={meta.variant} className="gap-1 text-[10px]">
                  <StateIcon className="h-3 w-3" /> {meta.label}
                </Badge>
              </div>
              <p className="mt-1.5 line-clamp-3 text-sm leading-relaxed text-muted-foreground">{detail.description || "No description provided."}</p>
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
                    <div className="px-2 py-1 text-[11px] font-semibold uppercase tracking-wide text-muted-foreground">Change state</div>
                    <button type="button" disabled={patchPending || st === "enabled"} onClick={onEnable} className="flex w-full items-center gap-2 rounded-sm px-2 py-1.5 text-xs hover:bg-accent disabled:opacity-50">
                      <ShieldCheck className="h-3.5 w-3.5 text-emerald-500" /> Enabled {st === "enabled" && <Check className="ml-auto h-3 w-3" />}
                    </button>
                    <button type="button" disabled={patchPending || st === "auto"} onClick={onAuto} className="flex w-full items-center gap-2 rounded-sm px-2 py-1.5 text-xs hover:bg-accent disabled:opacity-50">
                      <Zap className="h-3.5 w-3.5 text-zinc-500" /> Auto {st === "auto" && <Check className="ml-auto h-3 w-3" />}
                    </button>
                    <button type="button" disabled={patchPending || st === "blocked"} onClick={onBlock} className="flex w-full items-center gap-2 rounded-sm px-2 py-1.5 text-xs hover:bg-accent disabled:opacity-50">
                      <ShieldAlert className="h-3.5 w-3.5 text-red-500" /> Blocked {st === "blocked" && <Check className="ml-auto h-3 w-3" />}
                    </button>
                  </div>
                </PopoverContent>
              </Popover>
              <Button variant="ghost" size="sm" className="h-8 w-8 p-0 text-destructive hover:bg-destructive/10 hover:text-destructive" onClick={onDelete} disabled={removePending || patchPending} aria-label="Delete skill">
                {removePending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Trash2 className="h-4 w-4" />}
              </Button>
            </div>
          </div>

          {/* Metadata grid */}
          <div className="grid gap-2 rounded-lg border bg-muted/20 p-3 sm:grid-cols-2 lg:grid-cols-3">
            <MetaCell label="Domain" value={detail.domain || "—"} icon={Layers} />
            <MetaCell label="Subdomain" value={detail.subdomain || "—"} icon={Hash} />
            <MetaCell label="Version" value={detail.version ? `v${detail.version}` : "—"} icon={Tag} mono />
            <div className="sm:col-span-2 lg:col-span-3">
              <div className="text-[11px] font-medium uppercase tracking-wide text-muted-foreground">Tags</div>
              {detail.tags.length > 0 ? (
                <div className="mt-1.5 flex flex-wrap gap-1">
                  {detail.tags.map((t) => (
                    <Badge key={t} variant="outline" className="text-[11px] font-normal">
                      {t}
                    </Badge>
                  ))}
                </div>
              ) : (
                <span className="text-xs text-muted-foreground">No tags</span>
              )}
            </div>
            {(detail.nist_csf.length > 0 || detail.mitre_attack.length > 0) && (
              <div className="sm:col-span-2 lg:col-span-3 flex flex-wrap gap-2 pt-1">
                {detail.nist_csf.length > 0 && (
                  <div className="flex flex-wrap items-center gap-1.5">
                    <span className="text-[11px] font-medium uppercase tracking-wide text-muted-foreground">NIST CSF</span>
                    <div className="flex flex-wrap gap-1">
                      {detail.nist_csf.map((c) => (
                        <Badge key={c} variant="secondary" className="border border-violet-500/20 bg-violet-500/10 px-1.5 py-0 text-[11px] font-mono text-violet-700 dark:text-violet-300">
                          {c}
                        </Badge>
                      ))}
                    </div>
                  </div>
                )}
                {detail.mitre_attack.length > 0 && (
                  <div className="flex flex-wrap items-center gap-1.5">
                    <span className="text-[11px] font-medium uppercase tracking-wide text-muted-foreground">MITRE ATT&CK</span>
                    <div className="flex flex-wrap gap-1">
                      {detail.mitre_attack.map((c) => (
                        <Badge key={c} variant="secondary" className="border border-amber-500/20 bg-amber-500/10 px-1.5 py-0 text-[11px] font-mono text-amber-700 dark:text-amber-300">
                          {c}
                        </Badge>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}
            <div className="flex items-center gap-4 pt-1 text-xs text-muted-foreground sm:col-span-2 lg:col-span-3">
              <span className="inline-flex items-center gap-1">
                <FileText className="h-3 w-3" /> {detail.references.length} references
              </span>
              <span className="inline-flex items-center gap-1">
                <BookOpen className="h-3 w-3" /> {sectionEntries.length} sections
              </span>
              <span className="inline-flex items-center gap-1">
                <Tag className="h-3 w-3" /> {detail.tags.length} tags
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Content */}
      <div className="min-h-0 flex-1 overflow-auto scrollbar-thin">
        <div className="space-y-4 p-4">
          <Tabs defaultValue="body" className="w-full">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <TabsList className="h-8">
                <TabsTrigger value="body" className="gap-1.5 text-xs h-7">
                  <FileText className="h-3.5 w-3.5" /> Body
                </TabsTrigger>
                {sectionEntries.length > 0 && (
                  <TabsTrigger value="sections" className="gap-1.5 text-xs h-7">
                    <Layers className="h-3.5 w-3.5" /> Sections
                    <Badge variant="secondary" className="ml-1 h-4 px-1 text-[10px] tabular-nums">
                      {sectionEntries.length}
                    </Badge>
                  </TabsTrigger>
                )}
              </TabsList>
              {sectionEntries.length > 0 && (
                <div className="flex items-center gap-1">
                  <Button variant="ghost" size="sm" className="h-7 text-xs" onClick={() => toggleAll(true)} disabled={allExpanded}>
                    Expand all
                  </Button>
                  <Button variant="ghost" size="sm" className="h-7 text-xs" onClick={() => toggleAll(false)} disabled={!sectionEntries.some(([k]) => expanded[k])}>
                    Collapse all
                  </Button>
                </div>
              )}
            </div>

            <TabsContent value="body" className="mt-4">
              <div className="rounded-xl border bg-card p-4 sm:p-6">
                <SkillMarkdown>{detail.body}</SkillMarkdown>
              </div>
            </TabsContent>

            {sectionEntries.length > 0 && (
              <TabsContent value="sections" className="mt-4 space-y-2">
                {sectionEntries.map(([title, content]) => {
                  const isOpen = expanded[title] ?? false;
                  return (
                    <div key={title} className="overflow-hidden rounded-lg border bg-card">
                      <button
                        type="button"
                        onClick={() => setExpanded((p) => ({ ...p, [title]: !p[title] }))}
                        className="flex w-full items-center justify-between gap-2 px-4 py-3 text-left transition-colors hover:bg-accent/40 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-inset"
                        aria-expanded={isOpen}
                      >
                        <span className="text-sm font-semibold capitalize">{title.replace(/[-_]/g, " ")}</span>
                        <span className="flex items-center gap-2 text-xs text-muted-foreground">
                          <span className="hidden sm:inline">{content.length} chars</span>
                          {isOpen ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
                        </span>
                      </button>
                      {isOpen && (
                        <div className="border-t bg-muted/20 p-4 sm:p-6">
                          <SkillMarkdown>{content}</SkillMarkdown>
                        </div>
                      )}
                    </div>
                  );
                })}
              </TabsContent>
            )}
          </Tabs>

          {/* References */}
          <div className="overflow-hidden rounded-xl border bg-card">
            <div className="flex items-center justify-between gap-2 border-b bg-muted/20 px-4 py-3">
              <div className="flex items-center gap-2">
                <BookOpen className="h-4 w-4 text-muted-foreground" />
                <span className="text-sm font-semibold">References</span>
                <Badge variant="secondary" className="h-5 px-1.5 text-[11px] tabular-nums">
                  {detail.references.length}
                </Badge>
              </div>
              {detail.references.length > 0 && (
                <CopyButton value={detail.references.join("\n")} label="Copy all" size="sm" className="h-7 text-xs" />
              )}
            </div>
            {detail.references.length === 0 ? (
              <p className="p-4 text-sm text-muted-foreground">No references listed for this skill.</p>
            ) : (
              <ul className="divide-y">
                {detail.references.map((r) => (
                  <li key={r} className="flex items-start gap-2.5 px-4 py-2.5">
                    <span className="mt-1 h-1.5 w-1.5 shrink-0 rounded-full bg-muted-foreground/40" aria-hidden />
                    {isValidUrl(r) ? (
                      <a
                        href={r}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-flex min-w-0 items-center gap-1 break-all font-mono text-xs text-primary underline-offset-4 hover:underline"
                      >
                        <span className="truncate">{r}</span>
                        <ExternalLink className="h-3 w-3 shrink-0" />
                      </a>
                    ) : (
                      <span className="break-all font-mono text-xs text-muted-foreground">{r}</span>
                    )}
                    <CopyButton value={r} size="sm" className="ml-auto hidden h-6 shrink-0 px-2 text-[11px] sm:inline-flex" label="Copy" />
                  </li>
                ))}
              </ul>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

function MetaCell({ label, value, icon: Icon, mono }: { label: string; value: string; icon: typeof Layers; mono?: boolean }) {
  return (
    <div className="space-y-1">
      <div className="flex items-center gap-1 text-[11px] font-medium uppercase tracking-wide text-muted-foreground">
        <Icon className="h-3 w-3" /> {label}
      </div>
      <div className={cn("truncate text-sm", mono ? "font-mono text-xs" : "font-medium")}>{value}</div>
    </div>
  );
}
