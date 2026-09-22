import { useMemo, useState } from "react";
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
import { useToast } from "@/hooks/use-toast";
import {
  readSkillsConfig,
  skillState,
  type SkillsConfig,
  type SortKey,
  type StatusFilter,
} from "./skillsConfig";

/** All Skills page state: queries, filters, selection, dialogs, and mutations. */
export function useSkillsPage() {
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
      const order: Record<string, number> = { enabled: 0, auto: 1, blocked: 2 };
      out = [...out].sort(
        (a, b) =>
          order[skillState(a.name, skillsCfg)] - order[skillState(b.name, skillsCfg)] ||
          a.name.localeCompare(b.name),
      );
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
        if (
          enabled.size !== (skillsCfg.default_enabled ?? []).length ||
          exclude.size !== (skillsCfg.exclude_names ?? []).length
        ) {
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

  return {
    config,
    skills,
    search,
    detail,
    patch,
    install,
    remove,
    query,
    setQuery,
    tag,
    setTag,
    status,
    setStatus,
    sort,
    setSort,
    showFilters,
    setShowFilters,
    selected,
    setSelected,
    addOpen,
    setAddOpen,
    confirmDelete,
    setConfirmDelete,
    draftName,
    setDraftName,
    draftMarkdown,
    setDraftMarkdown,
    draftError,
    previewTab,
    setPreviewTab,
    skillsCfg,
    topTags,
    filtered,
    total,
    enabledCount,
    blockedCount,
    autoCount,
    isSearching,
    masterEnabled,
    hasActiveFilters,
    clearFilters,
    patchSkills,
    onEnable,
    onAuto,
    onBlock,
    onDelete,
    onInstall,
  };
}

export type SkillsPageState = ReturnType<typeof useSkillsPage>;
