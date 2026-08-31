// Schema-driven config editor filtered to one category. Renders each section
// as a SettingsSection with ConfigField rows, using friendly labels from
// SETTING_META. Fields marked `advanced` stay hidden behind a "Show advanced
// settings" disclosure. Unknown fields (no meta) surface under Advanced with
// their raw key, so the backend schema is never lost.

import { useMemo, useState } from "react";
import { ChevronDown, ChevronRight, Loader2 } from "lucide-react";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { SettingsSection } from "./SettingsSection";
import { ConfigField } from "./ConfigField";
import { useSettingsDraft } from "./useSettingsDraft";
import { fieldCategory, getSettingMeta, sectionLabel, type SettingCategory } from "./settingMeta";

interface ConfigEditorProps {
  category: SettingCategory;
  /** Restrict to these schema sections (e.g. AI & Providers hand-picks). */
  sections?: string[];
  className?: string;
}

export function ConfigEditor({ category, sections, className }: ConfigEditorProps) {
  const { draft, schema, isLoading, error, update } = useSettingsDraft();
  const [showAdvanced, setShowAdvanced] = useState(false);

  const isDepSatisfied = (dependsOn: unknown): boolean => {
    if (!dependsOn) return true;
    if (typeof dependsOn === "string") {
      const eqIdx = dependsOn.indexOf("=");
      if (eqIdx !== -1) {
        const key = dependsOn.slice(0, eqIdx).trim();
        const expected = dependsOn.slice(eqIdx + 1).trim();
        const [depSection, depField] = key.split(".");
        if (!depSection || !depField) return true;
        const val = resolveValue(draft, depSection, depField);
        return String(val) === expected;
      }
      const [depSection, depField] = dependsOn.split(".");
      if (!depSection || !depField) return true;
      const val = resolveValue(draft, depSection, depField);
      return Boolean(val);
    }
    if (typeof dependsOn === "object" && dependsOn !== null) {
      const dep = dependsOn as { section: string; field: string; value?: unknown };
      const depVal = resolveValue(draft, dep.section, dep.field);
      if (dep.value !== undefined) return depVal === dep.value;
      return Boolean(depVal);
    }
    return true;
  };

  const sectionEntries = useMemo(() => {
    if (!schema) return [];
    const entries = Object.entries(schema as Record<string, unknown>)
      .filter(([section]) => !sections || sections.includes(section))
      .map(([section, value]) => {
        let fields = Object.entries((value ?? {}) as Record<string, unknown>).filter(([field]) => {
          const meta = getSettingMeta(section, field);
          if (meta?.hide) return false;
          if (fieldCategory(section, field) !== category) return false;
          if (meta?.advanced && !showAdvanced) return false;
          if (meta?.dependsOn && !isDepSatisfied(meta.dependsOn)) return false;
          return true;
        });
        fields = fields.sort((a, b) => {
          const ma = getSettingMeta(section, a[0]);
          const mb = getSettingMeta(section, b[0]);
          const oa = ma?.order ?? 999;
          const ob = mb?.order ?? 999;
          if (oa !== ob) return oa - ob;
          return a[0].localeCompare(b[0]);
        });
        return { section, fields };
      })
      .filter(({ fields }) => fields.length > 0);
    return entries;
  }, [schema, category, sections, showAdvanced, draft]);

  const hasAdvanced = useMemo(() => {
    if (!schema) return false;
    return Object.entries(schema as Record<string, unknown>).some(([section, value]) => {
      if (sections && !sections.includes(section)) return false;
      return Object.keys((value ?? {}) as Record<string, unknown>).some((field) => {
        const meta = getSettingMeta(section, field);
        if (!meta || meta.advanced !== true || meta.category !== category) return false;
        if (meta.hide) return false;
        if (fieldCategory(section, field) !== category) return false;
        if (meta.dependsOn && !isDepSatisfied(meta.dependsOn)) return false;
        return true;
      });
    });
  }, [schema, category, sections, draft]);

  if (isLoading) {
    return (
      <div className="flex items-center gap-2 text-sm text-muted-foreground">
        <Loader2 className="h-4 w-4 animate-spin" />
        Loading config...
      </div>
    );
  }
  if (error) {
    return <div className="text-sm text-destructive">Could not load config.</div>;
  }
  if (!schema) return null;

  return (
    <div className={cn("space-y-4", className)}>
      {sectionEntries.map(({ section, fields }) => (
        <SettingsSection key={section} title={sectionLabel(section)}>
          {fields.map(([field, defaultVal]) => {
            const meta = getSettingMeta(section, field);
            const options = typeof meta?.options === "function" ? meta.options(draft) : meta?.options;
            return (
              <ConfigField
                key={`${section}.${field}`}
                section={section}
                field={field}
                value={resolveValue(draft, section, field)}
                defaultValue={defaultVal}
                options={options}
                onChange={(next) => update(section, field, next)}
              />
            );
          })}
        </SettingsSection>
      ))}

      {hasAdvanced && (
        <Button
          type="button"
          variant="ghost"
          size="sm"
          onClick={() => setShowAdvanced((v) => !v)}
          className="w-full justify-center gap-1.5 text-muted-foreground"
          aria-expanded={showAdvanced}
        >
          {showAdvanced ? <ChevronDown className="h-3.5 w-3.5" /> : <ChevronRight className="h-3.5 w-3.5" />}
          {showAdvanced ? "Hide advanced settings" : "Show advanced settings"}
        </Button>
      )}
    </div>
  );
}

function resolveValue(draft: Record<string, unknown>, section: string, field: string): unknown {
  const sec = draft[section];
  if (sec && typeof sec === "object") {
    return (sec as Record<string, unknown>)[field];
  }
  return undefined;
}
