// The Settings screen: category nav (sidebar on desktop, segmented on mobile),
// a global search, a compact status overview, the active category, and a
// sticky unsaved-changes bar. Everything edits one shared draft.

import { useState } from "react";
import { Settings, Stethoscope } from "lucide-react";
import { Button } from "@/components/ui/button";
import { SettingsDraftProvider, useSettingsDraft } from "./useSettingsDraft";
import { SettingsNav } from "./SettingsNav";
import { SettingsSearch } from "./SettingsSearch";
import { StatusOverview } from "./StatusOverview";
import { UnsavedChangesBar } from "./UnsavedChangesBar";
import { GeneralSettings } from "./GeneralSettings";
import { ProviderSettings } from "./ProviderSettings";
import { FeatureSettings } from "./FeatureSettings";
import { AdvancedSettings } from "./AdvancedSettings";
import { formatSavedAt } from "./format";
import type { SettingCategory } from "./settingMeta";

export function SettingsPage() {
  return (
    <SettingsDraftProvider>
      <SettingsPageInner />
    </SettingsDraftProvider>
  );
}

function SettingsPageInner() {
  const [category, setCategory] = useState<SettingCategory>("general");
  const { savedAt } = useSettingsDraft();

  const onSearchSelect = (cat: SettingCategory, section: string, field: string) => {
    setCategory(cat);
    // Scroll to the field once the category renders (no-op if it's hidden
    // behind "Show advanced settings" — the user lands on the right category).
    requestAnimationFrame(() => {
      document.getElementById(`setting-${section}-${field}`)?.scrollIntoView({ behavior: "smooth", block: "center" });
    });
  };

  return (
    <div className="space-y-4 p-4 md:p-6">
      <header className="space-y-3">
        <div className="flex flex-wrap items-center gap-3">
          <div className="flex items-center gap-2.5">
            <div className="flex h-9 w-9 items-center justify-center rounded-lg border bg-card">
              <Settings className="h-5 w-5 text-primary" />
            </div>
            <div>
              <h1 className="text-lg font-semibold leading-tight">Settings</h1>
              <p className="text-sm text-muted-foreground">Providers, configuration, and diagnostics.</p>
            </div>
          </div>
          {savedAt && <span className="text-xs text-emerald-300">{formatSavedAt(savedAt)}</span>}
          <div className="ml-auto flex items-center gap-2">
            <Button size="sm" variant="outline" onClick={() => setCategory("advanced")}>
              <Stethoscope className="h-4 w-4" />
              Run doctor
            </Button>
            <SettingsSearch onSelect={onSearchSelect} />
          </div>
        </div>
        <StatusOverview />
      </header>

      <div className="flex flex-col gap-4 md:flex-row md:gap-6">
        <div className="md:w-44 md:shrink-0">
          <SettingsNav value={category} onChange={setCategory} />
        </div>
        <div className="min-w-0 flex-1">
          {category === "general" && <GeneralSettings />}
          {category === "ai" && <ProviderSettings />}
          {category === "features" && <FeatureSettings />}
          {category === "advanced" && <AdvancedSettings />}
        </div>
      </div>

      <UnsavedChangesBar />
    </div>
  );
}
