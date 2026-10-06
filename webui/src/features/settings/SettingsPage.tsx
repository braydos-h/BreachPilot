// The Settings screen: category nav (sidebar on desktop, segmented on mobile),
// a global search, a compact status overview, the active category, and a
// sticky unsaved-changes bar. Everything edits one shared draft.

import { useCallback, useEffect, useState } from "react";
import { useBlocker, type BlockerFunction } from "react-router-dom";
import { Settings } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { SettingsDraftProvider, useSettingsDraft } from "./useSettingsDraft";
import { SettingsNav } from "./SettingsNav";
import { SettingsSearch } from "./SettingsSearch";
import { StatusOverview } from "./StatusOverview";
import { UnsavedChangesBar } from "./UnsavedChangesBar";
import { GeneralSettings } from "./GeneralSettings";
import { ProviderSettings } from "./ProviderSettings";
import { FeatureSettings } from "./FeatureSettings";
import { RunsSettings } from "./RunsSettings";
import { IntegrationsSettings } from "./IntegrationsSettings";
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
  const { savedAt, errors, dirtyCount } = useSettingsDraft();
  const shouldBlockNavigation = useCallback<BlockerFunction>(
    ({ currentLocation, nextLocation }) =>
      dirtyCount > 0 && currentLocation.pathname === "/system" && nextLocation.pathname !== "/system",
    [dirtyCount],
  );
  const blocker = useBlocker(shouldBlockNavigation);

  useEffect(() => {
    if (dirtyCount === 0) return;
    const warnBeforeUnload = (event: BeforeUnloadEvent) => {
      event.preventDefault();
      event.returnValue = "";
    };
    window.addEventListener("beforeunload", warnBeforeUnload);
    return () => window.removeEventListener("beforeunload", warnBeforeUnload);
  }, [dirtyCount]);

  const onSearchSelect = (cat: SettingCategory, section: string, field: string) => {
    setCategory(cat);
    requestAnimationFrame(() => {
      document.getElementById(`setting-${section}-${field}`)?.scrollIntoView?.({ behavior: "smooth", block: "center" });
    });
  };

  return (
    <div className="w-full space-y-4 p-4 md:p-6">
      <header className="space-y-3">
        <div className="flex flex-wrap items-center gap-3">
          <div className="flex items-center gap-2.5">
            <div className="flex h-9 w-9 items-center justify-center rounded-lg border bg-card">
              <Settings className="h-5 w-5 text-primary" />
            </div>
            <div>
              <h1 className="text-lg font-semibold leading-tight">Settings</h1>
              <p className="text-sm text-muted-foreground">Manage how BreachPilot works for you.</p>
            </div>
          </div>
          {savedAt && <span className="text-xs text-emerald-300">{formatSavedAt(savedAt)}</span>}
          <div className="ml-auto">
            <SettingsSearch onSelect={onSearchSelect} />
          </div>
        </div>
        <div className="rounded-lg border bg-card/40 px-3 py-2.5">
          <StatusOverview />
        </div>
        {errors.length > 0 && (
          <div className="rounded-md border border-destructive/40 bg-destructive/10 px-3 py-2 text-xs text-destructive">
            {errors.map((e, i) => (
              <div key={i}>{e}</div>
            ))}
          </div>
        )}
      </header>

      <div className="flex flex-col gap-6 md:flex-row md:gap-8">
        <div className="md:w-52 md:shrink-0 md:sticky md:top-4 md:self-start">
          <SettingsNav value={category} onChange={setCategory} />
        </div>
        <div className="min-w-0 flex-1">
          {category === "general" && <GeneralSettings />}
          {category === "ai" && <ProviderSettings />}
          {category === "runs" && <RunsSettings />}
          {category === "features" && <FeatureSettings />}
          {category === "integrations" && <IntegrationsSettings />}
          {category === "advanced" && <AdvancedSettings />}
        </div>
      </div>

      <UnsavedChangesBar />
      <Dialog
        open={blocker.state === "blocked"}
        onOpenChange={(open) => {
          if (!open && blocker.state === "blocked") blocker.reset();
        }}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Discard unsaved settings?</DialogTitle>
            <DialogDescription>
              You have unsaved settings changes. Stay here to keep editing, or discard them and continue to the page you selected.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button
              type="button"
              variant="outline"
              onClick={() => {
                if (blocker.state === "blocked") blocker.reset();
              }}
            >
              Stay on settings
            </Button>
            <Button
              type="button"
              variant="destructive"
              onClick={() => {
                if (blocker.state === "blocked") blocker.proceed();
              }}
            >
              Discard changes and leave
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
