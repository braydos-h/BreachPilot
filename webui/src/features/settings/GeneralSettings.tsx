// General: appearance + common application configuration with friendly labels.
// The ConfigEditor renders every general-category field from the backend schema.

import { Moon, Sun } from "lucide-react";
import { useTheme, setTheme } from "@/lib/useTheme";
import { ConfigEditor } from "./ConfigEditor";
import { SettingsSection } from "./SettingsSection";
import { SettingRow } from "./SettingRow";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";

export function GeneralSettings() {
  const { theme } = useTheme();
  return (
    <div className="space-y-4">
      <SettingsSection title="Appearance" description="How BreachPilot looks in your browser.">
        <SettingRow label="Theme" description="Choose dark or light mode.">
          <Select value={theme} onValueChange={(v) => setTheme(v as "dark" | "light")}>
            <SelectTrigger className="w-full sm:w-56" aria-label="Theme">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="dark">
                <span className="inline-flex items-center gap-1.5">
                  <Moon className="h-3.5 w-3.5" /> Dark
                </span>
              </SelectItem>
              <SelectItem value="light">
                <span className="inline-flex items-center gap-1.5">
                  <Sun className="h-3.5 w-3.5" /> Light
                </span>
              </SelectItem>
            </SelectContent>
          </Select>
        </SettingRow>
      </SettingsSection>
      <div className="rounded-xl border bg-muted/20 px-5 py-3 text-xs leading-relaxed text-muted-foreground">
        Everyday preferences for how BreachPilot behaves. These are the settings you will change most often.
      </div>
      <ConfigEditor category="general" />
    </div>
  );
}
