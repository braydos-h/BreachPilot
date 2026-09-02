// General: common application configuration with friendly labels.
// The ConfigEditor renders every general-category field from the backend schema.

import { ConfigEditor } from "./ConfigEditor";

export function GeneralSettings() {
  return (
    <div className="space-y-4">
      <div className="rounded-xl border bg-muted/20 px-5 py-3 text-xs leading-relaxed text-muted-foreground">
        Everyday preferences for how BreachPilot behaves. These are the settings you will change most often.
      </div>
      <ConfigEditor category="general" />
    </div>
  );
}
