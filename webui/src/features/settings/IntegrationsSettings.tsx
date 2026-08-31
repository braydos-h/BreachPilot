import { ConfigEditor } from "./ConfigEditor";

export function IntegrationsSettings() {
  return (
    <div className="space-y-4">
      <div className="rounded-xl border bg-muted/20 px-5 py-3 text-xs leading-relaxed text-muted-foreground">
        Connect BreachPilot to external services and notifications. Keys are stored server-side and never shown again;
        entering a new value replaces the existing one.
      </div>
      <ConfigEditor category="integrations" />
    </div>
  );
}
