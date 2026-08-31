import { ConfigEditor } from "./ConfigEditor";

export function RunsSettings() {
  return (
    <div className="space-y-4">
      <div className="rounded-xl border bg-muted/20 px-5 py-3 text-xs leading-relaxed text-muted-foreground">
        These control how BreachPilot runs, scans, and executes. Lower intensity is quieter but slower; higher intensity
        finds more but is noisier. Start with defaults and tune per engagement.
      </div>
      <ConfigEditor category="runs" />
    </div>
  );
}
