// Features: quick summary rows for Memory, Plugins, and Telemetry, then the
// full feature config below. Detailed controls (plugin list, memory page)
// appear only after choosing to manage.

import { useState } from "react";
import { Link } from "react-router-dom";
import { ChevronDown, ChevronRight } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Switch } from "@/components/ui/switch";
import { Badge } from "@/components/ui/badge";
import { SettingsSection } from "./SettingsSection";
import { SettingRow } from "./SettingRow";
import { ConfigEditor } from "./ConfigEditor";
import { useSettingsDraft } from "./useSettingsDraft";
import { usePlugins, useTelemetry } from "@/api/hooks";
import { SkeletonRows } from "@/components/Loading";

export function FeatureSettings() {
  return (
    <div className="space-y-4">
      <SettingsSection title="Highlights" description="Quick toggles and shortcuts for the optional subsystems.">
        <MemoryRow />
        <PluginsRow />
        <TelemetryRow />
      </SettingsSection>
      <ConfigEditor category="features" />
    </div>
  );
}

function MemoryRow() {
  const { draft, update } = useSettingsDraft();
  const enabled = Boolean((draft.memory as Record<string, unknown> | undefined)?.semantic_enabled);
  return (
    <SettingRow
      label="Memory"
      description="Store useful information between agent operations."
      htmlFor="feature-memory"
    >
      <div className="flex items-center gap-2">
        <Switch
          id="feature-memory"
          checked={enabled}
          onCheckedChange={(v) => update("memory", "semantic_enabled", v)}
          aria-label="Memory"
        />
        <Button asChild size="sm" variant="outline">
          <Link to="/memory">Manage</Link>
        </Button>
      </div>
    </SettingRow>
  );
}

function PluginsRow() {
  const plugins = usePlugins();
  const [open, setOpen] = useState(false);
  const list = plugins.data?.plugins ?? [];
  const loaded = list.filter((p) => p.loaded).length;
  return (
    <div>
      <SettingRow label="Plugins" description="Optional capability plugins.">
        <div className="flex items-center gap-2">
          <span className="text-sm text-muted-foreground">
            {plugins.isLoading ? "…" : `${loaded}/${list.length} loaded`}
          </span>
          <Button type="button" size="sm" variant="outline" onClick={() => setOpen((v) => !v)} aria-expanded={open}>
            {open ? <ChevronDown className="h-3.5 w-3.5" /> : <ChevronRight className="h-3.5 w-3.5" />}
            Manage
          </Button>
        </div>
      </SettingRow>
      {open && (
        <div className="border-t py-3">
          <PluginList />
        </div>
      )}
    </div>
  );
}

function TelemetryRow() {
  const telemetry = useTelemetry();
  const summary = telemetry.data?.summary;
  return (
    <SettingRow label="Telemetry" description="LLM usage statistics.">
      <div className="flex items-center gap-2">
        <span className="text-sm text-muted-foreground">
          {summary
            ? `${summary.calls} calls · ${summary.total_tokens.toLocaleString()} tokens`
            : telemetry.isLoading
              ? "…"
              : "No usage yet"}
        </span>
        <Button asChild size="sm" variant="outline">
          <Link to="/stats">View usage</Link>
        </Button>
      </div>
    </SettingRow>
  );
}

function PluginList() {
  const plugins = usePlugins();
  const list = plugins.data?.plugins ?? [];
  if (plugins.isLoading) return <SkeletonRows count={3} className="p-2" />;
  if (plugins.error) {
    return (
      <div className="flex items-center gap-2 text-sm text-destructive">
        <span>Failed to load plugins.</span>
        <Button size="sm" variant="outline" onClick={() => plugins.refetch()}>
          Retry
        </Button>
      </div>
    );
  }
  if (list.length === 0) return <p className="text-sm text-muted-foreground">No discovered plugins.</p>;
  return (
    <ul className="space-y-2">
      {list.map((p, i) => (
        <li key={i} className="rounded-md border p-2 text-xs">
          <div className="flex flex-wrap items-center gap-2">
            <span className="font-mono">{String(p.name ?? `plugin-${i}`)}</span>
            {p.version && <Badge variant="outline" className="text-[10px]">{String(p.version)}</Badge>}
            {p.loaded ? (
              <Badge variant="success" className="text-[10px]">loaded</Badge>
            ) : p.enabled ? (
              <Badge variant="warn" className="text-[10px]">enabled·not loaded</Badge>
            ) : (
              <Badge variant="muted" className="text-[10px]">disabled</Badge>
            )}
          </div>
          {p.description && <div className="mt-1 text-muted-foreground">{String(p.description)}</div>}
          <div className="mt-1 flex flex-wrap items-center gap-1">
            {Array.isArray(p.capabilities) &&
              p.capabilities.map((cap) => (
                <Badge key={cap} variant={cap === "event_subscriber" ? "info" : "outline"} className="text-[10px]">
                  {String(cap)}
                </Badge>
              ))}
          </div>
          <PluginGatingHints plugin={p} />
        </li>
      ))}
    </ul>
  );
}

/** Derive gating hints from a plugin's config_section (the manifest schema). */
function PluginGatingHints({ plugin }: { plugin: { config_section?: Record<string, Record<string, unknown>> | null; capabilities?: string[] } }) {
  const section = plugin.config_section;
  if (!section || typeof section !== "object") {
    const caps = plugin.capabilities ?? [];
    if (caps.includes("mcp_tool")) {
      return (
        <div className="mt-1 text-muted-foreground">
          <Badge variant="outline" className="text-[10px]">requires allowlist</Badge>
        </div>
      );
    }
    return null;
  }
  const hints: Array<{ label: string; variant: "warn" | "outline" | "info" }> = [];
  for (const block of Object.values(section)) {
    if (!block || typeof block !== "object") continue;
    const envKey = block.api_key_env;
    const url = block.url;
    if (typeof envKey === "string" && envKey) hints.push({ label: `needs ${envKey}`, variant: "warn" });
    if (typeof url === "string" && url === "") hints.push({ label: "no-op without url", variant: "warn" });
    if (block.enabled === false) hints.push({ label: "plugin block disabled", variant: "outline" });
  }
  const caps = plugin.capabilities ?? [];
  if (caps.includes("mcp_tool")) hints.push({ label: "requires allowlist", variant: "info" });
  if (hints.length === 0) return null;
  return (
    <div className="mt-1 flex flex-wrap items-center gap-1">
      {hints.map((h, idx) => (
        <Badge key={idx} variant={h.variant} className="text-[10px]">
          {h.label}
        </Badge>
      ))}
    </div>
  );
}
