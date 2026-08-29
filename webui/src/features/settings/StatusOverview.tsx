// Compact one-line status overview (replaces the four big health cards):
// "● AI Provider Connected ● Models 3 available ● Secrets Configured
// ● Plugins 8/8 loaded". Wraps on narrow screens.

import { useModels, usePlugins, useSandboxStatus, useSecrets } from "@/api/hooks";
import { useProviderStatus } from "@/components/ProviderSetup";
import { cn } from "@/lib/utils";

export function StatusOverview() {
  const status = useProviderStatus();
  const models = useModels();
  const secrets = useSecrets();
  const plugins = usePlugins();
  const sandbox = useSandboxStatus();

  const secretEntries = Object.entries(secrets.data?.keys ?? {});
  const configured = secretEntries.filter(([, s]) => s === "configured").length;
  const pluginList = plugins.data?.plugins ?? [];
  const loaded = pluginList.filter((p) => p.loaded).length;
  const modelCount = status.liveCount > 0 ? status.liveCount : Object.keys(models.data?.registry ?? {}).length;

  // Sandbox tone: enabled+docker-reachable is good; enabled+unreachable is bad
  // (fail-closed blocks attack execution); image missing is warn (build needed);
  // disabled is a deliberate opt-out.
  const sandboxEnabled = sandbox.data?.enabled ?? false;
  const sandboxTone: "ok" | "warn" | "bad" = !sandboxEnabled
    ? "warn"
    : sandbox.data?.docker_available
      ? sandbox.data?.image_present === false
        ? "warn"
        : "ok"
      : "bad";

  return (
    <div className="flex flex-wrap items-center gap-x-4 gap-y-1.5 text-xs text-muted-foreground">
      <StatusItem
        tone={status.online ? "ok" : status.error ? "bad" : "warn"}
        label="AI Provider"
        value={status.online ? "Connected" : status.error ? "Unreachable" : "Offline"}
      />
      <StatusItem tone="ok" label="Models" value={`${modelCount} available`} />
      <StatusItem
        tone={secretEntries.length === 0 || configured < secretEntries.length ? "warn" : "ok"}
        label="Secrets"
        value={
          secretEntries.length === 0
            ? "None configured"
            : configured === secretEntries.length
              ? "Configured"
              : `${configured}/${secretEntries.length} configured`
        }
      />
      <StatusItem tone="ok" label="Plugins" value={`${loaded}/${pluginList.length} loaded`} />
      <StatusItem
        tone={sandboxTone}
        label="Sandbox"
        value={
          sandboxEnabled
            ? sandbox.data?.docker_available
              ? sandbox.data?.image_present === false
                ? "Image missing"
                : `Contained (${sandbox.data?.backend ?? "docker"})`
              : "Docker unreachable"
            : "Disabled (host exec)"
        }
      />
    </div>
  );
}

export function StatusDot({ tone }: { tone: "ok" | "warn" | "bad" }) {
  return (
    <span
      className={cn(
        "inline-block h-1.5 w-1.5 rounded-full",
        tone === "ok" ? "bg-emerald-400" : tone === "warn" ? "bg-amber-400" : "bg-destructive",
      )}
      aria-hidden
    />
  );
}

function StatusItem({ tone, label, value }: { tone: "ok" | "warn" | "bad"; label: string; value: string }) {
  return (
    <span className="inline-flex items-center gap-1.5">
      <StatusDot tone={tone} />
      <span className="font-medium text-foreground">{label}</span>
      <span>{value}</span>
    </span>
  );
}
