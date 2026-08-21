import { useEffect, useState } from "react";
import { Check, Loader2, ShieldCheck } from "lucide-react";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Switch } from "@/components/ui/switch";
import { Card, CardContent } from "@/components/ui/card";
import { Spinner } from "@/components/Loading";
import { useConfig, usePatchConfig } from "@/api/hooks";
import { ApiError } from "@/api/client";
import type { RunMode } from "@/api/types";

const OPSEC_FIELDS: Array<{ key: string; label: string; hint: string }> = [
  { key: "enabled", label: "OPSEC enabled", hint: "Master switch. Advisory only — never gates tool execution." },
  { key: "ua_rotation", label: "User-Agent rotation", hint: "Rotate browser User-Agents on HTTP egress." },
  { key: "doh", label: "DNS over HTTPS", hint: "Resolve DNS via DoH (cloudflare/google) instead of local resolver." },
  { key: "min_gap_seconds", label: "Min gap (s)", hint: "Base pacing delay between actions." },
  { key: "jitter_seconds", label: "Jitter (s)", hint: "Random +/- added to the pacing gap." },
  { key: "rate_per_minute", label: "Rate cap (per min)", hint: "Token-bucket cap on actions. 0 = unlimited." },
  { key: "noise_budget", label: "Noise budget", hint: "Max noisy commands. 0 = unlimited. Dormant — not a gate." },
  { key: "local_targets_off", label: "Off for local targets", hint: "Private/RFC1918/local targets force OPSEC off so the AI moves freely on your own box." },
  { key: "public_autonomy", label: "Public autonomy", hint: "Documentary: for public targets the AI chooses its own attacks." },
  { key: "doh_provider", label: "DoH provider", hint: "cloudflare | google" },
  { key: "quiet_command_patterns", label: "Quiet command patterns", hint: "Substrings refused when enabled (advisory)." },
  { key: "local_cidrs", label: "Local CIDRs", hint: "Extra ranges treated as local (OPSEC off)." },
];

const SECTIONS: Array<{ title: string; keys: string[] }> = [
  { title: "Identity & headers", keys: ["ua_rotation"] },
  { title: "Timing & pacing", keys: ["min_gap_seconds", "jitter_seconds", "rate_per_minute"] },
  { title: "Network behavior", keys: ["doh", "doh_provider"] },
  { title: "Traffic behavior", keys: ["quiet_command_patterns"] },
  { title: "Other", keys: ["enabled", "noise_budget", "local_targets_off", "local_cidrs", "public_autonomy"] },
];

interface OpsecSettingsProps {
  mode: RunMode;
}

function cloneDeep<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

/** OPSEC posture editor. Self-contained — loads `opsec` from the config and
 *  persists a full-block PATCH on save. Advisory only; the server stays the
 *  authority. Dirty/saved/saving states mirror the original panel. */
export function OpsecSettings({ mode }: OpsecSettingsProps) {
  const opsecConfig = useConfig();
  const patchConfig = usePatchConfig();
  const [draft, setDraft] = useState<Record<string, unknown>>({});
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    const block = (opsecConfig.data as Record<string, unknown> | undefined)?.opsec;
    if (block && typeof block === "object") setDraft(cloneDeep(block) as Record<string, unknown>);
  }, [opsecConfig.data]);

  const dirty = JSON.stringify(draft) !== JSON.stringify(opsecConfig.data?.opsec);
  const update = (key: string, next: unknown) => setDraft((prev) => ({ ...prev, [key]: next }));

  const onSave = () => {
    setError("");
    patchConfig.mutate(
      { opsec: draft },
      {
        onSuccess: () => setSaved(true),
        onError: (err) => setError(err instanceof ApiError ? err.message : "Failed to save OPSEC settings."),
      },
    );
  };

  const isAttack = mode === "attack";
  const loading = opsecConfig.isLoading;

  return (
    <Card>
      <CardContent className="space-y-4 pt-6">
        <div className="flex items-start gap-2 rounded-md border bg-background/30 px-3 py-2">
          <ShieldCheck
            className={cn("mt-0.5 h-4 w-4 shrink-0", isAttack ? "text-amber-300" : "text-muted-foreground")}
            aria-hidden
          />
          <p className="text-xs leading-relaxed text-muted-foreground">
            {isAttack
              ? "Attack runs: OPSEC hardening (pacing, UA rotation, DoH) reduces your detection footprint. Target-aware — automatically off for local/private targets. Advisory only, never a gate."
              : "Recon mode is always read-only. OPSEC posture is advisory and only applies to attack runs; you can review it here and it is saved for attack runs."}
          </p>
        </div>

        {loading ? (
          <Spinner label="Loading OPSEC settings..." className="py-4" />
        ) : (
          <>
            {SECTIONS.map((section) => (
              <div key={section.title} className="space-y-2.5">
                <h3 className="text-[11px] font-semibold uppercase tracking-wide text-muted-foreground">
                  {section.title}
                </h3>
                <div className="grid gap-3 sm:grid-cols-2">
                  {section.keys.map((key) => {
                    const field = OPSEC_FIELDS.find((f) => f.key === key);
                    if (!field) return null;
                    return (
                      <OpsecField
                        key={key}
                        label={field.label}
                        hint={field.hint}
                        value={draft[key]}
                        onChange={(next) => update(key, next)}
                      />
                    );
                  })}
                </div>
              </div>
            ))}

            {error && (
              <div className="rounded-md border border-destructive/40 bg-destructive/10 p-3 text-sm text-red-200">
                {error}
              </div>
            )}
            {saved && !dirty && <p className="text-xs text-emerald-300">OPSEC settings saved.</p>}

            <div className="flex items-center gap-2 border-t pt-3">
              <Button type="button" size="sm" onClick={onSave} disabled={patchConfig.isPending || !dirty}>
                {patchConfig.isPending ? (
                  <Loader2 className="h-4 w-4 animate-spin" />
                ) : (
                  <Check className="h-4 w-4" />
                )}{" "}
                Save OPSEC settings
              </Button>
              <span className="text-xs text-muted-foreground">
                {dirty ? "Unsaved changes" : "Saved — matches config.yaml"}
              </span>
            </div>
          </>
        )}
      </CardContent>
    </Card>
  );
}

function OpsecField({
  label,
  hint,
  value,
  onChange,
}: {
  label: string;
  hint: string;
  value: unknown;
  onChange: (next: unknown) => void;
}) {
  const id = `opsec-${label.replace(/[^a-zA-Z0-9]/g, "-")}`;
  if (typeof value === "boolean") {
    return (
      <div className="space-y-1">
        <div className="flex items-center justify-between gap-2">
          <Label htmlFor={id} className="text-xs">
            {label}
          </Label>
          <Switch id={id} checked={value} onCheckedChange={(v) => onChange(v === true)} />
        </div>
        <p className="text-[11px] text-muted-foreground">{hint}</p>
      </div>
    );
  }
  if (Array.isArray(value)) {
    return (
      <div className="space-y-1">
        <Label htmlFor={id} className="text-xs">
          {label}
        </Label>
        <Textarea
          id={id}
          value={value.join("\n")}
          onChange={(e) => onChange(e.target.value.split("\n").map((l) => l.trim()).filter(Boolean))}
          placeholder={hint}
          autoComplete="off"
          className="min-h-[3rem] text-xs"
        />
        <p className="text-[11px] text-muted-foreground">{hint} — one per line.</p>
      </div>
    );
  }
  return (
    <div className="space-y-1">
      <Label htmlFor={id} className="text-xs">
        {label}
      </Label>
      <Input
        id={id}
        value={value === undefined ? "" : String(value)}
        onChange={(e) => onChange(e.target.value)}
        placeholder={hint}
        autoComplete="off"
      />
      <p className="text-[11px] text-muted-foreground">{hint}</p>
    </div>
  );
}
