import { useEffect, useMemo, useState } from "react";
import { Loader2, Save } from "lucide-react";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { useConfig, useConfigSchema, usePatchConfig } from "@/api/hooks";
import { ApiError } from "@/api/client";

interface ConfigEditorProps {
  className?: string;
}

const REDACTED = "[REDACTED]";

export function ConfigEditor({ className }: ConfigEditorProps) {
  const config = useConfig();
  const schema = useConfigSchema();
  const patch = usePatchConfig();
  const [draft, setDraft] = useState<Record<string, unknown>>({});
  const [errors, setErrors] = useState<string[]>([]);
  const [savedAt, setSavedAt] = useState<string>("");
  const [resetKey, setResetKey] = useState(0);

  useEffect(() => {
    if (config.data) {
      setDraft(clone(config.data));
      setErrors([]);
      setResetKey((key) => key + 1);
    }
  }, [config.data]);

  const sections = useMemo(() => {
    const schemaData = schema.data?.schema;
    if (!schemaData || typeof schemaData !== "object") return [];
    return Object.entries(schemaData as Record<string, unknown>)
      .filter(([, value]) => value && typeof value === "object")
      .map(([key, value]) => ({ key, value: value as Record<string, unknown> }));
  }, [schema.data]);

  const dirty = useMemo(() => diff(draft, config.data ?? {}), [draft, config.data]);

  const onSave = () => {
    setErrors([]);
    patch.mutate(dirty, {
      onSuccess: () => {
        setSavedAt(new Date().toISOString());
      },
      onError: (err) => {
        if (err instanceof ApiError && err.details && Array.isArray((err.details as { errors?: unknown[] }).errors)) {
          setErrors((err.details as { errors: string[] }).errors);
        } else {
          setErrors([err instanceof ApiError ? err.message : "Config patch failed."]);
        }
      },
    });
  };

  if (config.isLoading || schema.isLoading) {
    return <div className="flex items-center gap-2 text-sm text-muted-foreground"><Loader2 className="h-4 w-4 animate-spin" />Loading config...</div>;
  }
  if (config.error || schema.error) {
    return <div className="text-sm text-destructive">Could not load config.</div>;
  }

  return (
    <div className={cn("space-y-4", className)}>
      <div className="flex flex-wrap items-center gap-2">
        <Button type="button" onClick={onSave} disabled={Object.keys(dirty).length === 0 || patch.isPending}>
          {patch.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Save className="h-4 w-4" />}
          Save changes
        </Button>
        <span className="text-xs text-muted-foreground">
          {Object.keys(dirty).length} changed {Object.keys(dirty).length === 1 ? "field" : "fields"}
        </span>
        {savedAt && <span className="text-xs text-emerald-300">Saved {savedAt}</span>}
        <Button
          type="button"
          variant="ghost"
          size="sm"
          onClick={() => {
            if (!config.data) return;
            setDraft(clone(config.data));
            setResetKey((key) => key + 1);
          }}
        >
          Reset
        </Button>
      </div>

      {errors.length > 0 && (
        <div className="rounded-md border border-destructive/40 bg-destructive/10 p-3 text-sm text-red-200">
          <div className="mb-1 font-medium">Validation errors</div>
          <ul className="list-disc space-y-0.5 pl-4 text-xs">
            {errors.map((e, i) => <li key={i}>{e}</li>)}
          </ul>
        </div>
      )}

      <p className="text-xs text-muted-foreground">
        Redacted values are shown as <code className="rounded bg-muted px-1 py-0.5">{REDACTED}</code>. The API
        merges partial patches, so leave redacted fields untouched unless you intend to replace them.
      </p>

      <div className="space-y-4">
        {sections.map((section) => (
          <details key={section.key} className="rounded-md border bg-card/40">
            <summary className="cursor-pointer select-none px-3 py-2 text-sm font-medium">{section.key}</summary>
            <div className="space-y-3 border-t p-3">
              {Object.entries(section.value)
                .filter(([field]) => !["token_file"].includes(field) || section.key !== "api")
                .map(([field, defaultVal]) => (
                  <ConfigField
                    key={`${section.key}.${field}.${resetKey}`}
                    label={`${section.key}.${field}`}
                    value={resolveValue(draft, section.key, field)}
                    defaultValue={defaultVal}
                    onChange={(next) => updateDraft(setDraft, section.key, field, next)}
                  />
                ))}
            </div>
          </details>
        ))}
      </div>
    </div>
  );
}

interface ConfigFieldProps {
  label: string;
  value: unknown;
  defaultValue: unknown;
  onChange: (next: unknown) => void;
}

function ConfigField({ label, value, defaultValue, onChange }: ConfigFieldProps) {
  const isRedacted = typeof value === "string" && value === REDACTED;
  const inferredType = inferType(defaultValue, value);
  const serializedValue = isRedacted ? REDACTED : safeStringify(value ?? {});
  const [dictText, setDictText] = useState(serializedValue);
  const [dictInvalid, setDictInvalid] = useState(false);

  useEffect(() => {
    setDictText(serializedValue);
    setDictInvalid(false);
  }, [serializedValue]);

  if (inferredType === "boolean") {
    return (
      <div className="flex items-center justify-between gap-3">
        <Label className="text-xs">{label}</Label>
        <Switch
          checked={isRedacted ? false : Boolean(value)}
          disabled={isRedacted}
          onCheckedChange={onChange}
        />
      </div>
    );
  }

  if (inferredType === "list") {
    const items = Array.isArray(value) ? value : [];
    return (
      <div className="space-y-1.5">
        <Label className="text-xs">{label}</Label>
        <Textarea
          value={isRedacted ? REDACTED : items.map((i) => String(i)).join("\n")}
          onChange={(e) => onChange(parseList(e.target.value))}
          disabled={isRedacted}
          className="min-h-[5rem] font-mono text-xs"
        />
        <p className="text-xs text-muted-foreground">One item per line.</p>
      </div>
    );
  }

  if (inferredType === "dict") {
    return (
      <div className="space-y-1.5">
        <Label className="text-xs">{label}</Label>
        <Textarea
          value={dictText}
          onChange={(e) => {
            setDictText(e.target.value);
            try {
              onChange(JSON.parse(e.target.value));
              setDictInvalid(false);
            } catch {
              setDictInvalid(true);
            }
          }}
          disabled={isRedacted}
          aria-invalid={dictInvalid}
          className="min-h-[6rem] font-mono text-xs"
        />
        {dictInvalid && <p className="text-xs text-destructive">Enter valid JSON before saving.</p>}
      </div>
    );
  }

  if (inferredType === "int") {
    return (
      <div className="space-y-1.5">
        <Label className="text-xs">{label}</Label>
        <Input
          type="number"
          value={isRedacted ? REDACTED : String(value ?? "")}
          onChange={(e) => onChange(Number(e.target.value))}
          disabled={isRedacted}
        />
      </div>
    );
  }

  return (
    <div className="space-y-1.5">
      <Label className="text-xs">{label}</Label>
      <Input
        value={isRedacted ? REDACTED : String(value ?? "")}
        onChange={(e) => onChange(e.target.value)}
        disabled={isRedacted}
      />
    </div>
  );
}

function inferType(defaultValue: unknown, value: unknown): "boolean" | "int" | "list" | "dict" | "string" {
  if (typeof value === "boolean") return "boolean";
  if (typeof defaultValue === "boolean") return "boolean";
  if (Array.isArray(value) || Array.isArray(defaultValue)) return "list";
  if (value !== null && typeof value === "object") return "dict";
  if (defaultValue !== null && typeof defaultValue === "object") return "dict";
  if (typeof value === "number" || typeof defaultValue === "number") return "int";
  return "string";
}

function resolveValue(draft: Record<string, unknown>, section: string, field: string): unknown {
  const sec = draft[section];
  if (sec && typeof sec === "object") {
    return (sec as Record<string, unknown>)[field];
  }
  return undefined;
}

function updateDraft(
  setDraft: React.Dispatch<React.SetStateAction<Record<string, unknown>>>,
  section: string,
  field: string,
  next: unknown,
) {
  setDraft((prev) => {
    const clonePrev = clone(prev);
    const sec = (clonePrev[section] ?? {}) as Record<string, unknown>;
    sec[field] = next;
    clonePrev[section] = sec;
    return clonePrev;
  });
}

function clone<T>(value: T): T {
  if (typeof structuredClone === "function") return structuredClone(value);
  return JSON.parse(JSON.stringify(value)) as T;
}

function diff(draft: Record<string, unknown>, base: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const key of Object.keys(draft)) {
    const dVal = draft[key];
    const bVal = base[key];
    if (dVal && typeof dVal === "object" && !Array.isArray(dVal) && bVal && typeof bVal === "object") {
      const nested = diff(dVal as Record<string, unknown>, bVal as Record<string, unknown>);
      if (Object.keys(nested).length) out[key] = nested;
    } else if (JSON.stringify(dVal) !== JSON.stringify(bVal)) {
      out[key] = dVal;
    }
  }
  return out;
}

function parseList(text: string): string[] {
  return text.split("\n").map((l) => l.trim()).filter(Boolean);
}

function safeStringify(value: unknown): string {
  try {
    return JSON.stringify(value, null, 2);
  } catch {
    return String(value);
  }
}
