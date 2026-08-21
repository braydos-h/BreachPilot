// Shared config-draft state for the settings page. The backend config schema
// is the source of truth; this context owns the editable draft, the dirty diff,
// and the patch/save lifecycle so every category edits the same unsaved state.

import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from "react";
import { useConfig, useConfigSchema, usePatchConfig } from "@/api/hooks";
import { ApiError } from "@/api/client";
import { useToast } from "@/hooks/use-toast";

export const REDACTED = "[REDACTED]";

interface SettingsDraftValue {
  config: Record<string, unknown> | undefined;
  schema: Record<string, unknown> | undefined;
  isLoading: boolean;
  error: boolean;
  draft: Record<string, unknown>;
  dirty: Record<string, unknown>;
  dirtyCount: number;
  errors: string[];
  isSaving: boolean;
  /** ISO timestamp of the last successful save (rendered human-friendly). */
  savedAt: string | null;
  update: (section: string, field: string, value: unknown) => void;
  save: () => void;
  reset: () => void;
}

const SettingsDraftContext = createContext<SettingsDraftValue | null>(null);

export function SettingsDraftProvider({ children }: { children: React.ReactNode }) {
  const config = useConfig();
  const schema = useConfigSchema();
  const patch = usePatchConfig();
  const { toast } = useToast();
  const [draft, setDraft] = useState<Record<string, unknown>>({});
  const [errors, setErrors] = useState<string[]>([]);
  const [savedAt, setSavedAt] = useState<string | null>(null);
  const baseRef = useRef<Record<string, unknown>>({});

  // Adopt the server config whenever it actually changes (initial load, after
  // a save, or an external change). A refetch that returns the same config as
  // our base leaves the user's unsaved edits alone.
  useEffect(() => {
    if (!config.data) return;
    const next = clone(config.data);
    if (JSON.stringify(next) === JSON.stringify(baseRef.current)) return;
    baseRef.current = next;
    setDraft(next);
    setErrors([]);
  }, [config.data]);

  // Clear the "Saved just now" indicator after a few seconds.
  useEffect(() => {
    if (!savedAt) return;
    const t = setTimeout(() => setSavedAt(null), 4000);
    return () => clearTimeout(t);
  }, [savedAt]);

  const dirty = useMemo(() => diff(draft, baseRef.current), [draft]);
  const dirtyCount = Object.keys(dirty).length;

  const update = useCallback((section: string, field: string, value: unknown) => {
    setDraft((prev) => {
      const next = clone(prev);
      const sec = (next[section] ?? {}) as Record<string, unknown>;
      sec[field] = value;
      next[section] = sec;
      return next;
    });
  }, []);

  const save = useCallback(() => {
    setErrors([]);
    patch.mutate(dirty, {
      onSuccess: () => {
        setSavedAt(new Date().toISOString());
        toast({ title: "Changes saved" });
      },
      onError: (err) => {
        if (err instanceof ApiError && err.details && Array.isArray((err.details as { errors?: unknown[] }).errors)) {
          setErrors((err.details as { errors: string[] }).errors);
        } else {
          setErrors([err instanceof ApiError ? err.message : "Config patch failed."]);
        }
      },
    });
  }, [dirty, patch, toast]);

  const reset = useCallback(() => {
    if (!config.data) return;
    baseRef.current = clone(config.data);
    setDraft(clone(config.data));
    setErrors([]);
  }, [config.data]);

  const value = useMemo<SettingsDraftValue>(
    () => ({
      config: config.data,
      schema: schema.data?.schema,
      isLoading: config.isLoading || schema.isLoading,
      error: Boolean(config.error || schema.error),
      draft,
      dirty,
      dirtyCount,
      errors,
      isSaving: patch.isPending,
      savedAt,
      update,
      save,
      reset,
    }),
    [config.data, config.isLoading, config.error, schema.data, schema.isLoading, schema.error, draft, dirty, dirtyCount, errors, patch.isPending, savedAt, update, save, reset],
  );

  return <SettingsDraftContext.Provider value={value}>{children}</SettingsDraftContext.Provider>;
}

export function useSettingsDraft(): SettingsDraftValue {
  const ctx = useContext(SettingsDraftContext);
  if (!ctx) throw new Error("useSettingsDraft must be used within SettingsDraftProvider");
  return ctx;
}

export function clone<T>(value: T): T {
  if (typeof structuredClone === "function") return structuredClone(value);
  return JSON.parse(JSON.stringify(value)) as T;
}

export function diff(draft: Record<string, unknown>, base: Record<string, unknown>): Record<string, unknown> {
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

export function parseList(text: string): string[] {
  return text.split("\n").map((l) => l.trim()).filter(Boolean);
}

export function safeStringify(value: unknown): string {
  try {
    return JSON.stringify(value, null, 2);
  } catch {
    return String(value);
  }
}
