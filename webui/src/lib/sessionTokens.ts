import { useEffect, useState } from "react";
import { useTelemetry } from "@/api/hooks";

export const SESSION_BASELINE_KEY = "breachpilot.telemetry.sessionBaseline.v1";

export function getStoredBaseline(): number | null {
  try {
    const raw = sessionStorage.getItem(SESSION_BASELINE_KEY);
    if (raw == null) return null;
    const n = Number(raw);
    return Number.isFinite(n) && n >= 0 ? n : null;
  } catch {
    return null;
  }
}

export function setStoredBaseline(value: number): void {
  try {
    sessionStorage.setItem(SESSION_BASELINE_KEY, String(Math.max(0, Math.floor(value))));
  } catch {
    // Ignore storage failures.
  }
}

export function clearStoredBaseline(): void {
  try {
    sessionStorage.removeItem(SESSION_BASELINE_KEY);
  } catch {
    // Ignore
  }
}

/**
 * Session-scoped token counter.
 * Baseline is the all-time total_tokens at the start of this browser tab session,
 * persisted in sessionStorage so navigation/refresh doesn't reset it.
 * Session usage = max(0, current_total - baseline).
 * If the backend telemetry is cleared and current_total drops below the stored
 * baseline, we re-baseline to avoid negatives.
 */
export function useSessionTokens(): {
  sessionTokens: number;
  totalTokens: number | null;
  baseline: number | null;
  isLoading: boolean;
  error: unknown;
} {
  const telemetry = useTelemetry();
  const totalRaw = telemetry.data?.summary?.total_tokens;
  const total = typeof totalRaw === "number" && Number.isFinite(totalRaw) ? Math.max(0, Math.floor(totalRaw)) : null;

  // Initialize from sessionStorage synchronously so a refresh reuses the same baseline
  // without waiting for an effect. This also covers the "browser refresh" requirement.
  const [baseline, setBaseline] = useState<number | null>(() => getStoredBaseline());

  useEffect(() => {
    if (total == null) return;
    // First successful telemetry load in this session -> capture baseline.
    if (baseline == null) {
      setStoredBaseline(total);
      setBaseline(total);
      return;
    }
    // Telemetry log cleared/reset -> current total dropped below baseline.
    // Re-baseline instead of showing a negative.
    if (total < baseline) {
      setStoredBaseline(total);
      setBaseline(total);
    }
  }, [total, baseline]);

  // Also watch for external sessionStorage changes and auth expiry (which clears the baseline).
  useEffect(() => {
    const onStorage = (e: StorageEvent) => {
      if (e.key === SESSION_BASELINE_KEY && e.storageArea === sessionStorage) {
        setBaseline(getStoredBaseline());
      }
    };
    const onAuthExpired = () => setBaseline(null);
    window.addEventListener("storage", onStorage);
    window.addEventListener("breachpilot:auth-expired", onAuthExpired as EventListener);
    return () => {
      window.removeEventListener("storage", onStorage);
      window.removeEventListener("breachpilot:auth-expired", onAuthExpired as EventListener);
    };
  }, []);

  const sessionTokens = baseline == null || total == null ? 0 : Math.max(0, total - baseline);

  return {
    sessionTokens,
    totalTokens: total,
    baseline,
    isLoading: telemetry.isLoading,
    error: telemetry.error,
  };
}
