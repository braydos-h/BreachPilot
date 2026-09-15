import { useSyncExternalStore } from "react";

// Dark-only by design (todo 48): BreachPilot ships a single dark operational
// theme. There is no toggle and no persistence — this module exists only so
// callers have a stable hook returning "dark".
type Theme = "dark";

const current: Theme = "dark";
const listeners = new Set<() => void>();

function applyClass() {
  document.documentElement.classList.add("dark");
}

function subscribe(listener: () => void): () => void {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

function getSnapshot(): Theme {
  return current;
}

function getServerSnapshot(): Theme {
  return "dark";
}

// Ensure dark class is present at module init.
applyClass();

export function setTheme(_theme: Theme) {
  // Dark-only: no-op by design. Keep API for backwards compat.
  applyClass();
  listeners.forEach((l) => l());
}

export function toggleTheme() {
  // Dark-only: no toggle UI exists; no-op by design.
}

export function useTheme() {
  const theme = useSyncExternalStore(subscribe, getSnapshot, getServerSnapshot);
  return { theme, toggle: toggleTheme };
}
