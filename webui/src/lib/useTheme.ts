import { useSyncExternalStore } from "react";

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
  // Dark-only: no-op. Keep API for backwards compat.
  applyClass();
  listeners.forEach((l) => l());
}

export function toggleTheme() {
  // Dark-only: toggle is a no-op.
}

export function useTheme() {
  const theme = useSyncExternalStore(subscribe, getSnapshot, getServerSnapshot);
  return { theme, toggle: toggleTheme };
}
