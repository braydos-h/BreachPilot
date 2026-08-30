import { useSyncExternalStore } from "react";

type Theme = "dark" | "light";

const STORAGE_KEY = "breachpilot.theme";

function readInitial(): Theme {
  try {
    const v = localStorage.getItem(STORAGE_KEY);
    if (v === "light" || v === "dark") return v;
  } catch {
    /* storage disabled — fall through to dark */
  }
  return "dark";
}

// Module-level store shared by every useTheme() consumer. Layout and the graph
// canvas both render theme-dependent colors; per-component state let them drift
// apart after a toggle (the canvas kept its own snapshot).
let current: Theme = readInitial();
const listeners = new Set<() => void>();

function applyClass(theme: Theme) {
  document.documentElement.classList.toggle("dark", theme === "dark");
}

function persist(theme: Theme) {
  try {
    localStorage.setItem(STORAGE_KEY, theme);
  } catch {
    /* ignore */
  }
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

// Apply the stored preference immediately at module init so the first paint
// already carries the right class (previously it only landed after mount).
applyClass(current);

export function setTheme(theme: Theme) {
  current = theme;
  persist(theme);
  applyClass(theme);
  listeners.forEach((l) => l());
}

export function toggleTheme() {
  setTheme(current === "dark" ? "light" : "dark");
}

export function useTheme() {
  const theme = useSyncExternalStore(subscribe, getSnapshot, getServerSnapshot);
  return { theme, toggle: toggleTheme };
}