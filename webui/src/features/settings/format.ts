// Human-friendly rendering of the last-save timestamp (not raw ISO).

export function formatSavedAt(iso: string | null): string {
  if (!iso) return "";
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return "";
  const diff = Date.now() - then;
  if (diff < 5000) return "Saved just now";
  if (diff < 60000) return `Saved ${Math.max(1, Math.round(diff / 1000))}s ago`;
  if (diff < 3600000) return `Saved ${Math.round(diff / 60000)}m ago`;
  return `Saved at ${new Date(iso).toLocaleTimeString([], { hour: "numeric", minute: "2-digit" })}`;
}
