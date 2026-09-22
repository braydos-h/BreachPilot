import { AlertTriangle, Archive, CheckCircle2, Clock3, Layers } from "lucide-react";
import type { ConnectionStatus } from "@/api/types";

export function humanizeMethod(raw: string): string {
  if (!raw) return "—";
  return raw
    .split("_")
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

export const STATUS_RANK: Record<ConnectionStatus, number> = {
  error: 0,
  stale: 1,
  active: 2,
  removed: 3,
};

export const STATUS_META: Record<
  ConnectionStatus,
  { label: string; variant: "success" | "warn" | "danger" | "muted"; Icon: typeof CheckCircle2; dot: string }
> = {
  active: { label: "ACTIVE", variant: "success", Icon: CheckCircle2, dot: "bg-emerald-500" },
  stale: { label: "STALE", variant: "warn", Icon: Clock3, dot: "bg-amber-500" },
  removed: { label: "REMOVED", variant: "muted", Icon: Archive, dot: "bg-zinc-400" },
  error: { label: "ERROR", variant: "danger", Icon: AlertTriangle, dot: "bg-red-500" },
};

export function formatBeacon(lastBeacon: number | null): string {
  if (lastBeacon == null || lastBeacon === 0) return "Never";
  const diff = Date.now() / 1000 - lastBeacon;
  if (diff < 0) return "just now";
  if (diff < 5) return "just now";
  if (diff < 60) return `${Math.round(diff)}s ago`;
  if (diff < 3600) return `${Math.round(diff / 60)}m ago`;
  if (diff < 86400) {
    const h = Math.floor(diff / 3600);
    const m = Math.round((diff % 3600) / 60);
    return m > 0 ? `${h}h ${m}m ago` : `${h}h ago`;
  }
  const d = Math.round(diff / 86400);
  return `${d}d ago`;
}

export function formatAge(createdAt: number): string {
  if (!createdAt) return "—";
  const diff = Date.now() / 1000 - createdAt;
  if (diff < 0) return "just now";
  if (diff < 60) return `${Math.round(diff)}s`;
  if (diff < 3600) {
    const m = Math.floor(diff / 60);
    return `${m}m`;
  }
  if (diff < 86400) {
    const h = Math.floor(diff / 3600);
    const m = Math.floor((diff % 3600) / 60);
    return m > 0 ? `${h}h ${m}m` : `${h}h`;
  }
  const d = Math.floor(diff / 86400);
  if (d < 30) return `${d}d`;
  const mo = Math.floor(d / 30);
  return `${mo}mo`;
}

export function formatLastCheck(lastCheck: number | null): string {
  if (lastCheck == null || lastCheck === 0) return "Never checked";
  const diff = Date.now() / 1000 - lastCheck;
  if (diff < 5) return "just now";
  if (diff < 60) return `${Math.round(diff)}s ago`;
  if (diff < 3600) return `${Math.round(diff / 60)}m ago`;
  return `${Math.round(diff / 3600)}h ago`;
}

export function formatIsoOrRelative(epoch: number | null, iso?: string): string {
  if (iso) {
    const d = new Date(iso);
    if (!Number.isNaN(d.getTime())) return d.toLocaleString();
  }
  if (epoch == null || epoch === 0) return "—";
  const d = new Date(epoch * 1000);
  return d.toLocaleString();
}

export function beaconDotClass(lastBeacon: number | null, status: ConnectionStatus): string {
  if (status === "removed") return "bg-zinc-400";
  if (status === "error") return "bg-red-500";
  if (lastBeacon == null || lastBeacon === 0) return "bg-zinc-400";
  const diff = Date.now() / 1000 - lastBeacon;
  if (diff < 90) return "bg-emerald-500";
  if (diff < 3600) return "bg-amber-500";
  return "bg-zinc-400";
}

export type FilterKey = "all" | ConnectionStatus;
export type SortKey = "status" | "target" | "created" | "beacon" | "method";
export type SortDir = "asc" | "desc";

export const FILTER_OPTIONS: { key: FilterKey; label: string; Icon: typeof Layers }[] = [
  { key: "all", label: "All", Icon: Layers },
  { key: "active", label: "Active", Icon: CheckCircle2 },
  { key: "stale", label: "Stale", Icon: Clock3 },
  { key: "removed", label: "Removed", Icon: Archive },
  { key: "error", label: "Error", Icon: AlertTriangle },
];
