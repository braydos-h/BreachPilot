import { Badge } from "@/components/ui/badge";

export function DemoBadge({ className }: { className?: string }) {
  return (
    <Badge
      variant="outline"
      className={`border-indigo-500/25 bg-indigo-500/10 px-1.5 py-0 text-[9px] font-semibold uppercase tracking-wide text-indigo-300 ${className ?? ""}`}
      title="Synthetic demo session — no real target was contacted"
    >
      DEMO
    </Badge>
  );
}
