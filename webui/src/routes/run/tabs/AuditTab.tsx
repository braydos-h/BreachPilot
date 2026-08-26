import { cn } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";
import { AuditRecordsTable } from "@/components/AuditRecordsTable";
import { SkeletonRows } from "@/components/Loading";

interface AuditViewProps {
  loading: boolean;
  error: unknown;
  records: Array<Record<string, unknown>>;
  chainValid: boolean;
  chainReason: string;
}

export function AuditView({ loading, error, records, chainValid, chainReason }: AuditViewProps) {
  if (loading) return <SkeletonRows count={3} />;
  if (error) return <div className="text-sm text-destructive">Failed to load audit.</div>;
  return (
    <div className="space-y-3">
      <div
        className={cn(
          "rounded-md border p-3 text-sm",
          chainValid ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-200" : "border-destructive/40 bg-destructive/10 text-red-200",
        )}
      >
        <div className="flex items-center gap-2">
          <Badge variant={chainValid ? "success" : "danger"}>{chainValid ? "Chain valid" : "Chain invalid"}</Badge>
        </div>
        <div className="mt-1 text-xs">{chainReason}</div>
      </div>
      {records.length === 0 ? (
        <p className="text-sm text-muted-foreground">No audit records.</p>
      ) : (
        <AuditRecordsTable records={records} />
      )}
    </div>
  );
}
