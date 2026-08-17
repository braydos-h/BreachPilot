import { useState } from "react";
import { CheckCircle2, Eye, EyeOff, Loader2 } from "lucide-react";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { SkeletonRows } from "@/components/Loading";
import { useConfirmCredential, useCredentials, useRevealCredential } from "@/api/hooks";
import { ApiError } from "@/api/client";
import type { CredentialRecord } from "@/api/types";

interface CredentialTableProps {
  runId: string;
  className?: string;
}

export function CredentialTable({ runId, className }: CredentialTableProps) {
  const credentials = useCredentials(runId);
  const reveal = useRevealCredential(runId);
  const confirm = useConfirmCredential(runId);
  const [revealed, setRevealed] = useState<Record<number, string>>({});
  const [pending, setPending] = useState<Record<number, boolean>>({});
  const [confirming, setConfirming] = useState<Record<number, boolean>>({});
  const [error, setError] = useState<Record<number, string>>({});
  const [recent, setRecent] = useState<Array<{ index: number; username: string; at: string }>>([]);

  const rows = credentials.data?.credentials ?? [];

  const onReveal = (index: number) => {
    if (revealed[index] !== undefined) {
      setRevealed((prev) => {
        const next = { ...prev };
        delete next[index];
        return next;
      });
      return;
    }
    setPending((p) => ({ ...p, [index]: true }));
    setError((p) => {
      const next = { ...p };
      delete next[index];
      return next;
    });
    reveal.mutate(index, {
      onSuccess: (data) => {
        setRevealed((p) => ({ ...p, [index]: data.password }));
        setRecent((r) => [
          { index, username: data.username, at: new Date().toISOString() },
          ...r,
        ].slice(0, 10));
      },
      onError: (err) => {
        const msg = err instanceof ApiError ? err.message : "Reveal failed.";
        setError((p) => ({ ...p, [index]: msg }));
      },
      onSettled: () => {
        setPending((p) => {
          const next = { ...p };
          delete next[index];
          return next;
        });
      },
    });
  };

  const onConfirm = (index: number) => {
    setConfirming((p) => ({ ...p, [index]: true }));
    setError((p) => {
      const next = { ...p };
      delete next[index];
      return next;
    });
    confirm.mutate(index, {
      onError: (err) => {
        const msg = err instanceof ApiError ? err.message : "Confirm failed.";
        setError((p) => ({ ...p, [index]: msg }));
      },
      onSettled: () => {
        setConfirming((p) => {
          const next = { ...p };
          delete next[index];
          return next;
        });
      },
    });
  };

  if (credentials.isLoading) {
    return <SkeletonRows count={3} className="p-2" />;
  }
  if (credentials.error) {
    return (
      <div className="text-sm text-destructive">
        {credentials.error instanceof ApiError ? credentials.error.message : "Failed to load credentials."}
      </div>
    );
  }
  if (rows.length === 0) {
    return (
      <div className="rounded-md border border-dashed p-4 text-sm text-muted-foreground">
        No credentials captured for this run. The API reads a different location than the MCP credential
        vault, so credentials stored through MCP tools may not appear here.
      </div>
    );
  }

  return (
    <div className={cn("space-y-3", className)}>
      <div className="overflow-x-auto rounded-md border">
        <table className="w-full border-collapse text-sm">
          <thead>
            <tr>
              <th>#</th>
              <th>Username</th>
              <th>Target</th>
              <th>Type</th>
              <th>Source</th>
              <th>Password</th>
              <th className="text-right">Action</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => (
              <CredentialRow
                key={row.index}
                row={row}
                revealed={revealed[row.index]}
                pending={!!pending[row.index]}
                confirming={!!confirming[row.index]}
                error={error[row.index]}
                onReveal={() => onReveal(row.index)}
                onConfirm={() => onConfirm(row.index)}
                onBlur={() => {
                  if (revealed[row.index] !== undefined) {
                    setRevealed((prev) => {
                      const next = { ...prev };
                      delete next[row.index];
                      return next;
                    });
                  }
                }}
              />
            ))}
          </tbody>
        </table>
      </div>
      {recent.length > 0 && (
        <div className="rounded-md border bg-card/40 p-3 text-xs">
          <div className="mb-1 text-muted-foreground">Recent reveals (in-memory only)</div>
          <ul className="space-y-0.5">
            {recent.map((r, i) => (
              <li key={i} className="font-mono">
                #{r.index} {r.username} — {r.at}
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

interface CredentialRowProps {
  row: CredentialRecord;
  revealed?: string;
  pending: boolean;
  confirming: boolean;
  error?: string;
  onReveal: () => void;
  onConfirm: () => void;
  onBlur: () => void;
}

function CredentialRow({ row, revealed, pending, confirming, error, onReveal, onConfirm, onBlur }: CredentialRowProps) {
  return (
    <tr>
      <td className="tabular-nums">{row.index}</td>
      <td className="font-mono">{row.username || "\u2014"}</td>
      <td className="font-mono">{row.target_host || "\u2014"}</td>
      <td>{row.credential_type || "\u2014"}</td>
      <td className="font-mono text-xs">{row.source_action || "\u2014"}</td>
      <td className="font-mono" onBlur={onBlur}>
        {revealed !== undefined ? (
          <span className="select-all text-foreground">{revealed}</span>
        ) : (
          <span className="text-muted-foreground">[REDACTED]</span>
        )}
      </td>
      <td className="text-right">
        <div className="inline-flex items-center gap-1">
          {row.confirmed ? (
            <span className="inline-flex items-center gap-1 text-xs text-emerald-400" title="Confirmed after validated reuse">
              <CheckCircle2 className="h-3.5 w-3.5" />
            </span>
          ) : (
            <Button
              type="button"
              variant="ghost"
              size="sm"
              className="gap-1 text-muted-foreground hover:text-foreground"
              onClick={onConfirm}
              disabled={confirming}
              aria-label="Confirm credential"
              title="Mark as confirmed after validated reuse"
            >
              {confirming ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <CheckCircle2 className="h-3.5 w-3.5" />}
            </Button>
          )}
          <Button
            type="button"
            variant="outline"
            size="sm"
            className="gap-1.5"
            onClick={onReveal}
            disabled={pending}
          >
            {pending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : revealed !== undefined ? <EyeOff className="h-3.5 w-3.5" /> : <Eye className="h-3.5 w-3.5" />}
            {revealed !== undefined ? "Hide" : "Reveal"}
          </Button>
        </div>
        {error && <div className="mt-1 text-xs text-destructive">{error}</div>}
      </td>
    </tr>
  );
}