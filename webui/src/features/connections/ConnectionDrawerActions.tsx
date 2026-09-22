import { Loader2, ShieldAlert, Trash2 } from "lucide-react";
import { ApiError } from "@/api/client";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { formatLastCheck } from "./connectionFormat";
import type { ConnectionDrawerState } from "./useConnectionDrawer";

export function ConnectionHealthCheck({ drawer }: { drawer: ConnectionDrawerState }) {
  const { conn, checkMutation, onCheck } = drawer;
  if (!conn) return null;
  return (
    <section className="space-y-2 rounded-lg border bg-card/40 p-3">
      <h3 className="text-xs font-semibold">Health Check</h3>
      <p className="text-xs leading-relaxed text-muted-foreground">
        Probes the listener process and updates status to <span className="font-medium">active</span> or{" "}
        <span className="font-medium">stale</span>. Uses the existing check endpoint — no new credentials are exposed.
      </p>
      <div className="flex flex-wrap items-center gap-2">
        <Button
          size="sm"
          variant="outline"
          onClick={onCheck}
          disabled={checkMutation.isPending || conn.status === "removed"}
          aria-label="Check connection"
          className="gap-1.5"
        >
          {checkMutation.isPending ? (
            <>
              <Loader2 className="h-3.5 w-3.5 animate-spin" />
              Checking...
            </>
          ) : (
            <>
              <ShieldAlert className="h-3.5 w-3.5" />
              Check connection
            </>
          )}
        </Button>
        {conn.last_check != null && conn.last_check !== 0 && (
          <span className="text-xs text-muted-foreground">Last checked {formatLastCheck(conn.last_check)}</span>
        )}
      </div>
      {checkMutation.isError && (
        <p className="text-xs text-destructive">
          {checkMutation.error instanceof ApiError ? checkMutation.error.message : "Health check failed."}
        </p>
      )}
    </section>
  );
}

export function ConnectionDangerZone({ drawer }: { drawer: ConnectionDrawerState }) {
  const { conn, removeMutation, setShowRemoveDialog } = drawer;
  if (!conn) return null;
  return (
    <section className="space-y-2 rounded-lg border border-destructive/20 bg-destructive/5 p-3">
      <h3 className="flex items-center gap-1.5 text-xs font-semibold text-destructive">
        <Trash2 className="h-3.5 w-3.5" />
        Danger Zone
      </h3>
      <p className="text-xs leading-relaxed text-muted-foreground">
        Mark this connection as removed and attempt to stop the associated listener. The record is retained for audit.
      </p>
      <Button
        size="sm"
        variant="destructive"
        onClick={() => setShowRemoveDialog(true)}
        disabled={removeMutation.isPending || conn.status === "removed"}
        aria-label="Remove connection"
        className="gap-1.5"
      >
        {removeMutation.isPending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Trash2 className="h-3.5 w-3.5" />}
        Remove connection
      </Button>
      {conn.status === "removed" && <p className="text-xs text-muted-foreground">This connection is already marked removed.</p>}
    </section>
  );
}

export function ConnectionRemoveDialog({ drawer }: { drawer: ConnectionDrawerState }) {
  const { conn, showRemoveDialog, setShowRemoveDialog, removeMutation, onRemove } = drawer;
  return (
    <Dialog open={showRemoveDialog} onOpenChange={setShowRemoveDialog}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2 text-destructive">
            <Trash2 className="h-4 w-4" />
            Remove connection?
          </DialogTitle>
          <DialogDescription className="text-left">
            This will mark the persisted record as removed and attempt listener cleanup via the existing manager. The
            record remains for audit and can be inspected afterwards.
          </DialogDescription>
        </DialogHeader>
        {conn && (
          <div className="space-y-1 rounded-md bg-muted/40 p-3 font-mono text-xs">
            <div>
              Target: <span className="font-medium">{conn.target_ip}</span>
            </div>
            <div className="truncate">Listener: {conn.listener_name || "—"}</div>
            <div className="truncate">ID: {conn.connection_id}</div>
          </div>
        )}
        <DialogFooter>
          <Button variant="outline" onClick={() => setShowRemoveDialog(false)} disabled={removeMutation.isPending}>
            Cancel
          </Button>
          <Button variant="destructive" onClick={onRemove} disabled={removeMutation.isPending} className="gap-1.5">
            {removeMutation.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : null}
            Remove
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
