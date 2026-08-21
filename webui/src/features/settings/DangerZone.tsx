// Destructive reset, kept at the very bottom of Advanced. Requires typing
// RESET to confirm — never weakened.

import { useState } from "react";
import { Loader2, Trash2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { useResetSystem } from "@/api/hooks";
import { ApiError } from "@/api/client";

export function DangerZone() {
  const reset = useResetSystem();
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [confirmText, setConfirmText] = useState("");

  const onReset = () => {
    reset.mutate(undefined, {
      onSuccess: () => {
        setConfirmOpen(false);
        setConfirmText("");
      },
    });
  };

  return (
    <section className="overflow-hidden rounded-lg border border-destructive/40 bg-card/40">
      <header className="border-b border-destructive/20 px-4 py-3">
        <h2 className="text-sm font-semibold text-destructive">Danger zone</h2>
      </header>
      <div className="space-y-3 px-4 py-3">
        <p className="text-sm text-muted-foreground">
          Reset wipes all past work: run history, reports, exploit/research/swarm workspaces, and
          telemetry. This cannot be undone.
        </p>
        <Button size="sm" variant="destructive" onClick={() => setConfirmOpen(true)} disabled={reset.isPending}>
          {reset.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Trash2 className="h-4 w-4" />}
          Reset all data
        </Button>
        {reset.error && (
          <p className="text-xs text-destructive">
            {reset.error instanceof ApiError ? reset.error.message : "Reset failed."}
          </p>
        )}
        <Dialog open={confirmOpen} onOpenChange={setConfirmOpen}>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Reset all data?</DialogTitle>
              <DialogDescription>
                This permanently deletes every run, report, log, and workspace file. Type{" "}
                <span className="font-mono">RESET</span> to confirm.
              </DialogDescription>
            </DialogHeader>
            <Input
              value={confirmText}
              onChange={(e) => setConfirmText(e.target.value)}
              placeholder="RESET"
              autoComplete="off"
            />
            <DialogFooter>
              <Button size="sm" variant="outline" onClick={() => setConfirmOpen(false)}>
                Cancel
              </Button>
              <Button
                size="sm"
                variant="destructive"
                onClick={onReset}
                disabled={confirmText !== "RESET" || reset.isPending}
              >
                {reset.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Trash2 className="h-4 w-4" />}
                Delete everything
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </div>
    </section>
  );
}
