import { Loader2, Trash2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import type { SkillsPageState } from "./useSkillsPage";

export function DeleteSkillDialog({ page }: { page: SkillsPageState }) {
  const { confirmDelete, setConfirmDelete, remove, onDelete } = page;
  return (
    <Dialog open={confirmDelete !== null} onOpenChange={(open) => { if (!open) setConfirmDelete(null); }}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2 text-base">
            <span className="flex h-8 w-8 items-center justify-center rounded-full bg-destructive/10 text-destructive">
              <Trash2 className="h-4 w-4" />
            </span>
            Delete skill?
          </DialogTitle>
          <DialogDescription asChild>
            <div className="space-y-3 pt-1 text-left">
              <p className="text-sm leading-relaxed">
                Delete <span className="font-mono font-medium text-foreground">{confirmDelete}</span> from disk? This
                removes its directory and SKILL.md and cannot be undone.
              </p>
              <div className="rounded-md border border-amber-500/20 bg-amber-500/5 p-3 text-xs leading-relaxed text-amber-800 dark:text-amber-200">
                References in <span className="font-mono">default_enabled</span> and{" "}
                <span className="font-mono">exclude_names</span> will be cleaned up automatically.
              </div>
            </div>
          </DialogDescription>
        </DialogHeader>
        <DialogFooter className="gap-2 sm:gap-0">
          <Button variant="outline" onClick={() => setConfirmDelete(null)} disabled={remove.isPending}>
            Cancel
          </Button>
          <Button
            variant="destructive"
            disabled={remove.isPending}
            onClick={() => { if (confirmDelete) onDelete(confirmDelete); }}
            className="min-w-[96px]"
          >
            {remove.isPending ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Trash2 className="h-4 w-4" />}
            Delete
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
