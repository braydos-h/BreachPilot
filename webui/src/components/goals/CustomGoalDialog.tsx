import { useEffect, useState } from "react";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import type { CustomGoal } from "@/api/types";
import { Loader2 } from "lucide-react";

interface CustomGoalDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  initial?: CustomGoal | null;
  onSubmit: (data: { name: string; objective: string }) => void;
  isPending?: boolean;
  serverError?: string;
}

export function CustomGoalDialog({
  open,
  onOpenChange,
  initial,
  onSubmit,
  isPending,
  serverError,
}: CustomGoalDialogProps) {
  const isEdit = !!initial;
  const [name, setName] = useState("");
  const [objective, setObjective] = useState("");
  const [fieldError, setFieldError] = useState("");

  useEffect(() => {
    if (open) {
      setName(initial?.name ?? "");
      setObjective(initial?.objective ?? "");
      setFieldError("");
    }
  }, [open, initial]);

  const handleSubmit = () => {
    const n = name.trim();
    const o = objective.trim();
    if (!n) {
      setFieldError("Name is required.");
      return;
    }
    if (!o) {
      setFieldError("Objective is required.");
      return;
    }
    if (n.length > 100) {
      setFieldError("Name must be at most 100 characters.");
      return;
    }
    if (o.length > 2000) {
      setFieldError("Objective must be at most 2000 characters.");
      return;
    }
    setFieldError("");
    onSubmit({ name: n, objective: o });
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>{isEdit ? "Edit custom goal" : "Add custom goal"}</DialogTitle>
          <DialogDescription>
            {isEdit
              ? "Update the name and objective for this custom goal."
              : "Create a reusable custom goal. It will appear alongside built-in goals and can be used when starting a run."}
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4 py-1">
          <div className="space-y-1.5">
            <Label htmlFor="custom-goal-name" className="text-sm font-medium">
              Name
            </Label>
            <Input
              id="custom-goal-name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="Verify domain administrator access"
              className="h-9"
              disabled={!!isPending}
              maxLength={100}
            />
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="custom-goal-objective" className="text-sm font-medium">
              Objective
            </Label>
            <Textarea
              id="custom-goal-objective"
              value={objective}
              onChange={(e) => setObjective(e.target.value)}
              placeholder="Obtain and verify access to a domain administrator account on the authorized target environment."
              className="min-h-[7rem]"
              disabled={!!isPending}
              maxLength={2000}
            />
            <p className="text-xs text-muted-foreground">
              The agent will plan around this objective instead of a preset outcome.
            </p>
          </div>

          {(fieldError || serverError) && (
            <div
              className="rounded-md border border-destructive/30 bg-destructive/10 px-3 py-2 text-xs text-destructive"
              role="alert"
            >
              {fieldError || serverError}
            </div>
          )}
        </div>

        <DialogFooter>
          <Button type="button" variant="ghost" onClick={() => onOpenChange(false)} disabled={!!isPending}>
            Cancel
          </Button>
          <Button type="button" onClick={handleSubmit} disabled={!!isPending} className="min-w-[96px]">
            {isPending ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : null}
            {isEdit ? "Save" : "Create"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
