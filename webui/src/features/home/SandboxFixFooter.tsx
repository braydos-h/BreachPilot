import { Loader2 } from "lucide-react";
import { Button } from "@/components/ui/button";

export function SandboxFixFooter({
  mode,
  onClose,
  onStart,
  onRetry,
  startDisabled,
  starting,
}: {
  mode: "plan" | "fixing" | "success" | "failed";
  onClose: () => void;
  onStart: () => void;
  onRetry: () => void;
  startDisabled: boolean;
  starting: boolean;
}) {
  return (
    <div className="flex justify-end gap-2 border-t pt-4 mt-2">
      {mode === "plan" && (
        <>
          <Button variant="outline" size="sm" onClick={onClose}>
            Cancel
          </Button>
          <Button size="sm" onClick={onStart} disabled={startDisabled} className="gap-1.5">
            {starting && <Loader2 className="h-4 w-4 animate-spin" />}
            Start fix
          </Button>
        </>
      )}
      {mode === "fixing" && (
        <Button variant="outline" size="sm" disabled>
          <Loader2 className="h-4 w-4 animate-spin" />
          Fixing…
        </Button>
      )}
      {mode === "success" && (
        <Button size="sm" variant="outline" onClick={onClose}>
          Close
        </Button>
      )}
      {mode === "failed" && (
        <>
          <Button variant="outline" size="sm" onClick={onClose}>
            Close
          </Button>
          <Button size="sm" onClick={onRetry}>
            Retry
          </Button>
        </>
      )}
    </div>
  );
}
