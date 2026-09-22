import { useEffect, useState } from "react";
import { ShieldAlert } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";

export const NOTICE_KEY = "breachpilot.fullNotice.shown.v1";
export const NOTICE_DISMISSED_KEY = "breachpilot.fullNotice.dismissed.v1";

export function FullAccessNotice() {
  const [open, setOpen] = useState(false);

  useEffect(() => {
    try {
      if (localStorage.getItem(NOTICE_DISMISSED_KEY) === "1") return;
      if (sessionStorage.getItem(NOTICE_KEY) === "1") return;
      sessionStorage.setItem(NOTICE_KEY, "1");
      setOpen(true);
    } catch {
      // ignore
    }
  }, []);

  const handleGotIt = () => {
    setOpen(false);
  };

  const handleDontShowAgain = () => {
    try {
      localStorage.setItem(NOTICE_DISMISSED_KEY, "1");
    } catch {
      // ignore
    }
    setOpen(false);
  };

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2 text-lg">
            <ShieldAlert className="h-5 w-5 text-red-400" />
            Read-only by default
          </DialogTitle>
          <DialogDescription className="text-sm">
            The console defaults to <span className="text-yellow-300 font-medium">Read-only</span>. Every operator
            decision waits for you to answer it. Use the sidebar toggle to switch to Approve (auto-answers
            non-destructive decisions only).
          </DialogDescription>
        </DialogHeader>
        <div className="flex items-center justify-end gap-2 pt-1">
          <Button type="button" variant="ghost" size="sm" onClick={handleDontShowAgain}>
            Don&apos;t show again
          </Button>
          <Button type="button" size="sm" onClick={handleGotIt}>
            Got it
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}
