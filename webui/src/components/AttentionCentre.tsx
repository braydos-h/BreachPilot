import { Link } from "react-router-dom";
import { Bell } from "lucide-react";
import { useState } from "react";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { errorFixFor } from "@/lib/errorFixMap";

export interface AttentionItem {
  id: string;
  kind: "approval" | "completion" | "provider" | "connection" | "benchmark" | "other";
  title: string;
  detail?: string;
  to: string;
  fixKey?: string;
}

/** App-level notification / attention centre (todo 37). */
export function AttentionCentre({ items }: { items: AttentionItem[] }) {
  const [open, setOpen] = useState(false);
  const unread = items.length;
  return (
    <>
      <button
        type="button"
        onClick={() => setOpen(true)}
        aria-label={unread > 0 ? `${unread} items need attention` : "No items need attention"}
        className="relative inline-flex h-9 w-9 items-center justify-center rounded-md text-muted-foreground hover:bg-accent hover:text-foreground"
      >
        <Bell className="h-4 w-4" />
        {unread > 0 && (
          <span className="absolute -right-0.5 -top-0.5 flex h-4 min-w-4 items-center justify-center rounded-full bg-amber-500 px-1 text-xs font-bold text-black">
            {unread > 9 ? "9+" : unread}
          </span>
        )}
      </button>
      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle>Needs attention ({unread})</DialogTitle>
          </DialogHeader>
          <div className="space-y-2">
            {items.length === 0 && <p className="text-sm text-muted-foreground">All clear — nothing needs you right now.</p>}
            {items.map((it) => {
              const fix = it.fixKey ? errorFixFor(it.fixKey) : null;
              return (
                <div key={it.id} className="rounded-md border p-3">
                  <div className="text-sm font-medium">{it.title}</div>
                  {it.detail && <p className="mt-0.5 text-[13px] text-muted-foreground">{it.detail}</p>}
                  <div className="mt-2 flex gap-2">
                    <Link to={it.to} onClick={() => setOpen(false)} className="text-[13px] font-medium text-primary hover:underline">
                      Open
                    </Link>
                    {fix && (
                      <Link to={fix.to} onClick={() => setOpen(false)} className="text-[13px] text-muted-foreground hover:text-foreground hover:underline">
                        {fix.actionLabel}
                      </Link>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        </DialogContent>
      </Dialog>
    </>
  );
}
