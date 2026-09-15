import { Link } from "react-router-dom";
import { CheckCircle2, OctagonAlert } from "lucide-react";
import { cn } from "@/lib/utils";

export interface PreflightCheck {
  id: string;
  label: string;
  ok: boolean | null;
  detail?: string;
  fixTo?: string;
  fixLabel?: string;
}

/** Review-step preflight card (todo 27): one obvious ready moment before Launch. */
export function PreflightCard({ checks, canLaunch }: { checks: PreflightCheck[]; canLaunch: boolean }) {
  return (
    <section aria-label="Preflight checks" className="rounded-lg border bg-card/40 p-4">
      <h3 className="text-sm font-semibold">Ready to launch</h3>
      <p className="mt-0.5 text-[13px] text-muted-foreground">
        {canLaunch ? "All checks pass. One obvious Launch below." : "Resolve the blocked checks, then launch."}
      </p>
      <ul className="mt-3 space-y-2">
        {checks.map((c) => (
          <li key={c.id} className="flex items-start gap-2 text-[13px]">
            {c.ok ? (
              <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-emerald-500" aria-label="pass" />
            ) : (
              <OctagonAlert className="mt-0.5 h-4 w-4 shrink-0 text-destructive" aria-label="blocked" />
            )}
            <span className="flex-1">
              <span className={cn("font-medium", c.ok ? "" : "text-destructive")}>{c.label}</span>
              {c.detail && <span className="ml-1.5 text-muted-foreground">{c.detail}</span>}
              {c.fixTo && !c.ok && (
                <Link to={c.fixTo} className="ml-2 font-medium text-primary underline-offset-4 hover:underline">
                  {c.fixLabel ?? "Fix"}
                </Link>
              )}
            </span>
          </li>
        ))}
      </ul>
    </section>
  );
}
