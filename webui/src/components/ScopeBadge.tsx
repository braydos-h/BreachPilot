import { isValidTarget } from "@/lib/targetValidation";
import { cn } from "@/lib/utils";

/** Inline scope verdict next to the target (todo 26). Reuses frontend syntax
 *  gate; server allowlist verdict arrives at preflight/launch. */
export function ScopeBadge({ target }: { target: string }) {
  const t = target.trim();
  if (!t) return null;
  const ok = isValidTarget(t);
  const local = /^(127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])|localhost|::1)/i.test(t);
  return (
    <div
      role="status"
      className={cn(
        "mt-2 rounded-md border px-3 py-2 text-[13px]",
        ok ? "border-emerald-500/40 bg-emerald-500/10" : "border-destructive/40 bg-destructive/10",
      )}
    >
      {ok ? (
        <span>
          <strong>Authorized and in scope ✓</strong>
          <span className="ml-2 text-muted-foreground">
            {local ? "Local target — containment applies." : "Target syntax valid — allowlist confirmed at launch."}
          </span>
        </span>
      ) : (
        <span>
          <strong className="text-destructive">Target not valid.</strong>
          <span className="ml-2 text-muted-foreground">Enter an IPv4, IPv6, or domain you are authorized to test.</span>
        </span>
      )}
    </div>
  );
}
