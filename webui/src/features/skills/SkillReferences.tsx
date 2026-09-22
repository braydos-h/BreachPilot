import { BookOpen, ExternalLink } from "lucide-react";
import type { SkillDetail } from "@/api/types";
import { Badge } from "@/components/ui/badge";
import { CopyButton } from "@/components/CopyButton";
import { isValidUrl } from "./skillsConfig";

export function SkillReferences({ detail }: { detail: SkillDetail }) {
  return (
    <div className="overflow-hidden rounded-xl border bg-card">
      <div className="flex items-center justify-between gap-2 border-b bg-muted/20 px-4 py-3">
        <div className="flex items-center gap-2">
          <BookOpen className="h-4 w-4 text-muted-foreground" />
          <span className="text-sm font-semibold">References</span>
          <Badge variant="secondary" className="h-5 px-1.5 text-[11px] tabular-nums">
            {detail.references.length}
          </Badge>
        </div>
        {detail.references.length > 0 && (
          <CopyButton value={detail.references.join("\n")} label="Copy all" size="sm" className="h-7 text-xs" />
        )}
      </div>
      {detail.references.length === 0 ? (
        <p className="p-4 text-sm text-muted-foreground">No references listed for this skill.</p>
      ) : (
        <ul className="divide-y">
          {detail.references.map((r) => (
            <li key={r} className="flex items-start gap-2.5 px-4 py-2.5">
              <span className="mt-1 h-1.5 w-1.5 shrink-0 rounded-full bg-muted-foreground/40" aria-hidden />
              {isValidUrl(r) ? (
                <a
                  href={r}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex min-w-0 items-center gap-1 break-all font-mono text-xs text-primary underline-offset-4 hover:underline"
                >
                  <span className="truncate">{r}</span>
                  <ExternalLink className="h-3 w-3 shrink-0" />
                </a>
              ) : (
                <span className="break-all font-mono text-xs text-muted-foreground">{r}</span>
              )}
              <CopyButton value={r} size="sm" className="ml-auto hidden h-6 shrink-0 px-2 text-[11px] sm:inline-flex" label="Copy" />
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
