import { BookOpen, FileText, Hash, Layers, Tag } from "lucide-react";
import { cn } from "@/lib/utils";
import type { SkillDetail } from "@/api/types";
import { Badge } from "@/components/ui/badge";

export function SkillDetailMeta({ detail }: { detail: SkillDetail }) {
  const sectionEntries = Object.entries(detail.sections ?? {});
  return (
    <div className="grid gap-2 rounded-lg border bg-muted/20 p-3 sm:grid-cols-2 lg:grid-cols-3">
      <MetaCell label="Domain" value={detail.domain || "—"} icon={Layers} />
      <MetaCell label="Subdomain" value={detail.subdomain || "—"} icon={Hash} />
      <MetaCell label="Version" value={detail.version ? `v${detail.version}` : "—"} icon={Tag} mono />
      <div className="sm:col-span-2 lg:col-span-3">
        <div className="text-[11px] font-medium uppercase tracking-wide text-muted-foreground">Tags</div>
        {detail.tags.length > 0 ? (
          <div className="mt-1.5 flex flex-wrap gap-1">
            {detail.tags.map((t) => (
              <Badge key={t} variant="outline" className="text-[11px] font-normal">
                {t}
              </Badge>
            ))}
          </div>
        ) : (
          <span className="text-xs text-muted-foreground">No tags</span>
        )}
      </div>
      {(detail.nist_csf.length > 0 || detail.mitre_attack.length > 0) && (
        <div className="sm:col-span-2 lg:col-span-3 flex flex-wrap gap-2 pt-1">
          {detail.nist_csf.length > 0 && (
            <div className="flex flex-wrap items-center gap-1.5">
              <span className="text-[11px] font-medium uppercase tracking-wide text-muted-foreground">NIST CSF</span>
              <div className="flex flex-wrap gap-1">
                {detail.nist_csf.map((c) => (
                  <Badge
                    key={c}
                    variant="secondary"
                    className="border border-violet-500/20 bg-violet-500/10 px-1.5 py-0 text-[11px] font-mono text-violet-700 dark:text-violet-300"
                  >
                    {c}
                  </Badge>
                ))}
              </div>
            </div>
          )}
          {detail.mitre_attack.length > 0 && (
            <div className="flex flex-wrap items-center gap-1.5">
              <span className="text-[11px] font-medium uppercase tracking-wide text-muted-foreground">
                MITRE ATT&CK
              </span>
              <div className="flex flex-wrap gap-1">
                {detail.mitre_attack.map((c) => (
                  <Badge
                    key={c}
                    variant="secondary"
                    className="border border-amber-500/20 bg-amber-500/10 px-1.5 py-0 text-[11px] font-mono text-amber-700 dark:text-amber-300"
                  >
                    {c}
                  </Badge>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
      <div className="flex items-center gap-4 pt-1 text-xs text-muted-foreground sm:col-span-2 lg:col-span-3">
        <span className="inline-flex items-center gap-1">
          <FileText className="h-3 w-3" /> {detail.references.length} references
        </span>
        <span className="inline-flex items-center gap-1">
          <BookOpen className="h-3 w-3" /> {sectionEntries.length} sections
        </span>
        <span className="inline-flex items-center gap-1">
          <Tag className="h-3 w-3" /> {detail.tags.length} tags
        </span>
      </div>
    </div>
  );
}

function MetaCell({
  label,
  value,
  icon: Icon,
  mono,
}: {
  label: string;
  value: string;
  icon: typeof Layers;
  mono?: boolean;
}) {
  return (
    <div className="space-y-1">
      <div className="flex items-center gap-1 text-[11px] font-medium uppercase tracking-wide text-muted-foreground">
        <Icon className="h-3 w-3" /> {label}
      </div>
      <div className={cn("truncate text-sm", mono ? "font-mono text-xs" : "font-medium")}>{value}</div>
    </div>
  );
}
