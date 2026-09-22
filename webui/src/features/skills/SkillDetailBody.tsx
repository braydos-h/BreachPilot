import { useState } from "react";
import { ChevronDown, ChevronUp, FileText, Layers } from "lucide-react";
import type { SkillDetail } from "@/api/types";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { SkillMarkdown } from "./SkillMarkdown";

export function SkillDetailBody({ detail }: { detail: SkillDetail }) {
  const sectionEntries = Object.entries(detail.sections ?? {});
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});
  const allExpanded = sectionEntries.length > 0 && sectionEntries.every(([k]) => expanded[k]);

  const toggleAll = (v: boolean) => {
    const next: Record<string, boolean> = {};
    for (const [k] of sectionEntries) next[k] = v;
    setExpanded(next);
  };

  return (
    <Tabs defaultValue="body" className="w-full">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <TabsList className="h-8">
          <TabsTrigger value="body" className="gap-1.5 text-xs h-7">
            <FileText className="h-3.5 w-3.5" /> Body
          </TabsTrigger>
          {sectionEntries.length > 0 && (
            <TabsTrigger value="sections" className="gap-1.5 text-xs h-7">
              <Layers className="h-3.5 w-3.5" /> Sections
              <Badge variant="secondary" className="ml-1 h-4 px-1 text-[10px] tabular-nums">
                {sectionEntries.length}
              </Badge>
            </TabsTrigger>
          )}
        </TabsList>
        {sectionEntries.length > 0 && (
          <div className="flex items-center gap-1">
            <Button variant="ghost" size="sm" className="h-7 text-xs" onClick={() => toggleAll(true)} disabled={allExpanded}>
              Expand all
            </Button>
            <Button
              variant="ghost"
              size="sm"
              className="h-7 text-xs"
              onClick={() => toggleAll(false)}
              disabled={!sectionEntries.some(([k]) => expanded[k])}
            >
              Collapse all
            </Button>
          </div>
        )}
      </div>

      <TabsContent value="body" className="mt-4">
        <div className="rounded-xl border bg-card p-4 sm:p-6">
          <SkillMarkdown>{detail.body}</SkillMarkdown>
        </div>
      </TabsContent>

      {sectionEntries.length > 0 && (
        <TabsContent value="sections" className="mt-4 space-y-2">
          {sectionEntries.map(([title, content]) => {
            const isOpen = expanded[title] ?? false;
            return (
              <div key={title} className="overflow-hidden rounded-lg border bg-card">
                <button
                  type="button"
                  onClick={() => setExpanded((p) => ({ ...p, [title]: !p[title] }))}
                  className="flex w-full items-center justify-between gap-2 px-4 py-3 text-left transition-colors hover:bg-accent/40 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-inset"
                  aria-expanded={isOpen}
                >
                  <span className="text-sm font-semibold capitalize">{title.replace(/[-_]/g, " ")}</span>
                  <span className="flex items-center gap-2 text-xs text-muted-foreground">
                    <span className="hidden sm:inline">{content.length} chars</span>
                    {isOpen ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
                  </span>
                </button>
                {isOpen && (
                  <div className="border-t bg-muted/20 p-4 sm:p-6">
                    <SkillMarkdown>{content}</SkillMarkdown>
                  </div>
                )}
              </div>
            );
          })}
        </TabsContent>
      )}
    </Tabs>
  );
}
