import { FileText } from "lucide-react";
import { cn } from "@/lib/utils";
import { Textarea } from "@/components/ui/textarea";
import { SKILL_TEMPLATE } from "./skillsConfig";
import { SkillMarkdown } from "./SkillMarkdown";

export function SkillDraftEditor({
  draftMarkdown,
  setDraftMarkdown,
  previewTab,
  setPreviewTab,
}: {
  draftMarkdown: string;
  setDraftMarkdown: (v: string) => void;
  previewTab: "write" | "preview";
  setPreviewTab: (v: "write" | "preview") => void;
}) {
  return (
    <div className="min-h-0 flex-1 overflow-hidden">
      <div className="flex items-center gap-1 border-b bg-muted/20 px-2 py-1 sm:hidden">
        <button
          type="button"
          onClick={() => setPreviewTab("write")}
          className={cn(
            "flex-1 rounded-md px-3 py-1.5 text-xs font-medium",
            previewTab === "write" ? "bg-background shadow-sm" : "text-muted-foreground",
          )}
        >
          Write
        </button>
        <button
          type="button"
          onClick={() => setPreviewTab("preview")}
          className={cn(
            "flex-1 rounded-md px-3 py-1.5 text-xs font-medium",
            previewTab === "preview" ? "bg-background shadow-sm" : "text-muted-foreground",
          )}
        >
          Preview
        </button>
      </div>

      <div className="grid h-full min-h-0 grid-cols-1 lg:grid-cols-2">
        <div className={cn("flex min-h-0 flex-col border-r", previewTab === "preview" ? "hidden lg:flex" : "flex")}>
          <div className="flex items-center justify-between border-b bg-muted/30 px-3 py-1.5">
            <span className="text-xs font-medium text-muted-foreground">SKILL.md</span>
            <span className="text-[11px] tabular-nums text-muted-foreground">{draftMarkdown.length} chars</span>
          </div>
          <Textarea
            value={draftMarkdown}
            onChange={(e) => setDraftMarkdown(e.target.value)}
            placeholder={SKILL_TEMPLATE}
            className="min-h-[320px] flex-1 resize-none rounded-none border-0 font-mono text-xs leading-relaxed focus-visible:ring-0 focus-visible:ring-offset-0 lg:min-h-0"
            spellCheck={false}
          />
        </div>
        <div className={cn("min-h-0 overflow-auto bg-card p-4 scrollbar-thin", previewTab === "write" ? "hidden lg:block" : "block")}>
          <div className="mb-3 flex items-center gap-2 text-xs font-medium text-muted-foreground">
            <FileText className="h-3.5 w-3.5" /> Preview
          </div>
          {draftMarkdown.trim() ? (
            <div className="rounded-lg border bg-muted/20 p-4">
              <SkillMarkdown>{draftMarkdown}</SkillMarkdown>
            </div>
          ) : (
            <div className="rounded-lg border border-dashed p-6 text-center text-sm text-muted-foreground">
              Start writing to see a live preview here. The preview uses the same renderer as the detail view.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
