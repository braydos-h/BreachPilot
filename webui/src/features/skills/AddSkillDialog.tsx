import { Loader2, Plus } from "lucide-react";
import { cn } from "@/lib/utils";
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
import { SKILL_TEMPLATE } from "./skillsConfig";
import { SkillDraftEditor } from "./SkillDraftEditor";
import type { SkillsPageState } from "./useSkillsPage";

export function AddSkillDialog({ page }: { page: SkillsPageState }) {
  const {
    addOpen,
    setAddOpen,
    draftName,
    setDraftName,
    draftMarkdown,
    setDraftMarkdown,
    draftError,
    setDraftError,
    previewTab,
    setPreviewTab,
    install,
    onInstall,
  } = page;
  return (
    <Dialog
      open={addOpen}
      onOpenChange={(o) => {
        setAddOpen(o);
        if (!o) {
          setDraftError("");
          setPreviewTab("write");
        }
      }}
    >
      <DialogContent className="flex max-h-[92vh] max-w-5xl flex-col gap-0 overflow-hidden p-0 sm:rounded-xl">
        <DialogHeader className="shrink-0 border-b px-6 py-4 text-left">
          <DialogTitle className="flex items-center gap-2 text-base">
            <div className="flex h-7 w-7 items-center justify-center rounded-md bg-primary text-primary-foreground">
              <Plus className="h-4 w-4" />
            </div>
            Add skill
          </DialogTitle>
          <DialogDescription className="text-xs">
            Create a new skill directory with a SKILL.md file. The name becomes the directory name on disk.
          </DialogDescription>
        </DialogHeader>

        <div className="flex min-h-0 flex-1 flex-col">
          <div className="shrink-0 space-y-3 border-b bg-muted/20 px-6 py-4">
            <div className="flex flex-col gap-3 sm:flex-row sm:items-end sm:gap-4">
              <div className="flex-1 space-y-1.5">
                <Label htmlFor="skill-name" className="text-xs font-medium">
                  Skill name
                </Label>
                <Input
                  id="skill-name"
                  value={draftName}
                  onChange={(e) => setDraftName(e.target.value)}
                  placeholder="my-skill-name"
                  className="h-9 font-mono text-sm"
                  spellCheck={false}
                  autoComplete="off"
                />
              </div>
              <div className="flex items-center gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  className="h-9 text-xs"
                  onClick={() => setDraftMarkdown((v) => (v.trim() ? v : SKILL_TEMPLATE))}
                >
                  Insert template
                </Button>
                <div className="hidden items-center gap-1 rounded-md border bg-background p-0.5 sm:flex" role="tablist" aria-label="Editor mode">
                  <button
                    type="button"
                    role="tab"
                    aria-selected={previewTab === "write"}
                    onClick={() => setPreviewTab("write")}
                    className={cn(
                      "rounded-sm px-3 py-1 text-xs font-medium transition-colors",
                      previewTab === "write"
                        ? "bg-primary text-primary-foreground shadow-sm"
                        : "text-muted-foreground hover:text-foreground",
                    )}
                  >
                    Write
                  </button>
                  <button
                    type="button"
                    role="tab"
                    aria-selected={previewTab === "preview"}
                    onClick={() => setPreviewTab("preview")}
                    className={cn(
                      "rounded-sm px-3 py-1 text-xs font-medium transition-colors",
                      previewTab === "preview"
                        ? "bg-primary text-primary-foreground shadow-sm"
                        : "text-muted-foreground hover:text-foreground",
                    )}
                  >
                    Preview
                  </button>
                </div>
              </div>
            </div>
            <p className="text-xs text-muted-foreground">
              2–64 characters · lowercase letters, digits, hyphens · must start with a letter or digit
            </p>
            {draftError && (
              <p className="rounded-md border border-destructive/30 bg-destructive/10 px-3 py-2 text-xs text-destructive">
                {draftError}
              </p>
            )}
          </div>

          <SkillDraftEditor
            draftMarkdown={draftMarkdown}
            setDraftMarkdown={setDraftMarkdown}
            previewTab={previewTab}
            setPreviewTab={setPreviewTab}
          />
        </div>

        <DialogFooter className="shrink-0 border-t bg-muted/20 px-6 py-3">
          <Button variant="ghost" onClick={() => setAddOpen(false)} disabled={install.isPending}>
            Cancel
          </Button>
          <Button onClick={onInstall} disabled={install.isPending} className="min-w-[96px]">
            {install.isPending ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : null}
            Install
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
