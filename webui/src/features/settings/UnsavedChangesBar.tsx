// Sticky bottom action bar shown only while there are unsaved changes.
// Sticks to the viewport bottom without covering content (the page keeps
// bottom padding for it).

import { Loader2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { useSettingsDraft } from "./useSettingsDraft";

export function UnsavedChangesBar() {
  const { dirtyCount, isSaving, save, reset } = useSettingsDraft();
  if (dirtyCount === 0) return null;

  return (
    <div className="sticky bottom-0 z-20 -mx-4 border-t bg-background/90 px-4 py-3 backdrop-blur sm:-mx-6 sm:px-6">
      <div className="flex items-center justify-between gap-3">
        <span className="text-sm text-muted-foreground">
          {dirtyCount} unsaved {dirtyCount === 1 ? "change" : "changes"}
        </span>
        <div className="flex items-center gap-2">
          <Button type="button" variant="ghost" size="sm" onClick={reset} disabled={isSaving}>
            Discard
          </Button>
          <Button type="button" size="sm" onClick={save} disabled={isSaving}>
            {isSaving && <Loader2 className="h-3.5 w-3.5 animate-spin" />}
            Save changes
          </Button>
        </div>
      </div>
    </div>
  );
}
