import { useMemo } from "react";
import { cn } from "@/lib/utils";
import { CopyButton } from "@/components/CopyButton";
import { Spinner } from "@/components/Loading";
import { renderByExtension } from "@/components/ArtifactViewer";
import { useFetchWorkspaceFile } from "@/api/hooks";
import { useBlobText } from "@/lib/useBlobText";

interface WorkspaceViewerProps {
  runId: string;
  path: string;
  className?: string;
}

/** Renders a single file under the run's exploit_workspace/ (reuses ArtifactViewer's renderer). */
export function WorkspaceViewer({ runId, path, className }: WorkspaceViewerProps) {
  const fetchBlob = useFetchWorkspaceFile(runId);

  const ext = useMemo(() => {
    const match = path.match(/\.([a-z0-9]+)$/i);
    return match ? match[1].toLowerCase() : "";
  }, [path]);

  const { blob, text, error, isLoading, objectUrl } = useBlobText(fetchBlob, path, ext, "Failed to load file.");

  return (
    <div className={cn("flex flex-col gap-2", className)}>
      <div className="flex items-center justify-between gap-2">
        <span className="truncate font-mono text-xs text-muted-foreground">{path}</span>
        {text && <CopyButton value={text} label="Copy" size="sm" />}
      </div>
      {isLoading && <Spinner label="Loading file..." />}
      {error && <div className="rounded border border-destructive/40 bg-destructive/10 p-2 text-sm text-red-200">{error}</div>}
      {blob && !isLoading && !error && (
        <div className="overflow-auto rounded-md border bg-background/40 scrollbar-thin">
          {renderByExtension(ext, blob, text, objectUrl, path)}
        </div>
      )}
    </div>
  );
}
