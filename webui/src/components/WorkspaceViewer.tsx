import { useEffect, useMemo, useState } from "react";
import { cn } from "@/lib/utils";
import { CopyButton } from "@/components/CopyButton";
import { Spinner } from "@/components/Loading";
import { isTextExt, renderByExtension } from "@/components/ArtifactViewer";
import { useFetchWorkspaceFile } from "@/api/hooks";
import { ApiError } from "@/api/client";

interface WorkspaceViewerProps {
  runId: string;
  path: string;
  className?: string;
}

/** Renders a single file under the run's exploit_workspace/ (reuses ArtifactViewer's renderer). */
export function WorkspaceViewer({ runId, path, className }: WorkspaceViewerProps) {
  const fetchBlob = useFetchWorkspaceFile(runId);
  const [blob, setBlob] = useState<Blob | null>(null);
  const [text, setText] = useState<string>("");
  const [error, setError] = useState<string>("");
  const [objectUrl, setObjectUrl] = useState("");

  const ext = useMemo(() => {
    const match = path.match(/\.([a-z0-9]+)$/i);
    return match ? match[1].toLowerCase() : "";
  }, [path]);

  useEffect(() => {
    let cancelled = false;
    setBlob(null);
    setText("");
    setError("");
    fetchBlob.mutate(path, {
      onSuccess: (data) => {
        if (cancelled) return;
        setBlob(data);
        if (isTextExt(ext) || data.type.startsWith("text/")) {
          data.text().then((t) => !cancelled && setText(t)).catch(() => !cancelled && setError("Could not decode text."));
        }
      },
      onError: (err) => {
        if (cancelled) return;
        setError(err instanceof ApiError ? err.message : "Failed to load file.");
      },
    });
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [runId, path]);

  useEffect(() => {
    setObjectUrl("");
    if (!blob || !["png", "jpg", "jpeg", "gif", "webp", "svg"].includes(ext)) return;
    const url = URL.createObjectURL(blob);
    setObjectUrl(url);
    return () => URL.revokeObjectURL(url);
  }, [blob, ext]);

  const loading = fetchBlob.isPending && !blob && !error;

  return (
    <div className={cn("flex flex-col gap-2", className)}>
      <div className="flex items-center justify-between gap-2">
        <span className="truncate font-mono text-xs text-muted-foreground">{path}</span>
        {text && <CopyButton value={text} label="Copy" size="sm" />}
      </div>
      {loading && <Spinner label="Loading file..." />}
      {error && <div className="rounded border border-destructive/40 bg-destructive/10 p-2 text-sm text-red-200">{error}</div>}
      {blob && !loading && !error && (
        <div className="overflow-auto rounded-md border bg-background/40 scrollbar-thin">
          {renderByExtension(ext, blob, text, objectUrl)}
        </div>
      )}
    </div>
  );
}
