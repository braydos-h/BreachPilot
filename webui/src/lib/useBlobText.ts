import { useEffect, useState } from "react";
import { ApiError } from "@/api/client";
import { isTextExt } from "@/components/ArtifactViewer";

interface BlobFetcher {
  mutate: (path: string, opts: { onSuccess: (data: Blob) => void; onError: (err: unknown) => void }) => void;
  isPending: boolean;
}

interface UseBlobTextResult {
  blob: Blob | null;
  text: string;
  error: string;
  isLoading: boolean;
  objectUrl: string;
}

export function useBlobText(fetcher: BlobFetcher, path: string, ext: string, failMessage: string): UseBlobTextResult {
  const [blob, setBlob] = useState<Blob | null>(null);
  const [text, setText] = useState<string>("");
  const [error, setError] = useState<string>("");
  const [objectUrl, setObjectUrl] = useState("");

  useEffect(() => {
    let cancelled = false;
    setBlob(null);
    setText("");
    setError("");
    fetcher.mutate(path, {
      onSuccess: (data) => {
        if (cancelled) return;
        setBlob(data);
        if (isTextExt(ext) || data.type.startsWith("text/")) {
          data.text().then((t) => !cancelled && setText(t)).catch(() => !cancelled && setError("Could not decode text."));
        }
      },
      onError: (err) => {
        if (cancelled) return;
        setError(err instanceof ApiError ? err.message : failMessage);
      },
    });
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [path]);

  useEffect(() => {
    setObjectUrl("");
    if (!blob || !["png", "jpg", "jpeg", "gif", "webp", "svg"].includes(ext)) return;
    const url = URL.createObjectURL(blob);
    setObjectUrl(url);
    return () => URL.revokeObjectURL(url);
  }, [blob, ext]);

  const isLoading = fetcher.isPending && !blob && !error;

  return { blob, text, error, isLoading, objectUrl };
}
