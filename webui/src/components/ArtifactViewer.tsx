import { useMemo } from "react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { cn } from "@/lib/utils";
import { CopyButton } from "@/components/CopyButton";
import { Spinner } from "@/components/Loading";
import { useFetchArtifactBlob } from "@/api/hooks";
import { useBlobText } from "@/lib/useBlobText";

interface ArtifactViewerProps {
  runId: string;
  name: string;
  className?: string;
}

export function ArtifactViewer({ runId, name, className }: ArtifactViewerProps) {
  const fetchBlob = useFetchArtifactBlob(runId);

  const ext = useMemo(() => {
    const match = name.match(/\.([a-z0-9]+)$/i);
    return match ? (match[1] ?? "").toLowerCase() : "";
  }, [name]);

  const { blob, text, error, isLoading, objectUrl } = useBlobText(fetchBlob, name, ext, "Failed to load artifact.");

  return (
    <div className={cn("flex flex-col gap-2", className)}>
      <div className="flex items-center justify-between gap-2">
        <span className="truncate font-mono text-xs text-muted-foreground">{name}</span>
        {text && <CopyButton value={text} label="Copy" size="sm" />}
      </div>
      {isLoading && <Spinner label="Loading artifact..." />}
      {error && <div className="rounded border border-destructive/40 bg-destructive/10 p-2 text-sm text-red-200">{error}</div>}
      {blob && !isLoading && !error && (
        <div className="overflow-auto rounded-md border bg-background/40 scrollbar-thin">
          {renderByExtension(ext, blob, text, objectUrl, name)}
        </div>
      )}
    </div>
  );
}

export function renderByExtension(ext: string, blob: Blob, text: string, objectUrl: string, name: string): React.ReactNode {
  if (ext === "md" && text) {
    return (
      <div className="prose prose-invert max-w-none p-4 text-sm prose-pre:rounded prose-pre:bg-muted prose-code:rounded prose-code:bg-muted prose-code:px-1 prose-code:py-0.5">
        <ReactMarkdown remarkPlugins={[remarkGfm]}>{text}</ReactMarkdown>
      </div>
    );
  }
  if (ext === "html" && blob) {
    return (
      <iframe
        title="artifact-html"
        sandbox=""
        srcDoc={text}
        className="h-[60vh] w-full bg-background"
      />
    );
  }
  if ((ext === "png" || ext === "jpg" || ext === "jpeg" || ext === "gif" || ext === "webp" || ext === "svg") && blob) {
    return objectUrl ? <img src={objectUrl} alt={name} className="max-h-[70vh] w-full object-contain" /> : null;
  }
  if (ext === "csv" && text) {
    return <CsvTable text={text} name={name} />;
  }
  if (isTextExt(ext) && text) {
    return (
      <pre className="max-h-[70vh] overflow-auto p-3 font-mono text-xs whitespace-pre-wrap break-words scrollbar-thin">
        {text}
      </pre>
    );
  }
  return (
    <pre className="p-3 font-mono text-xs text-muted-foreground">
      Binary artifact ({blob.type || "unknown"}). {blob.size} bytes.
    </pre>
  );
}

export function isTextExt(ext: string): boolean {
  return ["md", "txt", "log", "json", "jsonl", "csv", "html", "py", "sh", "ps1", "yaml", "yml", "toml"].includes(ext);
}

function CsvTable({ text, name }: { text: string; name: string }) {
  const rows = useMemo(() => parseCsv(text), [text]);
  if (!rows.length) return <pre className="p-3 font-mono text-xs">{text}</pre>;
  const headers = rows[0] ?? [];
  const body = rows.slice(1);
  return (
    <div className="max-h-[70vh] overflow-auto scrollbar-thin">
      <table className="w-full border-collapse text-xs">
        <caption className="sr-only">{name}</caption>
        <thead className="sticky top-0 bg-muted/60">
          <tr>
            {headers.map((h, i) => (
              <th key={i} scope="col" className="border-b p-2 text-left font-semibold">{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {body.map((row, i) => (
            <tr key={i} className="even:bg-muted/20">
              {headers.map((_, j) => (
                <td key={j} className="border-b p-2 align-top font-mono">{row[j] ?? ""}</td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function parseCsv(text: string): string[][] {
  const rows: string[][] = [];
  let row: string[] = [];
  let field = "";
  let inQuotes = false;
  for (let i = 0; i < text.length; i += 1) {
    const ch = text[i];
    if (inQuotes) {
      if (ch === '"') {
        if (text[i + 1] === '"') {
          field += '"';
          i += 1;
        } else {
          inQuotes = false;
        }
      } else {
        field += ch;
      }
      continue;
    }
    if (ch === '"') {
      inQuotes = true;
    } else if (ch === ",") {
      row.push(field);
      field = "";
    } else if (ch === "\n") {
      row.push(field);
      rows.push(row);
      row = [];
      field = "";
    } else if (ch !== "\r") {
      field += ch;
    }
  }
  if (field || row.length) {
    row.push(field);
    rows.push(row);
  }
  return rows;
}
