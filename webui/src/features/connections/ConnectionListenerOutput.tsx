import { Loader2, RefreshCw, Wifi } from "lucide-react";
import { cn } from "@/lib/utils";
import { ApiError } from "@/api/client";
import { Button } from "@/components/ui/button";
import { formatLastCheck } from "./connectionFormat";
import type { ConnectionDrawerState } from "./useConnectionDrawer";

export function ConnectionListenerOutput({ drawer }: { drawer: ConnectionDrawerState }) {
  const { conn, listenerQuery, listenerAutoScroll, setListenerAutoScroll, outputRef, handleScroll } = drawer;
  return (
    <section className="space-y-2">
      <div className="flex items-center justify-between gap-2">
        <h3 className="text-[11px] font-semibold uppercase tracking-wide text-muted-foreground">Listener Output</h3>
        <div className="flex items-center gap-1.5">
          {listenerQuery.isFetching && conn?.status === "active" && (
            <span className="inline-flex items-center gap-1 text-[10px] font-medium uppercase tracking-wide text-emerald-600 dark:text-emerald-300">
              <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-emerald-500" aria-hidden />
              Live
            </span>
          )}
          <Button
            size="sm"
            variant="ghost"
            className="h-7 px-2 text-xs"
            onClick={() => void listenerQuery.refetch()}
            disabled={listenerQuery.isFetching}
            aria-label="Refresh listener output"
          >
            <RefreshCw className={cn("h-3 w-3", listenerQuery.isFetching && "animate-spin")} />
            Refresh
          </Button>
        </div>
      </div>

      {listenerQuery.isLoading && (
        <div className="rounded-md border bg-muted/20 p-3" role="status" aria-label="Loading listener output">
          <div className="flex items-center gap-2 text-xs text-muted-foreground">
            <Loader2 className="h-3.5 w-3.5 animate-spin" />
            Loading listener output...
          </div>
        </div>
      )}

      {listenerQuery.error && (
        <div className="rounded-md border border-destructive/30 bg-destructive/5 p-3 text-xs text-destructive">
          {listenerQuery.error instanceof ApiError ? listenerQuery.error.message : "Failed to load listener output."}
          <Button size="sm" variant="outline" className="ml-2 h-6 text-xs" onClick={() => void listenerQuery.refetch()}>
            Retry
          </Button>
        </div>
      )}

      {!listenerQuery.isLoading && !listenerQuery.error && listenerQuery.data && (
        <>
          {listenerQuery.data.status === "not_found" || listenerQuery.data.output.startsWith("LOG_NOT_FOUND") ? (
            <div className="rounded-md border border-dashed p-4 text-center text-xs text-muted-foreground">
              <Wifi className="mx-auto h-5 w-5 opacity-50" aria-hidden />
              <p className="mt-1">Listener unavailable or stopped</p>
              <p className="mt-1 font-mono text-[10px]">{listenerQuery.data.listener_name}</p>
            </div>
          ) : (
            <pre
              ref={outputRef}
              onScroll={handleScroll}
              className="max-h-[260px] overflow-auto rounded-md border bg-zinc-950 p-3 font-mono text-xs leading-relaxed text-zinc-100 whitespace-pre-wrap break-words scrollbar-thin"
              style={{ overflowX: "auto", whiteSpace: "pre-wrap", wordBreak: "break-word" }}
              aria-label="Listener output"
            >
              {listenerQuery.data.output || "(no output yet)"}
            </pre>
          )}
          <div className="flex items-center justify-between text-[10px] text-muted-foreground">
            <span>
              {listenerQuery.data.running ? "Listener running" : "Listener stopped"} · updated{" "}
              {formatLastCheck(
                listenerQuery.data.updated_at ? Date.parse(listenerQuery.data.updated_at) / 1000 : null,
              )}
            </span>
            {!listenerAutoScroll && (
              <button type="button" className="underline-offset-4 hover:underline" onClick={() => setListenerAutoScroll(true)}>
                Resume autoscroll
              </button>
            )}
          </div>
        </>
      )}
    </section>
  );
}
