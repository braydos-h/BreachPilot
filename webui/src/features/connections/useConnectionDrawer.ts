import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { ApiError } from "@/api/client";
import {
  useCheckConnection,
  useConnection,
  useConnectionListener,
  useRemoveConnection,
} from "@/api/hooks";
import { useToast } from "@/hooks/use-toast";

/** Details-drawer state: connection + listener queries, check/remove, autoscroll. */
export function useConnectionDrawer(
  connectionId: string,
  open: boolean,
  opts?: { onRemoveSuccess?: () => void },
) {
  const { toast } = useToast();
  const connQuery = useConnection(open ? connectionId : null, open);
  const listenerEnabled = open && connQuery.data?.status !== "removed";
  const listenerQuery = useConnectionListener(open ? connectionId : null, listenerEnabled);
  const checkMutation = useCheckConnection();
  const removeMutation = useRemoveConnection();
  const [showRemoveDialog, setShowRemoveDialog] = useState(false);
  const [listenerAutoScroll, setListenerAutoScroll] = useState(true);
  const outputRef = useRef<HTMLPreElement>(null);
  const conn = connQuery.data;

  useEffect(() => {
    if (!listenerAutoScroll) return;
    const el = outputRef.current;
    if (!el) return;
    el.scrollTop = el.scrollHeight;
  }, [listenerQuery.data?.output, listenerAutoScroll]);

  const handleScroll = useCallback(() => {
    const el = outputRef.current;
    if (!el) return;
    const nearBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 40;
    setListenerAutoScroll(nearBottom);
  }, []);

  const onCheck = () => {
    if (checkMutation.isPending) return;
    checkMutation.mutate(connectionId, {
      onSuccess: () => {
        toast({ title: "Health check complete", description: "Connection status updated." });
      },
      onError: (err) => {
        toast({
          title: "Health check failed",
          description: err instanceof ApiError ? err.message : "Could not check connection.",
          variant: "destructive" as unknown as string,
        } as unknown as Parameters<typeof toast>[0]);
      },
    });
  };

  const onRemove = () => {
    if (removeMutation.isPending) return;
    removeMutation.mutate(connectionId, {
      onSuccess: () => {
        toast({ title: "Connection removed", description: `${conn?.target_ip ?? connectionId} marked as removed.` });
        setShowRemoveDialog(false);
        opts?.onRemoveSuccess?.();
      },
      onError: (err) => {
        toast({
          title: "Removal failed",
          description: err instanceof ApiError ? err.message : "Could not remove connection.",
          variant: "destructive" as unknown as string,
        } as unknown as Parameters<typeof toast>[0]);
      },
    });
  };

  const guidance = useMemo(() => {
    if (!conn) return null;
    if (conn.status === "active") {
      const diff = conn.last_beacon ? Date.now() / 1000 - conn.last_beacon : Infinity;
      if (diff < 120) return { text: "Healthy — recent beacon. No action needed.", tone: "emerald" as const };
      if (diff < 3600) return { text: "Beacon recent but not immediate. Monitor or Check if needed.", tone: "muted" as const };
      return { text: "No recent beacon despite active status — consider running Check.", tone: "amber" as const };
    }
    if (conn.status === "stale")
      return { text: "Degraded — no recent beacon. Run Check to verify, then Remove if decommissioned.", tone: "amber" as const };
    if (conn.status === "error")
      return { text: "Failing — last health check reported an error. Verify listener and run Check again.", tone: "red" as const };
    if (conn.status === "removed")
      return { text: "Disabled — this record is retained for audit but no longer active. Listener cleanup was attempted.", tone: "muted" as const };
    return null;
  }, [conn]);

  return {
    connQuery,
    listenerQuery,
    checkMutation,
    removeMutation,
    showRemoveDialog,
    setShowRemoveDialog,
    listenerAutoScroll,
    setListenerAutoScroll,
    outputRef,
    conn,
    guidance,
    onCheck,
    onRemove,
    handleScroll,
  };
}

export type ConnectionDrawerState = ReturnType<typeof useConnectionDrawer>;
