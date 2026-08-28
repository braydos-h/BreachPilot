import {
  MutationCache,
  QueryCache,
  QueryClient,
} from "@tanstack/react-query";
import { ApiError, expireSession } from "@/api/client";

/** Global 401 funnel: any query or mutation rejected with 401 means the
 *  session token is dead, so expireSession() clears it, fires the
 *  AUTH_EXPIRED_EVENT (TokenGate listens and re-renders the gate), toasts,
 *  and drops cached data so a re-auth starts clean. A query opts out with
 *  meta.onErrorAuthClear === false; mutations carry no meta and always fire.
 *  Retries already refuse 4xx, so this fires at most once per endpoint. */
function isAuthRejection(error: unknown, meta: unknown): boolean {
  if (!(error instanceof ApiError) || !error.isAuth) return false;
  const opts = (meta ?? {}) as { onErrorAuthClear?: boolean };
  return opts.onErrorAuthClear !== false;
}

function onAuthRejection(error: unknown, meta: unknown): void {
  if (!isAuthRejection(error, meta)) return;
  expireSession("Your session token was rejected by the API.");
  // removeQueries (not clear) — it drops cached data + subscriptions without
  // touching the mutation cache or resetting the cache instance itself.
  queryClient.removeQueries();
}

export const queryClient = new QueryClient({
  queryCache: new QueryCache({
    onError: (error, query) => onAuthRejection(error, query.meta),
  }),
  mutationCache: new MutationCache({
    onError: (error) => onAuthRejection(error, undefined),
  }),
  defaultOptions: {
    queries: {
      retry: (failureCount, error) => {
        if (error && typeof error === "object" && "status" in error) {
          const status = (error as { status: number }).status;
          if (status >= 400 && status < 500 && status !== 408 && status !== 429) return false;
        }
        return failureCount < 2;
      },
      refetchOnWindowFocus: false,
    },
  },
});