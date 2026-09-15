import { useCallback } from "react";
import { useSearchParams } from "react-router-dom";

/** Persist filters + selected tab in query params (todo 45). Clean URLs when default. */
export function useUrlState<T extends string>(key: string, defaultValue: T): [T, (v: T) => void] {
  const [params, setParams] = useSearchParams();
  const value = (params.get(key) as T | null) ?? defaultValue;
  const set = useCallback(
    (v: T) => {
      setParams(
        (prev) => {
          const next = new URLSearchParams(prev);
          if (v === defaultValue || v === "" || v === (null as unknown as T)) next.delete(key);
          else next.set(key, v);
          return next;
        },
        { replace: true },
      );
    },
    [key, defaultValue, setParams],
  );
  return [value, set];
}
