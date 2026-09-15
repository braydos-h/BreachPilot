// Shared error -> direct-fix map (todo 35).
// Every error surface (preflight, readiness, self-test, banners) must render
// the primary fix action from here instead of inventing per-page strings.

export interface ErrorFix {
  title: string;
  detail: string;
  actionLabel: string;
  to: string;
}

export const ERROR_FIX_MAP: Record<string, ErrorFix> = {
  provider_offline: {
    title: "Provider offline",
    detail: "The configured model provider is unreachable. Runs cannot start until it is back.",
    actionLabel: "Open provider settings",
    to: "/system",
  },
  model_unavailable: {
    title: "Model unavailable",
    detail: "The selected model is not available from the provider.",
    actionLabel: "Choose a fallback model",
    to: "/system",
  },
  sandbox_unavailable: {
    title: "Sandbox unavailable",
    detail: "The disposable worker container is not ready. Attack execution stays blocked until fixed.",
    actionLabel: "Open fix workflow",
    to: "/system",
  },
  scope_failure: {
    title: "Target out of scope",
    detail: "This target is not covered by the allowlist lock.",
    actionLabel: "Edit target or scope",
    to: "/runs/new",
  },
  selftest_failed: {
    title: "Self-test failed",
    detail: "The safe localhost smoke test did not pass.",
    actionLabel: "Open diagnostics",
    to: "/system",
  },
  connection_lost: {
    title: "Live updates disconnected",
    detail: "The run continues on the server. Reconnect to resume live updates.",
    actionLabel: "Back to runs",
    to: "/runs",
  },
};

export function errorFixFor(key: string): ErrorFix {
  return (
    ERROR_FIX_MAP[key] ?? {
      title: "Something needs attention",
      detail: "Follow the linked fix to resolve this.",
      actionLabel: "Open settings",
      to: "/system",
    }
  );
}
