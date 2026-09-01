import { useCallback, useState } from "react";
import { AlertTriangle, ExternalLink, X } from "lucide-react";
import { useHostPlatform } from "@/api/hooks";
import { Button } from "@/components/ui/button";

export const WINDOWS_WARNING_STORAGE_KEY = "breachpilot.windowsPerformanceWarning.dismissed";
export const WSL_DOCS_URL = "https://learn.microsoft.com/en-us/windows/wsl/install";

function isDismissedFromStorage(): boolean {
  try {
    return localStorage.getItem(WINDOWS_WARNING_STORAGE_KEY) === "true";
  } catch {
    return false;
  }
}

/**
 * Dismissible warning displayed only when the BreachPilot backend reports
 * native Windows. The OS is derived from the backend'\''s `platform.system()`
 * (never the browser UA) and normalized to `windows | linux | darwin | unknown`.
 * WSL2 reports Linux and therefore does not trigger the warning.
 */
export function WindowsPerformanceWarning() {
  const [dismissed, setDismissed] = useState<boolean>(() => isDismissedFromStorage());
  let data: ReturnType<typeof useHostPlatform>["data"] | undefined;
  let isError = false;
  try {
    const result = useHostPlatform();
    data = result.data;
    isError = Boolean(result.isError);
  } catch {
    // No QueryClient / hook error — silently omit warning, don'\''t break UI.
    return null;
  }

  const handleDismiss = useCallback(() => {
    try {
      localStorage.setItem(WINDOWS_WARNING_STORAGE_KEY, "true");
    } catch {
      // Ignore storage failures (private mode, etc.)
    }
    setDismissed(true);
  }, []);

  // Failure handling: silently omit on error, loading, unknown, or non-windows.
  if (dismissed) return null;
  if (isError) return null;
  if (!data) return null;
  if (data.platform !== "windows") return null;

  return (
    <div
      role="region"
      aria-label="Windows performance warning"
      className="mx-4 mt-3 flex flex-col gap-3 rounded-lg border border-amber-500/40 bg-amber-500/10 px-4 py-3 shadow-sm sm:flex-row sm:items-start sm:justify-between sm:gap-4"
    >
      <div className="flex min-w-0 flex-1 gap-3">
        <AlertTriangle
          className="mt-0.5 h-5 w-5 shrink-0 text-amber-400"
          aria-hidden="true"
        />
        <div className="min-w-0 flex-1 space-y-1">
          <h2 className="text-sm font-semibold leading-tight text-amber-100">
            Running BreachPilot on Windows
          </h2>
          <p className="text-sm leading-relaxed text-amber-100/80">
            Native Windows environments may reduce BreachPilot performance and can cause compatibility
            issues with some security tools and workflows.
          </p>
          <p className="text-sm leading-relaxed text-amber-100/80">
            For the best performance and compatibility, we recommend running BreachPilot using{" "}
            <span className="font-semibold text-amber-100">WSL2</span> or a{" "}
            <span className="font-semibold text-amber-100">native Linux environment</span>.
          </p>
        </div>
      </div>

      <div className="flex shrink-0 flex-col gap-2 sm:flex-row sm:items-center sm:self-start">
        <Button
          variant="outline"
          size="sm"
          asChild
          className="w-full justify-center gap-1.5 border-amber-500/40 bg-amber-500/10 text-amber-100 hover:bg-amber-500/20 hover:text-amber-50 sm:w-auto"
        >
          <a href={WSL_DOCS_URL} target="_blank" rel="noopener noreferrer">
            <ExternalLink className="h-3.5 w-3.5" aria-hidden="true" />
            Learn about WSL2
          </a>
        </Button>
        <Button
          variant="ghost"
          size="sm"
          onClick={handleDismiss}
          aria-label="Dismiss Windows performance warning"
          className="w-full justify-center gap-1.5 text-amber-200 hover:bg-amber-500/20 hover:text-amber-50 sm:w-auto"
        >
          <X className="h-3.5 w-3.5" aria-hidden="true" />
          Dismiss
        </Button>
      </div>
    </div>
  );
}
