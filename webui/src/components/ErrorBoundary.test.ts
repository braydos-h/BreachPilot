import { describe, expect, it } from "vitest";
import { ErrorBoundary } from "@/components/ErrorBoundary";

describe("ErrorBoundary", () => {
  it("getDerivedStateFromError captures the error for the fallback UI", () => {
    const err = new Error("boom");
    expect(ErrorBoundary.getDerivedStateFromError(err)).toEqual({ error: err });
  });

  it("starts with no error", () => {
    // Instantiate without rendering; state is initialized in the field.
    const boundary = new ErrorBoundary({ children: null });
    expect(boundary.state.error).toBeNull();
  });
});
