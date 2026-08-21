// Vitest setup: jest-dom matchers for component tests. The node-env unit tests
// never import DOM matchers; this file only registers them for jsdom files.
import "@testing-library/jest-dom/vitest";
import { cleanup } from "@testing-library/react";
import { afterEach } from "vitest";

// RTL auto-cleanup only hooks the global afterEach, which vitest does not
// provide with `globals: false`. Without this, DOM from one jsdom test leaks
// into the next and "Found multiple elements" errors appear for any repeated
// text. Guarded so node-env tests (no document) no-op.
afterEach(() => {
  if (typeof document !== "undefined") cleanup();
});
