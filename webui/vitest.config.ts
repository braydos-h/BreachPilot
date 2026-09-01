import { defineConfig } from "vitest/config";
import path from "node:path";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: { "@": path.resolve(__dirname, "src") },
  },
  test: {
    environment: "node",
    // Component tests opt into jsdom per-file with a `@vitest-environment jsdom`
    // docblock so the existing node-env unit tests keep running headless.
    include: ["src/**/*.test.{ts,tsx}"],
    setupFiles: [path.resolve(__dirname, "src/test/setup.ts")],
    testTimeout: 10000,
  },
});
