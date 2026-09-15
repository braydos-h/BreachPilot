import { defineConfig } from "vitest/config";
import path from "node:path";
import { readFileSync } from "node:fs";
import react from "@vitejs/plugin-react";

const pkg = JSON.parse(readFileSync(path.resolve(__dirname, "package.json"), "utf8"));

export default defineConfig({
  define: {
    __APP_VERSION__: JSON.stringify(pkg.version),
  },
  plugins: [react()],
  resolve: {
    alias: { "@": path.resolve(__dirname, "src") },
  },
  test: {
    environment: "node",
    // ponytail: tsx component tests get jsdom by glob; plain ts unit tests stay node.
    environmentMatchGlobs: [["src/**/*.test.tsx", "jsdom"]],
    include: ["src/**/*.test.{ts,tsx}"],
    setupFiles: [path.resolve(__dirname, "src/test/setup.ts")],
    testTimeout: 10000,
  },
});
