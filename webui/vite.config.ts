import { defineConfig, loadEnv } from "vite";
import react from "@vitejs/plugin-react";
import path from "node:path";
import { readFileSync } from "node:fs";

const DEFAULT_API = "http://127.0.0.1:8765";
const pkg = JSON.parse(readFileSync(path.resolve(__dirname, "package.json"), "utf8"));

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), "VITE_");
  const target = env.VITE_API_URL || DEFAULT_API;
  return {
    define: {
      __APP_VERSION__: JSON.stringify(pkg.version),
    },
    plugins: [react()],
    resolve: {
      alias: { "@": path.resolve(__dirname, "src") },
    },
    server: {
      port: 5173,
      strictPort: true,
      proxy: {
        "/api": {
          target,
          changeOrigin: true,
          ws: true,
          secure: false,
        },
      },
    },
    preview: {
      port: 5173,
      strictPort: true,
      proxy: {
        "/api": {
          target,
          changeOrigin: true,
          ws: true,
          secure: false,
        },
      },
    },
    build: {
      outDir: "dist",
      sourcemap: false,
      target: "es2020",
    },
  };
});