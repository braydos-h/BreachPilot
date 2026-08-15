import { spawnSync } from "node:child_process";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { gzipSync } from "node:zlib";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const assetsDir = join(root, "dist", "assets");

// Build via the local vite binary (no npx, no network, cross-platform).
const viteBin = join(root, "node_modules", "vite", "bin", "vite.js");
const build = spawnSync(process.execPath, [viteBin, "build"], {
  cwd: root,
  stdio: "inherit",
});
if (build.status !== 0) {
  process.exit(build.status ?? 1);
}

let files;
try {
  files = readdirSync(assetsDir).filter((f) => /\.(js|css)$/.test(f));
} catch {
  console.error("bundle-report: no dist/assets directory after build");
  process.exit(1);
}

const rows = files
  .map((f) => {
    const p = join(assetsDir, f);
    const raw = statSync(p).size;
    const gz = gzipSync(readFileSync(p)).length;
    return { file: f, raw, gz };
  })
  .sort((a, b) => b.raw - a.raw);

const fmt = (n) => `${(n / 1024).toFixed(1)} KiB`;
const nameW = Math.max(...rows.map((r) => r.file.length), 4);
const rawW = Math.max(...rows.map((r) => fmt(r.raw).length), 3);
const gzW = Math.max(...rows.map((r) => fmt(r.gz).length), 4);

console.log("\nBundle sizes (dist/assets):\n");
console.log(`${"file".padEnd(nameW)}  ${"raw".padStart(rawW)}  ${"gzip".padStart(gzW)}`);
for (const r of rows) {
  console.log(`${r.file.padEnd(nameW)}  ${fmt(r.raw).padStart(rawW)}  ${fmt(r.gz).padStart(gzW)}`);
}
const totalRaw = rows.reduce((s, r) => s + r.raw, 0);
const totalGz = rows.reduce((s, r) => s + r.gz, 0);
console.log(`${"TOTAL".padEnd(nameW)}  ${fmt(totalRaw).padStart(rawW)}  ${fmt(totalGz).padStart(gzW)}`);
