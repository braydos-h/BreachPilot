---
title: Build System — Vite, TS, Tailwind, Vitest
sources:
  - webui/package.json
  - webui/vite.config.ts
  - webui/vitest.config.ts
  - webui/tsconfig.json
  - webui/tsconfig.app.json
  - webui/tsconfig.node.json
  - webui/tailwind.config.ts
  - webui/postcss.config.js
  - webui/index.html
  - webui/scripts/bundle-report.mjs
tests:
  - webui/src/test/setup.ts
  - webui/src/lib/campaignCheckpoint.test.ts
  - webui/src/lib/stateShape.test.ts
subsystem: webui
---

# Build System

## Scripts (`webui/package.json:6`)

Use Node 20.19+ on the 20.x line, 22.12+ on the 22.x line, or 24+ with the
locked dependencies for the full install/build/test workflow. Vite 6 and the
installer's current version check accept Node 18+, but the frontend lockfile
contains packages with newer engine ranges (including jsdom). CI uses Node 22.

| Script | Command | Purpose |
|--------|---------|---------|
| `dev` | `vite` | dev server `http://127.0.0.1:5173 strictPort` + `/api` proxy (`VITE_API_URL` or `DEFAULT_API http://127.0.0.1:8765`) |
| `build` | `tsc -b && vite build` | typecheck both project refs then bundle to `webui/dist/` (`outDir dist`, no sourcemap, target `es2020`) |
| `preview` | `vite preview --port 5173 --strictPort` | serves `dist` with same `/api` proxy as dev |
| `bundle-report` | `node scripts/bundle-report.mjs` | post-build chunk analysis (read `dist` files) |
| `test` | `vitest run` | `environment node` by default, per-file jsdom opt-in |

## Vite (`webui/vite.config.ts:1`)

```ts
DEFAULT_API = "http://127.0.0.1:8765"
pkg = JSON.parse(readFileSync(package.json))
define.__APP_VERSION__ = pkg.version // "0.68.4"
plugins:[react()], resolve.alias["@"]=src
server{port:5173, strictPort, proxy{"/api":{target, changeOrigin, ws:true, secure:false}}}
preview{same proxy}, build{outDir:"dist", sourcemap:false, target:"es2020"}
```

`target` env: `loadEnv(mode, cwd, "VITE_")` (`vite.config.ts:10`) → `VITE_API_URL` overrides `DEFAULT_API`. The `ws:true` flag proxies WebSocket upgrades for `useRunEvents`.

Production serving: `python main.py --web` from a source checkout builds `webui/dist/` if it is missing (`npm ci && npm run build`, requires Node+npm) and mounts it at `/` with SPA fallback in the `create_app` factory (`docs/api.md: api.serve_webui`). Release wheels install the CI-built SPA under the Python environment's data prefix (`webui/dist`); both the CLI bootstrap and `create_app` resolve that location through `tools.paths.get_webui_dist_dir()`, so normal `breachpilot --web` works from an installed wheel without Node.js or a repository checkout. `--rebuild` requires the source checkout and Node/npm.

## TypeScript (`webui/tsconfig.json`, `tsconfig.app.json`, `tsconfig.node.json`)

`tsconfig.json:1` is a references file: `{files:[], references:[./tsconfig.app.json, ./tsconfig.node.json]}` — `tsc -b` builds both.

| File | Key compilerOptions | Notes |
|------|----------------------|-------|
| `tsconfig.app.json:2` | `target ES2021`, `useDefineForClassFields`, `lib [ES2023, DOM, DOM.Iterable]`, `module ESNext`, `skipLibCheck`, `moduleResolution Bundler`, `allowImportingTsExtensions`, `isolatedModules`, `moduleDetection force`, `noEmit`, `jsx react-jsx`, `strict`, `noUnusedLocals/Parameters`, `noFallthroughCasesInSwitch`, `baseUrl .`, `paths {"@/*":["src/*"]}`, `include ["src"]` | strict tree used for bundle; `baseUrl/paths` mirrors vite alias |
| `tsconfig.node.json` | includes `vite.config.ts`; strict, no-emit ESNext/Bundler settings | node tooling only |

CI scoped checks: `ruff`/`mypy` scopes listed in `README §CI`; `tsc -b` is the only typed build gate for the SPA.

## Tailwind (`webui/tailwind.config.ts:1`)

| Field | Value |
|-------|-------|
| import | `type Config` + `typography(@tailwindcss/typography)`, `animate(tailwindcss-animate)` |
| `darkMode` | `["class"]` (`index.html:class="dark"` toggled by `lib/useTheme.ts` via `localStorage breachpilot.theme`) |
| `content` | `["./index.html","./src/**/*.{ts,tsx}"]` |
| `theme.container` | `center true, padding 1rem` |
| `theme.extend.typography.invert.css` | prose vars `prose-body/headings/links/code/pre-bg/pre-code/bullets/quotes/quote-borders → hsl(var(--*))` for `SkillMarkdown` in `SkillsPage.tsx` + `docs/api.md` pages |
| `theme.extend.colors` | `border|input|ring|background|foreground|primary(+foreground)|secondary|destructive|muted|accent|popover|card` mapped to `hsl(var(--*))` from `index.css` HSL vars |
| `theme.extend.borderRadius` | `lg:var(--radius)` (0.5rem) etc. (`radius: 0.5rem` in `index.css:27`) |
| `theme.extend.fontFamily.mono` | `ui-monospace,SFMono-Regular,Menlo,Consolas,monospace` |
| plugins | `[typography, animate]` |

Tailwind 4 is processed through `@tailwindcss/postcss` in `postcss.config.js`.
`src/index.css` imports Tailwind and explicitly loads the legacy JS config with
`@config "../tailwind.config.ts"`; this preserves the existing HSL theme and
`typography` / `animate` plugin setup during the Tailwind 4 migration.

`src/index.css` (`@import "tailwindcss"` + `@layer base` HSL vars in `:root`
and `.dark`, `@layer utilities` `bg-grid/grid-sm/radial-fade/glow-primary/
skeleton/scrollbar-thin/animate-*`). `index.html` sets `color-scheme: dark`; the
theme is dark-only and has no toggle or local-storage persistence.

Deps (`package.json:13`):

| Family | Packages |
|--------|----------|
| UI primitives | `@radix-ui/react-{checkbox,dialog,label,popover,scroll-area,select,separator,slot,switch,tabs,toast,tooltip}` + `class-variance-authority`, `clsx`, `tailwind-merge` |
| Graph | `reactflow` |
| Data | `@tanstack/react-query`, `@tanstack/react-virtual` |
| Markdown | `react-markdown`, `remark-gfm`, `@tailwindcss/typography` |
| Icons/routing | `lucide-react`, `react-router-dom` |
| Dev | TypeScript, Vite, `@vitejs/plugin-react`, Tailwind 4 + `@tailwindcss/postcss`, Autoprefixer, Vitest, Testing Library, jsdom, `@types/*`, `tailwindcss-animate` |

Declared dependency ranges and exact lockfile resolutions are maintained in
`webui/package.json` and `webui/package-lock.json`.

## Vitest (`webui/vitest.config.ts:1`)

```ts
defineConfig({ plugins:[react()], resolve:{alias:{"@":src}},
  test:{ environment:"node", include:["src/**/*.test.{ts,tsx}"],
         setupFiles:[src/test/setup.ts] }})
```

- **Environment model:** default `node` (so pure-logic tests `stateShape.test.ts`, `campaignCheckpoint.test.ts` run headless); component tests opt into `jsdom` via per-file `/** @vitest-environment jsdom */` docblock.
- **Setup:** `src/test/setup.ts:1` imports `@testing-library/jest-dom/vitest` (matchers) + `afterEach(cleanup())` for RTL. `globals:false` — tests import `vitest` globals explicitly.
- **Coverage surfaces:** `stateShape` helpers (`deriveRun`, `checkpoint` visuals/encoding) run without DOM; `SettingsPage.test.tsx` and `RunWizard.test.tsx` are jsdom.

Execution: `npm test` (`vitest run` once), `vitest` watch on loopback-only env already has no live network — all `subprocess/network` mocked.

## Output

| Artifact | Location | Notes |
|----------|----------|-------|
| `index.html` | `dist/index.html` | entry with `<script type=module src=/assets/...>` |
| `assets/<hash>.js/css` | `dist/assets/` | fingerprinted; `__APP_VERSION__` inlined `JSON.stringify(pkg.version)` |
| Spa fallback | handled by `api. serve_webui` mount (catch-all `GET /{path:not api}` → `dist/index.html`) | |
| Version label | `Layout` shows `v{__APP_VERSION__} beta` (`Layout.tsx:81`) | |

## Local commands

```powershell
npm install          # webui/
npm run dev          # vite 5173 + proxy; keep `python main.py --demon` running
npm run build        # tsc -b && vite build
npm run preview      # serves dist
npm test             # vitest run
npm run bundle-report
```

`requirements.txt` and `pyproject.toml` (`AGENTS.md: pyproject + requirements sync`) cover Python toolchain; webui `devDependencies` are not synced to Python.
