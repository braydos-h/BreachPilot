// Single source of truth for the app version (todo 53).
// Canonical value comes from webui/package.json via vite define
// (__APP_VERSION__); every surface must render via this module.

declare const __APP_VERSION__: string;

export const APP_VERSION: string =
  typeof __APP_VERSION__ !== "undefined" ? __APP_VERSION__ : "0.0.0-dev";

export function appVersionLabel(): string {
  return `v${APP_VERSION} beta`;
}
