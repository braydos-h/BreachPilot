import tailwindcss from "@tailwindcss/postcss";
import themeAlphaFallback from "./scripts/tailwind-theme-alpha-fallback.mjs";

export default {
  plugins: [tailwindcss(), themeAlphaFallback()],
};
