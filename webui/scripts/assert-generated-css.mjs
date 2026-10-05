import { readdir, readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import postcss from "postcss";

const assetsDirectory = fileURLToPath(new URL("../dist/assets/", import.meta.url));
const assetNames = await readdir(assetsDirectory);
const cssAssets = assetNames.filter((name) => name.endsWith(".css"));
if (cssAssets.length === 0) {
  throw new Error("Vite build produced no CSS assets");
}

const expectedOpacityRules = [
  { selector: ".bg-background\\/30", token: "--background", alpha: "0.3" },
  { selector: ".bg-primary\\/10", token: "--primary", alpha: "0.1" },
];
const foundOpacityRules = new Set();

for (const name of cssAssets) {
  const cssPath = path.join(assetsDirectory, name);
  const css = await readFile(cssPath, "utf8");
  postcss.parse(css).walkRules((rule) => {
    const expectedRule = expectedOpacityRules.find(({ selector }) =>
      rule.selector.includes(selector),
    );
    if (!expectedRule) return;

    let nestedInColorMixSupport = false;
    for (let ancestor = rule.parent; ancestor; ancestor = ancestor.parent) {
      if (
        ancestor.type === "atrule" &&
        ancestor.name === "supports" &&
        ancestor.params.includes("color-mix")
      ) {
        nestedInColorMixSupport = true;
        break;
      }
    }
    if (nestedInColorMixSupport) return;

    rule.walkDecls("background-color", (declaration) => {
      const escapedToken = expectedRule.token.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      const escapedAlpha = expectedRule.alpha.replace(/^0\./, "0?\\.");
      if (
        new RegExp(`hsl\\(var\\(${escapedToken}\\)\\s*\\/\\s*${escapedAlpha}\\)`)
          .test(declaration.value)
      ) {
        foundOpacityRules.add(expectedRule.selector);
      }
    });
  });
}

const missingOpacityRules = expectedOpacityRules
  .filter(({ selector }) => !foundOpacityRules.has(selector))
  .map(({ selector }) => selector);
if (missingOpacityRules.length > 0) {
  throw new Error(
    `Generated CSS is missing native alpha fallbacks for: ${missingOpacityRules.join(", ")}`,
  );
}
