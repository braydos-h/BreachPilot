const THEME_COLOR_MIX =
  /^color-mix\(\s*in\s+oklab\s*,\s*hsl\(\s*var\(\s*(--[a-z0-9-]+)\s*\)\s*\/\s*1(?:\.0+)?\s*\)\s*(\d+(?:\.\d+)?)%\s*,\s*transparent\s*\)$/i;

function alphaFallback(value) {
  const match = THEME_COLOR_MIX.exec(value.trim());
  if (!match) return null;

  const [, token, opacityPercent] = match;
  const alpha = (Number(opacityPercent) / 100).toString();
  return `hsl(var(${token}) / ${alpha})`;
}

/**
 * Tailwind v4 expresses palette opacity with color-mix(), whose generated
 * legacy fallback is opaque when the palette color references HSL channels
 * through var(). Emit native HSL alpha declarations after each supports block
 * for only those theme tokens, so opacity remains correct without color-mix.
 */
export default function themeAlphaFallback() {
  return {
    postcssPlugin: "breachpilot-tailwind-theme-alpha-fallback",
    Once(root) {
      root.walkAtRules("supports", (supports) => {
        if (!supports.params.includes("color-mix")) return;

        const fallbackRules = [];
        supports.walkRules((rule) => {
          const declarations = rule.nodes
            .filter((node) => node.type === "decl")
            .map((declaration) => ({
              declaration,
              value: alphaFallback(declaration.value),
            }))
            .filter((item) => item.value !== null);
          if (declarations.length === 0) return;

          const fallbackRule = rule.clone();
          fallbackRule.removeAll();
          for (const { declaration, value } of declarations) {
            fallbackRule.append(declaration.clone({ value }));
          }

          let fallbackNode = fallbackRule;
          let ancestor = rule.parent;
          while (ancestor !== supports) {
            const wrapper = ancestor.clone();
            wrapper.removeAll();
            wrapper.append(fallbackNode);
            fallbackNode = wrapper;
            ancestor = ancestor.parent;
          }

          fallbackRules.push(fallbackNode);
        });

        let insertionPoint = supports;
        for (const fallbackRule of fallbackRules) {
          supports.parent.insertAfter(insertionPoint, fallbackRule);
          insertionPoint = fallbackRule;
        }
      });
    },
  };
}
