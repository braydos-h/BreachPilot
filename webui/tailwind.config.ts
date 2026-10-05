import type { Config } from "tailwindcss";
import typography from "@tailwindcss/typography";
import animate from "tailwindcss-animate";

// Give the v4 compatibility pass a normalized HSL token to derive slash-opacity
// fallbacks from (for example, `bg-background/30`).
const themeColor = (name: string) => `hsl(var(--${name}) / <alpha-value>)`;

const config: Config = {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    container: {
      center: true,
      padding: "1rem",
    },
    extend: {
      typography: {
        invert: {
          css: {
            "--tw-prose-body": "hsl(var(--muted-foreground))",
            "--tw-prose-headings": "hsl(var(--foreground))",
            "--tw-prose-links": "hsl(var(--primary))",
            "--tw-prose-code": "hsl(var(--foreground))",
            "--tw-prose-pre-bg": "hsl(var(--muted))",
            "--tw-prose-pre-code": "hsl(var(--foreground))",
            "--tw-prose-bullets": "hsl(var(--border))",
            "--tw-prose-quotes": "hsl(var(--muted-foreground))",
            "--tw-prose-quote-borders": "hsl(var(--primary) / 0.4)",
          },
        },
      },
      colors: {
        border: themeColor("border"),
        input: themeColor("input"),
        ring: themeColor("ring"),
        background: themeColor("background"),
        foreground: themeColor("foreground"),
        primary: {
          DEFAULT: themeColor("primary"),
          foreground: themeColor("primary-foreground"),
        },
        secondary: {
          DEFAULT: themeColor("secondary"),
          foreground: themeColor("secondary-foreground"),
        },
        destructive: {
          DEFAULT: themeColor("destructive"),
          foreground: themeColor("destructive-foreground"),
        },
        muted: {
          DEFAULT: themeColor("muted"),
          foreground: themeColor("muted-foreground"),
        },
        accent: {
          DEFAULT: themeColor("accent"),
          foreground: themeColor("accent-foreground"),
        },
        popover: {
          DEFAULT: themeColor("popover"),
          foreground: themeColor("popover-foreground"),
        },
        card: {
          DEFAULT: themeColor("card"),
          foreground: themeColor("card-foreground"),
        },
      },
      borderRadius: {
        lg: "var(--radius)",
        md: "calc(var(--radius) - 2px)",
        sm: "calc(var(--radius) - 4px)",
      },
      fontFamily: {
        mono: ["ui-monospace", "SFMono-Regular", "Menlo", "Consolas", "monospace"],
      },
    },
  },
  plugins: [typography, animate],
};

export default config;
