import { describe, expect, it } from "vitest";
import { cn } from "./utils";

describe("cn Tailwind v4 class merging", () => {
  it("keeps only the last text shadow utility", () => {
    expect(cn("text-shadow-sm", "text-shadow-lg")).toBe("text-shadow-lg");
  });

  it("merges background directions without crossing modifier scopes", () => {
    expect(cn("bg-linear-to-r hover:bg-linear-to-b bg-linear-to-l")).toBe(
      "hover:bg-linear-to-b bg-linear-to-l",
    );
  });
});
