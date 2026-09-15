// @vitest-environment jsdom
import { describe, expect, it } from "vitest";
import { APP_VERSION } from "@/lib/version";
import pkg from "../../package.json";

describe("version single source (todo 53)", () => {
  it("APP_VERSION derives from package.json", () => {
    expect(APP_VERSION).toBe((pkg as { version: string }).version);
  });
});
