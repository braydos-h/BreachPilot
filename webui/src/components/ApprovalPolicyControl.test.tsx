// @vitest-environment jsdom
import { describe, expect, it } from "vitest";
import { approvalPolicyToBackend } from "@/components/ApprovalPolicyControl";

describe("approval policy mapping (todo 09)", () => {
  it("maps to backend flags explicitly", () => {
    expect(approvalPolicyToBackend("read_only")).toEqual({ mode: "read_only", yes: false });
    expect(approvalPolicyToBackend("approve")).toEqual({ mode: "approve", yes: false });
    expect(approvalPolicyToBackend("full_access")).toEqual({ mode: "full_access", yes: true });
  });
});
