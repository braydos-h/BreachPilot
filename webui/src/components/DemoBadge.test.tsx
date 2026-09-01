// @vitest-environment jsdom
import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { DemoBadge } from "@/components/DemoBadge";

describe("DemoBadge", () => {
  it("renders DEMO text", () => {
    render(<DemoBadge />);
    expect(screen.getByText("DEMO")).toBeInTheDocument();
  });

  it("has accessible title", () => {
    render(<DemoBadge />);
    expect(screen.getByText("DEMO").title).toMatch(/Synthetic demo/i);
  });
});
