// @vitest-environment jsdom
import { useState } from "react";
import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { SegmentedControl, TriStateToggle } from "./segmented";

function Control({ disabled = false }: { disabled?: boolean }) {
  const [value, setValue] = useState("b");
  return <><SegmentedControl label="Mode" value={value} onChange={setValue} disabled={disabled}
    options={[{ value: "a", label: "First" }, { value: "b", label: "Second" }, { value: "c", label: "Third" }]} />
    <button type="button">After control</button></>;
}

describe("SegmentedControl keyboard selection", () => {
  it("uses one tab stop and selects with wrapping arrow keys, Home and End", async () => {
    const user = userEvent.setup();
    render(<Control />);
    expect(screen.getByRole("radiogroup", { name: "Mode" })).toBeInTheDocument();
    await user.tab();
    expect(screen.getByRole("radio", { name: "Second" })).toHaveFocus();
    await user.keyboard("{ArrowRight}");
    expect(screen.getByRole("radio", { name: "Third" })).toHaveFocus();
    expect(screen.getByRole("radio", { name: "Third" })).toHaveAttribute("aria-checked", "true");
    await user.keyboard("{ArrowDown}");
    expect(screen.getByRole("radio", { name: "First" })).toHaveFocus();
    await user.keyboard("{ArrowLeft}");
    expect(screen.getByRole("radio", { name: "Third" })).toHaveFocus();
    await user.keyboard("{ArrowUp}");
    expect(screen.getByRole("radio", { name: "Second" })).toHaveFocus();
    await user.keyboard("{Home}");
    expect(screen.getByRole("radio", { name: "First" })).toHaveAttribute("aria-checked", "true");
    await user.keyboard("{End}");
    expect(screen.getByRole("radio", { name: "Third" })).toHaveFocus();
    await user.tab();
    expect(screen.getByRole("button", { name: "After control" })).toHaveFocus();
  });

  it("skips disabled groups in keyboard navigation", async () => {
    const user = userEvent.setup();
    render(<Control disabled />);
    await user.tab();
    expect(screen.getByRole("button", { name: "After control" })).toHaveFocus();
    expect(screen.getByRole("radio", { name: "Second" })).toHaveAttribute("aria-checked", "true");
  });

  it("passes a distinct accessible name through tri-state controls", () => {
    render(<TriStateToggle label="Recon first" value={null} onChange={() => {}} labels={{ true: "On", false: "Off", null: "Auto" }} />);
    expect(screen.getByRole("radiogroup", { name: "Recon first" })).toBeInTheDocument();
    expect(screen.getByRole("radio", { name: "Auto" })).toHaveAttribute("tabindex", "0");
  });
});
