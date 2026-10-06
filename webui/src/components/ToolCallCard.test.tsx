// @vitest-environment jsdom
import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { ToolCallCard } from "./ToolCallCard";

describe("ToolCallCard disclosure", () => {
  it("associates repeated tools with distinct result panels", async () => {
    const user = userEvent.setup();
    render(<><ToolCallCard toolName="nmap" result="first output" started completed={false} />
      <ToolCallCard toolName="nmap" result="second output" started completed={false} /></>);
    const buttons = screen.getAllByRole("button", { name: /nmap/ });
    const first = buttons[0]!;
    const second = buttons[1]!;
    const firstId = first.getAttribute("aria-controls");
    const secondId = second.getAttribute("aria-controls");
    expect(firstId).toBeTruthy();
    expect(secondId).toBeTruthy();
    expect(firstId).not.toBe(secondId);
    expect(document.getElementById(firstId!)?.textContent).toContain("first output");
    expect(document.getElementById(secondId!)?.textContent).toContain("second output");
    await user.click(first);
    expect(first).toHaveAttribute("aria-expanded", "false");
    expect(first).not.toHaveAttribute("aria-controls");
    expect(screen.getByText("second output")).toBeInTheDocument();
  });

  it("does not label ordinary completed tools as unverified exploit claims", async () => {
    const user = userEvent.setup();
    render(
      <ToolCallCard
        toolName="nmap"
        result="port 443 open"
        operational_status="completed"
        exploit_outcome="none"
        started
        completed
      />,
    );

    expect(screen.queryByText("Not verified")).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /nmap/ }));
    expect(screen.getByText("Not applicable")).toBeInTheDocument();
    expect(screen.getByText("none")).toBeInTheDocument();
  });
});
