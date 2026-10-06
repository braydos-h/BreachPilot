// @vitest-environment jsdom
import { useState } from "react";
import { describe, expect, it, vi } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, useLocation } from "react-router-dom";
import { CommandPalette } from "./CommandPalette";

function Harness() {
  const [open, setOpen] = useState(true);
  const location = useLocation();
  return <><CommandPalette open={open} onOpenChange={setOpen} />
    <output aria-label="Current route">{location.pathname}</output></>;
}

describe("CommandPalette search navigation", () => {
  it("renders unique route entries even when extensions repeat a built-in entry", () => {
    render(<MemoryRouter><CommandPalette open onOpenChange={() => {}}
      extraEntries={[{ label: "Runs", hint: "Go to", to: "/runs" }]} /></MemoryRouter>);
    const results = screen.getByRole("navigation", { name: "Search results" });
    expect(within(results).getAllByRole("link", { name: /^Runs/ })).toHaveLength(1);
    expect(within(results).getAllByRole("link", { name: /^Connections/ })).toHaveLength(1);
  });
  it("exposes filtered navigation links that can be followed with Tab and Enter", async () => {
    const user = userEvent.setup();
    render(<MemoryRouter><Harness /></MemoryRouter>);
    const search = screen.getByRole("textbox", { name: "Global search" });
    await user.click(search);
    await user.type(search, "Provider settings");
    const results = screen.getByRole("navigation", { name: "Search results" });
    await waitFor(() => expect(within(results).getAllByRole("link")).toHaveLength(1));
    expect(search).toHaveValue("Provider settings");
    const link = within(results).getByRole("link", { name: /Provider settings/ });
    expect(link).toHaveAttribute("href", "/system");
    expect(screen.queryByRole("listbox")).not.toBeInTheDocument();
    await user.tab();
    expect(link).toHaveFocus();
    await user.keyboard("{Enter}");
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(screen.getByLabelText("Current route")).toHaveTextContent("/system");
  });

  it("describes the diagnostics route as navigation instead of claiming to run a self-test", async () => {
    const user = userEvent.setup();
    render(<MemoryRouter><Harness /></MemoryRouter>);
    const search = screen.getByRole("textbox", { name: "Global search" });
    await user.type(search, "diagnostics");

    const diagnostics = screen.getByRole("link", { name: /Open diagnostics/ });
    expect(diagnostics).toHaveAttribute("href", "/system");
    expect(diagnostics).toHaveTextContent("Go to");
    expect(screen.queryByRole("link", { name: /Run local self-test/ })).not.toBeInTheDocument();
  });

  it("preserves distinct actions when extensions share the same visible entry", async () => {
    const user = userEvent.setup();
    const firstAction = vi.fn();
    const secondAction = vi.fn();
    render(<MemoryRouter><CommandPalette open onOpenChange={() => {}}
      extraEntries={[
        { label: "Custom action", hint: "Command", to: "/system", action: firstAction, keywords: "first" },
        { label: "Custom action", hint: "Command", to: "/system", action: secondAction, keywords: "second" },
      ]} /></MemoryRouter>);
    const search = screen.getByRole("textbox", { name: "Global search" });

    await user.type(search, "first");
    await user.click(screen.getByRole("link", { name: /Custom action/ }));
    expect(firstAction).toHaveBeenCalledOnce();

    await user.type(search, "second");
    await user.click(screen.getByRole("link", { name: /Custom action/ }));
    expect(secondAction).toHaveBeenCalledOnce();
  });
});
