// @vitest-environment jsdom
import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { PermissionControl } from "@/components/permission/PermissionControl";
import type { PermissionMode } from "@/lib/permissionMode";

function setup(mode: PermissionMode = "read_only") {
  const onModeChange = vi.fn();
  render(<PermissionControl mode={mode} onModeChange={onModeChange} />);
  return { onModeChange };
}

describe("PermissionControl", () => {
  it("renders all three modes as radios with the current one checked", () => {
    setup("approve");
    expect(screen.getAllByRole("radio")).toHaveLength(3);
    expect(screen.getByRole("radio", { name: /Approve/ })).toBeChecked();
    expect(screen.getByRole("radio", { name: /Read-only/ })).not.toBeChecked();
    expect(screen.getByRole("radio", { name: /Full access/ })).not.toBeChecked();
  });

  it("applies read-only and approve immediately without a confirmation dialog", async () => {
    const user = userEvent.setup();
    const onModeChange = vi.fn();
    const { rerender } = render(<PermissionControl mode="read_only" onModeChange={onModeChange} />);

    await user.click(screen.getByRole("radio", { name: /Approve/ }));
    expect(onModeChange).toHaveBeenCalledWith("approve");
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();

    // Parent adopts the new mode; the control is fully controlled.
    rerender(<PermissionControl mode="approve" onModeChange={onModeChange} />);
    await user.click(screen.getByRole("radio", { name: /Read-only/ }));
    expect(onModeChange).toHaveBeenCalledWith("read_only");
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("opens a confirmation dialog when full access is selected and does not change mode yet", async () => {
    const user = userEvent.setup();
    const { onModeChange } = setup("read_only");
    await user.click(screen.getByRole("radio", { name: /Full access/ }));

    expect(screen.getByRole("dialog")).toBeInTheDocument();
    expect(screen.getByText(/Enable Full Access\?/i)).toBeInTheDocument();
    expect(onModeChange).not.toHaveBeenCalled();
  });

  it("cancelling the dialog leaves the mode unchanged", async () => {
    const user = userEvent.setup();
    const { onModeChange } = setup("read_only");
    await user.click(screen.getByRole("radio", { name: /Full access/ }));
    await user.click(screen.getByRole("button", { name: "Cancel" }));
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(onModeChange).not.toHaveBeenCalled();
    expect(screen.getByRole("radio", { name: /Read-only/ })).toBeChecked();
  });

  it("applies full access only after the operator confirms", async () => {
    const user = userEvent.setup();
    const { onModeChange } = setup("read_only");
    await user.click(screen.getByRole("radio", { name: /Full access/ }));
    await user.click(screen.getByRole("button", { name: "Enable Full Access" }));
    expect(onModeChange).toHaveBeenCalledTimes(1);
    expect(onModeChange).toHaveBeenCalledWith("full_access");
  });

  it("keeps the previous mode and surfaces the error when applying full access fails", async () => {
    const user = userEvent.setup();
    const onModeChange = vi.fn(async () => {
      throw new Error("Server rejected the permission change");
    });
    render(<PermissionControl mode="approve" onModeChange={onModeChange} />);

    await user.click(screen.getByRole("radio", { name: /Full access/ }));
    await user.click(screen.getByRole("button", { name: "Enable Full Access" }));

    expect(await screen.findByRole("alert")).toHaveTextContent("Server rejected the permission change");
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    // Displayed state is still the old one — full access was not adopted.
    expect(screen.getByRole("radio", { name: /Approve/ })).toBeChecked();
  });
});
