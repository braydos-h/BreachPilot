// @vitest-environment jsdom
import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import type { ComponentProps } from "react";
import { AddSkillDialog } from "./AddSkillDialog";

describe("AddSkillDialog", () => {
  it("clears the validation message and resets preview when closed", () => {
    const setDraftError = vi.fn();
    const setPreviewTab = vi.fn();
    const page = {
      addOpen: true,
      setAddOpen: vi.fn(),
      draftName: "",
      setDraftName: vi.fn(),
      draftMarkdown: "",
      setDraftMarkdown: vi.fn(),
      draftError: "Markdown body is required.",
      setDraftError,
      previewTab: "preview",
      setPreviewTab,
      install: { isPending: false },
      onInstall: vi.fn(),
    } satisfies ComponentProps<typeof AddSkillDialog>["page"];

    render(<AddSkillDialog page={page} />);

    expect(screen.getByText("Markdown body is required.")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Close" }));

    expect(setDraftError).toHaveBeenCalledWith("");
    expect(setPreviewTab).toHaveBeenCalledWith("write");
  });
});
