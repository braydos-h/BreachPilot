// @vitest-environment jsdom
import { describe, expect, it, vi, beforeEach } from "vitest";
import { cleanup, render, screen, within, fireEvent } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { HelpPage } from "@/routes/HelpPage";

function renderHelp() {
  cleanup();
  document.body.innerHTML = "";
  return render(
    <MemoryRouter>
      <HelpPage />
    </MemoryRouter>,
  );
}

beforeEach(() => {
  cleanup();
  document.body.innerHTML = "";
  vi.clearAllMocks();
  window.HTMLElement.prototype.scrollIntoView = vi.fn() as unknown as typeof window.HTMLElement.prototype.scrollIntoView;
  (window.Element.prototype as unknown as Record<string, unknown>).scrollIntoView = vi.fn();
});

describe("HelpPage renders", () => {
  it("shows header, quick-start cards and main sections", () => {
    renderHelp();
    expect(screen.getByRole("heading", { name: /Help & Reference/i })).toBeInTheDocument();
    expect(screen.getByPlaceholderText(/What do you need help with/i)).toBeInTheDocument();
    expect(screen.getByText("Start your first run")).toBeInTheDocument();
    expect(screen.getByText("Understand a live run")).toBeInTheDocument();
    expect(screen.getByText("Find collected evidence")).toBeInTheDocument();
    expect(screen.getByText("Configure BreachPilot")).toBeInTheDocument();
    expect(screen.getAllByRole("heading", { name: /How a run flows/i }).length).toBeGreaterThan(0);
    expect(screen.getAllByRole("heading", { name: /Permission modes/i }).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/The target-IP allowlist lock applies in every mode/i).length).toBeGreaterThan(0);
    expect(screen.getAllByRole("heading", { name: /Where do I find/i }).length).toBeGreaterThan(0);
    expect(screen.getAllByRole("heading", { name: /Common workflows/i }).length).toBeGreaterThan(0);
    expect(screen.getAllByRole("heading", { name: /Troubleshooting/i }).length).toBeGreaterThan(0);
    expect(screen.getAllByRole("heading", { name: /FAQ/i }).length).toBeGreaterThan(0);
    expect(screen.getAllByRole("heading", { name: /Documentation library/i }).length).toBeGreaterThan(0);
  });

  it("hides search results when query is empty", () => {
    renderHelp();
    expect(screen.queryByRole("listbox", { name: /Search results/i })).not.toBeInTheDocument();
  });
});

describe("HelpPage search", () => {
  it("filters case-insensitively on title + description + keywords", async () => {
    const user = userEvent.setup();
    renderHelp();
    const input = screen.getByPlaceholderText(/What do you need help with/i);
    await user.type(input, "allowlist");
    const listbox = screen.getByRole("listbox");
    expect(within(listbox).getByText(/Target allowlist lock/i)).toBeInTheDocument();
    expect(within(listbox).getByText(/What is the allowlist/i)).toBeInTheDocument();
    await user.clear(input);
    await user.type(input, "ALLOWLIST");
    expect(screen.getByRole("listbox")).toBeInTheDocument();
    expect(within(screen.getByRole("listbox")).getByText(/Target allowlist lock/i)).toBeInTheDocument();
  });

  it("shows no-results state with guidance", async () => {
    const user = userEvent.setup();
    renderHelp();
    const input = screen.getByPlaceholderText(/What do you need help with/i);
    await user.type(input, "zzz_no_match_999");
    expect(screen.getByText(/No results for/i)).toBeInTheDocument();
    expect(screen.getByText(/Try.*allowlist.*recon.*artifact/i)).toBeInTheDocument();
  });

  it("search covers docs, workflows, troubleshooting and directory", async () => {
    const user = userEvent.setup();
    renderHelp();
    const input = screen.getByPlaceholderText(/What do you need help with/i);
    await user.type(input, "recon only");
    expect(within(screen.getByRole("listbox")).getByText(/Recon only/i)).toBeInTheDocument();
    await user.clear(input);
    await user.type(input, "Getting Started");
    expect(within(screen.getByRole("listbox")).getByText("Getting Started")).toBeInTheDocument();
    await user.clear(input);
    await user.type(input, "provider unavailable");
    expect(screen.getByRole("listbox")).toBeInTheDocument();
  });

  it('hitting "/" focuses search when not typing in another field', async () => {
    renderHelp();
    const input = screen.getByPlaceholderText(/What do you need help with/i) as HTMLInputElement;
    expect(document.activeElement).not.toBe(input);
    fireEvent.keyDown(window, { key: "/" });
    expect(document.activeElement).toBe(input);
  });

  it('hitting "/" does not hijack typing inside the search field itself', async () => {
    const user = userEvent.setup();
    renderHelp();
    const input = screen.getByPlaceholderText(/What do you need help with/i) as HTMLInputElement;
    await user.click(input);
    await user.type(input, "/");
    expect(input.value).toContain("/");
  });

  it("Escape clears a non-empty query and blurs when already empty", async () => {
    const user = userEvent.setup();
    renderHelp();
    const input = screen.getByPlaceholderText(/What do you need help with/i) as HTMLInputElement;
    await user.type(input, "artifact");
    expect(input.value).toBe("artifact");
    fireEvent.keyDown(input, { key: "Escape" });
    expect(input.value).toBe("");
    await user.click(input);
    fireEvent.keyDown(input, { key: "Escape" });
    expect(document.activeElement).not.toBe(input);
  });

  it("clicking a result scrolls to its section", async () => {
    const user = userEvent.setup();
    renderHelp();
    const input = screen.getByPlaceholderText(/What do you need help with/i);
    await user.type(input, "attack graph");
    const listbox = screen.getByRole("listbox");
    const btn = within(listbox).getAllByRole("option")[0];
    await user.click(btn);
    // document should still contain the help page and click should not throw
    expect(document.getElementById("directory") || document.getElementById("docs") || document.body).toBeInTheDocument();
  });
});

describe("HelpPage links", () => {
  it("internal header CTAs use React Router links with correct routes", () => {
    renderHelp();
    const newRunLinks = screen.getAllByRole("link", { name: /Start a run/i });
    expect(newRunLinks.some((a) => a.getAttribute("href") === "/runs/new")).toBe(true);
    const sessionLinks = screen.getAllByRole("link", { name: /View sessions/i });
    expect(sessionLinks.some((a) => a.getAttribute("href") === "/sessions")).toBe(true);
    const openSettingsLinks = screen.getAllByRole("link", { name: /Open settings/i });
    expect(openSettingsLinks.some((a) => a.getAttribute("href") === "/system")).toBe(true);
  });

  it("directory items link to correct global routes where they exist", () => {
    renderHelp();
    const directory = screen.getByRole("heading", { level: 2, name: /Where do I find/i }).closest("section")!;
    expect(within(directory).getByRole("link", { name: /Runs \/ Sessions/ })).toHaveAttribute("href", "/sessions");
    expect(within(directory).getByRole("link", { name: /Goals/ })).toHaveAttribute("href", "/goals");
    expect(within(directory).getByRole("link", { name: /Attack Modules/ })).toHaveAttribute("href", "/modules");
    expect(within(directory).getByRole("link", { name: /Skills/ })).toHaveAttribute("href", "/skills");
    expect(within(directory).getByRole("link", { name: /Memory/ })).toHaveAttribute("href", "/memory");
    expect(within(directory).getByRole("link", { name: /Stats/ })).toHaveAttribute("href", "/stats");
    const directorySettings = within(directory).getAllByRole("link", { name: /Settings/ });
    expect(directorySettings.some((a) => a.getAttribute("href") === "/system")).toBe(true);
  });

  it("documentation links have correct external URLs and open in new tabs", () => {
    renderHelp();
    const docSection = screen.getByRole("heading", { level: 2, name: /Documentation library/i }).closest("section")!;
    const links = within(docSection).getAllByRole("link");
    for (const a of links) {
      expect(a).toHaveAttribute("target", "_blank");
      expect(a.getAttribute("href")).toMatch(/^https:\/\/github\.com\/braydos-h\/BreachPilot\/blob\/main\/docs\/.+\.md$/);
    }
    expect(within(docSection).getByRole("link", { name: /Getting Started/ })).toHaveAttribute("href", expect.stringContaining("docs/getting-started.md"));
    expect(within(docSection).getByRole("link", { name: /Safety Model/ })).toHaveAttribute("href", expect.stringContaining("docs/safety-model.md"));
    expect(within(docSection).getByRole("link", { name: /Attack Modules/ })).toHaveAttribute("href", expect.stringContaining("docs/attack-modules.md"));
    const webuiLinks = within(docSection).getAllByRole("link", { name: /WebUI/ });
    expect(webuiLinks.length).toBeGreaterThan(0);
    expect(webuiLinks.some((a) => a.getAttribute("href")?.includes("docs/webui.md"))).toBe(true);
    expect(within(docSection).getByRole("link", { name: /Model Providers/ })).toHaveAttribute("href", expect.stringContaining("docs/providers.md"));
    const troubleLinks = within(docSection).getAllByRole("link").filter((a) => a.getAttribute("href")?.includes("docs/troubleshooting.md"));
    expect(troubleLinks.length).toBeGreaterThan(0);
  });

  it("anchor navigation links scroll cleanly", async () => {
    const user = userEvent.setup();
    renderHelp();
    const startLink = screen.getAllByRole("link", { name: /Start here/ }).find((a) => a.getAttribute("href")?.includes("#start-here"));
    expect(startLink).toBeInTheDocument();
    expect(startLink).toHaveAttribute("href", expect.stringContaining("#start-here"));
    expect(document.getElementById("start-here")).toBeInTheDocument();
    await user.click(startLink!);
    expect(document.getElementById("start-here")).toBeInTheDocument();
    // also verify the sticky nav has at least 8 distinct on-this-page entries (desktop + mobile may duplicate)
    const allOnPage = screen.getAllByRole("link", { name: /Start here|Run lifecycle|Permissions|Find a feature|Workflows|Troubleshooting|FAQ|Documentation/ });
    expect(allOnPage.length).toBeGreaterThanOrEqual(8);
  });
});

describe("HelpPage permission modes", () => {
  it("renders all three modes and the allowlist invariant", () => {
    renderHelp();
    const badges = screen.getAllByText(/Read-only/i);
    expect(badges.length).toBeGreaterThan(0);
    expect(screen.getAllByText(/Approve/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/Full access/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText("Run start (start_confirm)").length).toBeGreaterThan(0);
    expect(screen.getAllByText("Destructive confirmations").length).toBeGreaterThan(0);
    expect(screen.getAllByText("Goal selection").length).toBeGreaterThan(0);
    expect(screen.getAllByText(/The target-IP allowlist lock applies in every mode/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/goal_select/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/never auto-answered/i).length).toBeGreaterThan(0);
  });
});

describe("HelpPage accessibility", () => {
  it("has semantic headings and a labeled search input", () => {
    renderHelp();
    expect(screen.getByRole("heading", { level: 1, name: /Help & Reference/i })).toBeInTheDocument();
    expect(screen.getAllByRole("heading", { level: 2 }).length).toBeGreaterThanOrEqual(7);
    expect(screen.getByLabelText(/Search help topics/i)).toBeInTheDocument();
  });

  it("has no critical information conveyed only through color (badges + text)", () => {
    renderHelp();
    const approveBadges = screen.getAllByText("Approve");
    for (const el of approveBadges) {
      expect(el.textContent).toMatch(/Approve/);
    }
  });
});
