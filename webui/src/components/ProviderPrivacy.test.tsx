// @vitest-environment jsdom
import { describe, expect, it, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import React from "react";

vi.mock("@/api/client", async () => {
  const actual = await vi.importActual<typeof import("@/api/client")>("@/api/client");
  return { ...actual, apiFetch: vi.fn() };
});

import { apiFetch } from "@/api/client";

const apiFetchMock = vi.mocked(apiFetch);

import {
  ProviderPrivacyGate,
  ProviderPrivacyNotice,
  privacyAckKeyFor,
  readPrivacyAck,
  useProviderPrivacy,
} from "@/components/ProviderSetup";
import { renderHook } from "@testing-library/react";

const ACK_KEY = "breachpilot.providerPrivacyAck.v1";

function createWrapper() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return ({ children }: { children: React.ReactNode }) => React.createElement(QueryClientProvider, { client: qc }, children);
}

function mockBackend(opts: { provider: string; residency?: "local" | "cloud"; egress?: string; label?: string }) {
  const { provider, residency = "cloud", egress = "", label } = opts;
  const name = label ?? provider;
  apiFetchMock.mockImplementation(async (path: string) => {
    if (path === "/models") return { provider, default_alias: "m", registry: {} } as never;
    if (path === "/models/live") return { models: ["m"], source: provider } as never;
    if (path === "/providers")
      return {
        provider,
        active: provider,
        providers: [
          {
            id: provider,
            name,
            capabilities: { chat: true, streaming: true, tool_calls: true, reasoning: false, embeddings: false, model_discovery: true },
            data_residency: residency,
            egress_target: egress,
          },
        ],
      } as never;
    throw new Error(`unexpected ${path}`);
  });
}

function renderNode(node: React.ReactNode) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={qc}>{node}</QueryClientProvider>);
}

beforeEach(() => {
  vi.clearAllMocks();
  localStorage.clear();
});

describe("useProviderPrivacy", () => {
  it("resolves local residency with an empty egress target", async () => {
    mockBackend({ provider: "ollama", residency: "local", egress: "", label: "Ollama" });
    const { result } = renderHook(() => useProviderPrivacy(), { wrapper: createWrapper() });
    await waitFor(() => expect(result.current.isLoading).toBe(false));
    expect(result.current.residency).toBe("local");
    expect(result.current.isCloud).toBe(false);
    expect(result.current.egressTarget).toBe("");
  });

  it("resolves cloud residency with the backend egress target", async () => {
    mockBackend({ provider: "ollama", residency: "cloud", egress: "https://api.ollama.com", label: "Ollama" });
    const { result } = renderHook(() => useProviderPrivacy(), { wrapper: createWrapper() });
    await waitFor(() => expect(result.current.isLoading).toBe(false));
    expect(result.current.residency).toBe("cloud");
    expect(result.current.egressTarget).toBe("https://api.ollama.com");
  });
});

describe("ProviderPrivacyNotice", () => {
  it("shows the Local badge with a stays-on-host notice", async () => {
    mockBackend({ provider: "ollama", residency: "local", label: "Ollama" });
    renderNode(<ProviderPrivacyNotice />);
    const badge = await screen.findByTestId("provider-privacy-badge");
    expect(badge.textContent).toMatch(/Local/);
    expect((await screen.findByTestId("provider-privacy-notice")).textContent).toMatch(/Stays on this host/);
  });

  it("shows the Cloud badge with the egress target", async () => {
    mockBackend({ provider: "opencode_go", residency: "cloud", egress: "https://opencode.ai/zen/go/v1", label: "OpenCode Go" });
    renderNode(<ProviderPrivacyNotice />);
    const badge = await screen.findByTestId("provider-privacy-badge");
    expect(badge.textContent).toMatch(/Cloud/);
    expect((await screen.findByTestId("provider-privacy-notice")).textContent).toMatch(/Sends prompts to https:\/\/opencode\.ai/);
  });

  it("names the ChatGPT account as the egress target, not the proxy", async () => {
    mockBackend({ provider: "chatgpt", residency: "cloud", egress: "OpenAI via ChatGPT account", label: "ChatGPT" });
    renderNode(<ProviderPrivacyNotice />);
    const notice = await screen.findByTestId("provider-privacy-notice");
    expect(notice.textContent).toMatch(/Sends prompts to OpenAI via ChatGPT account/);
    expect(notice.textContent).not.toMatch(/127\.0\.0\.1/);
  });
});

describe("ProviderPrivacyGate", () => {
  it("does not gate a local provider", async () => {
    mockBackend({ provider: "ollama", residency: "local", label: "Ollama" });
    renderNode(
      <ProviderPrivacyGate>
        <div>app content</div>
      </ProviderPrivacyGate>,
    );
    expect(await screen.findByText("app content")).toBeTruthy();
    expect(screen.queryByTestId("provider-privacy-gate")).toBeNull();
  });

  it("gates a cloud route until explicitly acknowledged, then persists", async () => {
    const user = userEvent.setup();
    mockBackend({ provider: "ollama", residency: "cloud", egress: "https://api.ollama.com", label: "Ollama" });
    const { unmount } = renderNode(
      <ProviderPrivacyGate>
        <div>app content</div>
      </ProviderPrivacyGate>,
    );
    expect(await screen.findByTestId("provider-privacy-gate")).toBeTruthy();
    expect(screen.queryByText("app content")).toBeNull();

    // Explicit confirm required: button disabled until the checkbox is checked.
    const confirm = screen.getByRole("button", { name: /Acknowledge/i });
    expect((confirm as HTMLButtonElement).disabled).toBe(true);
    await user.click(screen.getByLabelText(/I understand prompts leave this machine/i));
    await user.click(confirm);
    expect(await screen.findByText("app content")).toBeTruthy();
    expect(readPrivacyAck()).toBe(privacyAckKeyFor("ollama", "https://api.ollama.com"));
    expect(localStorage.getItem(ACK_KEY)).toBe("ollama|https://api.ollama.com");

    // Persisted: a fresh mount with the same route does not re-prompt.
    unmount();
    renderNode(
      <ProviderPrivacyGate>
        <div>app content</div>
      </ProviderPrivacyGate>,
    );
    expect(await screen.findByText("app content")).toBeTruthy();
    expect(screen.queryByTestId("provider-privacy-gate")).toBeNull();
  });

  it("re-prompts when the cloud route changes", async () => {
    localStorage.setItem(ACK_KEY, "ollama|https://api.ollama.com");
    mockBackend({ provider: "opencode_go", residency: "cloud", egress: "https://opencode.ai/zen/go/v1", label: "OpenCode Go" });
    renderNode(
      <ProviderPrivacyGate>
        <div>app content</div>
      </ProviderPrivacyGate>,
    );
    expect(await screen.findByTestId("provider-privacy-gate")).toBeTruthy();
    expect(screen.queryByText("app content")).toBeNull();
  });
});
