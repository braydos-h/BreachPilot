// @vitest-environment jsdom
import { describe, expect, it, vi } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { EventViewer } from "@/components/events/EventViewer";
import type { EventType, RunEvent } from "@/api/types";

// jsdom has no layout, so the real virtualizer renders nothing. Replace it
// with a flat layout that renders every row so behavior (filters, pause,
// unseen counts, follow) is testable against real DOM.
vi.mock("@tanstack/react-virtual", () => ({
  useVirtualizer: (opts: { count: number }) => {
    const count = opts.count;
    return {
      getVirtualItems: () =>
        Array.from({ length: count }, (_, index) => ({
          index,
          key: index,
          start: index * 50,
          size: 50,
        })),
      getTotalSize: () => count * 50,
      scrollToIndex: vi.fn(),
    };
  },
}));

function event(seq: number, type: EventType, payload: Record<string, unknown> = {}): RunEvent {
  return { sequence: seq, timestamp: "2026-08-21T00:00:00Z", run_id: "r1", type, payload };
}

const baseEvents = [
  event(1, "assistant", { text: "hello from agent" }),
  event(2, "tool_request", { name: "nmap", action: 1, arguments: { target: "10.0.0.5" } }),
  event(3, "tool_result", { action: 1, result: "port 80 open", success: true }),
  event(4, "error", { message: "connection refused" }),
];

type Props = React.ComponentProps<typeof EventViewer>;

function defaultProps(events: RunEvent[] = baseEvents): Props {
  return {
    events,
    decisions: [],
    runId: "r1",
    status: "open",
    transport: "sse",
  };
}

describe("EventViewer", () => {
  it("renders events in chronological order (oldest first)", () => {
    render(<EventViewer {...defaultProps()} />);
    const rows = screen.getByLabelText("Run events");
    const helloPos = rows.textContent!.indexOf("hello from agent");
    const errorPos = rows.textContent!.indexOf("connection refused");
    expect(helloPos).toBeGreaterThanOrEqual(0);
    expect(errorPos).toBeGreaterThan(helloPos);
    expect(screen.getByText("nmap")).toBeInTheDocument();
  });

  it("filters by free text, case-insensitively, and clears", async () => {
    const user = userEvent.setup();
    render(<EventViewer {...defaultProps()} />);
    await user.type(screen.getByLabelText("Filter events by text"), "CONNECTION");
    // Debounced by 200ms, so wait for the filter to apply.
    await waitFor(() => {
      expect(screen.queryByText(/hello from agent/)).not.toBeInTheDocument();
      expect(screen.getByText("connection refused")).toBeInTheDocument();
    });

    await user.click(screen.getByRole("button", { name: "Clear filters" }));
    expect(screen.getByText(/hello from agent/)).toBeInTheDocument();
    expect(screen.getByText("connection refused")).toBeInTheDocument();
  });

  it("filters by event type category", async () => {
    const user = userEvent.setup();
    render(<EventViewer {...defaultProps()} />);
    await user.click(screen.getByRole("button", { name: "Errors" }));
    expect(screen.queryByText(/hello from agent/)).not.toBeInTheDocument();
    expect(screen.getByText("connection refused")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Errors" })).toHaveAttribute("aria-pressed", "true");
  });

  it("pausing freezes the display and counts new events; resuming clears them", async () => {
    const user = userEvent.setup();
    const { rerender } = render(
      <EventViewer {...defaultProps(baseEvents.slice(0, 2))} />,
    );

    await user.click(screen.getByRole("button", { name: "Pause live view" }));
    expect(screen.getByText(/Paused/)).toBeInTheDocument();

    // New events arrive while paused: the counter shows, no auto-follow.
    rerender(
      <EventViewer
        {...defaultProps([...baseEvents.slice(0, 2), event(3, "assistant", { text: "third" })])}
      />,
    );
    expect(screen.getByText(/Paused · 1 new/)).toBeInTheDocument();

    // Resuming shows the latest and clears the unseen count.
    await user.click(screen.getByRole("button", { name: "Resume live view" }));
    expect(screen.queryByText(/Paused/)).not.toBeInTheDocument();
    expect(screen.queryByText(/\d+ new/)).not.toBeInTheDocument();
  });

  it("scrolling away disables follow; jump-to-latest restores it", async () => {
    const user = userEvent.setup();
    const { rerender } = render(<EventViewer {...defaultProps(baseEvents.slice(0, 2))} />);

    // Simulate the user scrolling up the feed.
    const el = screen.getByLabelText("Run events");
    Object.defineProperty(el, "scrollTop", { value: 500, configurable: true });
    Object.defineProperty(el, "scrollHeight", { value: 1000, configurable: true });
    Object.defineProperty(el, "clientHeight", { value: 200, configurable: true });
    fireEvent.scroll(el);

    // New events arrive while scrolled away → unseen counter surfaces.
    rerender(
      <EventViewer
        {...defaultProps([...baseEvents.slice(0, 2), event(3, "assistant", { text: "third" })])}
      />,
    );
    const jump = await screen.findByRole("button", { name: /Jump to latest/ });
    expect(jump).toHaveTextContent("1 new");

    // Jumping clears the unseen counter.
    await user.click(jump);
    expect(screen.queryByRole("button", { name: /Jump to latest/ })).not.toBeInTheDocument();
  });

  it("shows connection status from props", () => {
    const { rerender } = render(
      <EventViewer {...defaultProps()} status="reconnecting" />,
    );
    expect(screen.getByText("Reconnecting")).toBeInTheDocument();

    rerender(<EventViewer {...defaultProps()} status="open" />);
    expect(screen.getByText("Live")).toBeInTheDocument();

    rerender(<EventViewer {...defaultProps()} status="closed" />);
    expect(screen.getByText("Disconnected")).toBeInTheDocument();
  });

  it("surfaces auth failure distinctly and never leaks the token", () => {
    render(
      <EventViewer
        {...defaultProps()}
        status="error"
        authError="Authentication failed. Token rejected by the API."
      />,
    );
    // The distinct "Auth error" status (not plain "Disconnected").
    expect(screen.getByText("Auth error")).toBeInTheDocument();
    // The reason is in the tooltip, not the status text.
    expect(screen.getByTitle(/Authentication failed/)).toBeInTheDocument();
    expect(document.body.textContent).not.toContain("Bearer ");
  });

  it("shows the truncation banner with the omitted count", () => {
    render(<EventViewer {...defaultProps()} dropped={57} />);
    expect(screen.getByText(/57 older events omitted/)).toBeInTheDocument();
    expect(screen.getByText(/full history is preserved server-side/)).toBeInTheDocument();
  });
});
