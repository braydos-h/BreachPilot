// Stylized app frame that morphs per tour step. Static JSX only — no data
// fetching. aria-hidden: the tour copy panel carries the real information.

import { Home, List, Play, Settings, ShieldCheck, Sparkles, Terminal } from "lucide-react";
import { cn } from "@/lib/utils";
import { KillChain } from "@/components/welcome/KillChain";
import type { MockupKey, TourStep } from "@/components/welcome/steps";

const NAV = [
  { label: "Home", icon: Home },
  { label: "Sessions", icon: List },
  { label: "Skills", icon: Sparkles },
  { label: "System", icon: Settings },
];

// Which sidebar item is highlighted per mockup (-1 = none).
const ACTIVE_NAV: Record<MockupKey, number> = {
  killchain: 0,
  home: 0,
  wizard: 0,
  run: 0,
  decisions: 0,
  sessions: 1,
  artifacts: 1,
  skills: 2,
  system: 3,
  safety: -1,
  cta: -1,
};

export function ConsoleMockup({ step }: { step: TourStep }) {
  return (
    <div className="overflow-hidden rounded-xl border bg-card/40 shadow-2xl" aria-hidden>
      {/* Title bar */}
      <div className="flex items-center gap-2 border-b bg-card/60 px-3 py-2">
        <div className="flex gap-1.5">
          <span className="h-2.5 w-2.5 rounded-full bg-muted-foreground/30" />
          <span className="h-2.5 w-2.5 rounded-full bg-muted-foreground/30" />
          <span className="h-2.5 w-2.5 rounded-full bg-muted-foreground/30" />
        </div>
        <div className="flex-1 text-center text-[10px] text-muted-foreground">
          BreachPilot · Local console
        </div>
        <div className="text-[9px] text-muted-foreground">v{__APP_VERSION__}</div>
      </div>

      <div className="flex">
        {/* Sidebar */}
        <div className="hidden w-40 shrink-0 border-r bg-card/30 p-2 sm:block">
          <div className="mb-2 flex items-center gap-1.5 px-1">
            <Terminal className="h-3.5 w-3.5 text-primary" />
            <span className="text-[10px] font-semibold">
              <span className="text-gradient-primary">BreachPilot</span>
              <span>AI</span>
            </span>
          </div>
          <nav className="space-y-0.5">
            {NAV.map((item, i) => {
              const Icon = item.icon;
              const active = ACTIVE_NAV[step.mockup] === i;
              return (
                <div
                  key={item.label}
                  className={cn(
                    "flex items-center gap-1.5 rounded px-2 py-1 text-[9px]",
                    active ? "bg-primary/10 text-primary" : "text-muted-foreground",
                  )}
                >
                  <Icon className="h-3 w-3" />
                  {item.label}
                </div>
              );
            })}
          </nav>
          <div className="mt-3 border-t pt-2">
            <div className="px-1 text-[8px] uppercase tracking-wide text-muted-foreground">
              Permission
            </div>
            <div className="mt-1 flex gap-1 px-1">
              {["Read", "Approve", "Full"].map((m, i) => (
                <span
                  key={m}
                  className={cn(
                    "rounded px-1 py-0.5 text-[8px]",
                    i === 0 ? "bg-primary/10 text-primary" : "bg-muted text-muted-foreground",
                  )}
                >
                  {m}
                </span>
              ))}
            </div>
          </div>
        </div>

        {/* Content — keyed by step so the fade replays on each transition */}
        <div key={step.id} className="min-h-[11rem] min-w-0 flex-1 p-3 animate-fade-in">
          <MockupContent step={step} />
        </div>
      </div>
    </div>
  );
}

function MockupContent({ step }: { step: TourStep }) {
  switch (step.mockup) {
    case "killchain":
      return (
        <div className="flex h-full flex-col justify-center">
          <KillChain />
        </div>
      );
    case "home":
      return (
        <div className="space-y-2">
          <div className="rounded-lg border bg-card/60 p-3">
            <div className="text-sm font-semibold">
              <span className="text-gradient-primary">BreachPilot</span>
              <span>AI</span>
            </div>
            <p className="text-[10px] text-muted-foreground">
              AI-driven penetration testing console.
            </p>
          </div>
          <div className="grid grid-cols-4 gap-px overflow-hidden rounded-md border bg-border">
            {[
              ["Total", "12"],
              ["Active", "1"],
              ["Done", "9"],
              ["Failed", "2"],
            ].map(([label, value]) => (
              <div key={label} className="bg-card/60 px-2 py-1.5">
                <div className="text-[8px] uppercase tracking-wide text-muted-foreground">{label}</div>
                <div className="font-mono text-sm tabular-nums">{value}</div>
              </div>
            ))}
          </div>
          <div className="grid grid-cols-2 gap-2">
            <div className="rounded-md border bg-card/40 p-2">
              <div className="text-[10px] font-medium">Recon & Suggest Goals</div>
              <div className="text-[8px] text-muted-foreground">Scan first, then pick a goal.</div>
            </div>
            <div className="rounded-md border bg-card/40 p-2">
              <div className="text-[10px] font-medium">Attack</div>
              <div className="text-[8px] text-muted-foreground">Full exploitation session.</div>
            </div>
          </div>
        </div>
      );
    case "wizard":
      return (
        <div className="space-y-2">
          <div className="flex items-center gap-1 text-[9px]">
            <span className="rounded bg-primary/10 px-1.5 py-0.5 text-primary">Settings</span>
            <span className="text-muted-foreground/50">→</span>
            <span className="rounded bg-primary/10 px-1.5 py-0.5 text-primary">Target</span>
            <span className="text-muted-foreground/50">→</span>
            <span className="rounded bg-muted px-1.5 py-0.5 text-muted-foreground">Review & confirm</span>
          </div>
          <div className="rounded-md border bg-card/60 p-2">
            <div className="text-[8px] uppercase tracking-wide text-muted-foreground">Target</div>
            <div className="mt-1 rounded border bg-background px-2 py-1 font-mono text-[10px]">
              10.0.0.50
            </div>
          </div>
          <div className="rounded-md border bg-primary/10 px-2 py-1 text-center text-[10px] text-primary">
            Create run
          </div>
        </div>
      );
    case "run":
      return (
        <div className="space-y-2">
          <div className="rounded-md border bg-card/60 p-2">
            <div className="flex items-center gap-1.5 text-[9px] text-muted-foreground">
              <span className="h-2 w-2 animate-spin rounded-full border border-primary border-t-transparent" />
              Phase Recon
            </div>
            <div className="mt-1.5 flex gap-0.5">
              {[0, 1, 2, 3, 4].map((i) => (
                <div
                  key={i}
                  className={cn("h-1 flex-1 rounded-full", i <= 1 ? "bg-primary" : "bg-muted")}
                />
              ))}
            </div>
          </div>
          <div className="space-y-1 rounded-md border bg-card/60 p-2 font-mono text-[9px]">
            <div className="text-muted-foreground">[phase] starting → recon</div>
            <div className="text-muted-foreground">[tool] nmap -sV 10.0.0.50</div>
            <div className="text-muted-foreground">[progress] round 3 · 12 actions · recon</div>
            <div className="text-primary">[assistant] Found 3 open ports…</div>
          </div>
          <div className="font-mono text-[9px] text-muted-foreground">
            tokens 12,431 · calls 18 · ctx 34%
          </div>
        </div>
      );
    case "decisions":
      return (
        <div className="space-y-2">
          <div className="flex gap-1">
            {["Read", "Approve", "Full"].map((m, i) => (
              <span
                key={m}
                className={cn(
                  "rounded px-1.5 py-0.5 text-[9px]",
                  i === 0 ? "bg-primary/10 text-primary" : "bg-muted text-muted-foreground",
                )}
              >
                {m}
              </span>
            ))}
          </div>
          <div className="rounded-md border bg-card/60 p-2">
            <div className="flex items-center justify-between">
              <span className="text-[9px] font-medium">tool_approval</span>
              <span className="rounded bg-yellow-500/15 px-1.5 py-0.5 text-[8px] text-yellow-300">
                pending
              </span>
            </div>
            <div className="mt-1.5 rounded border border-destructive/40 bg-destructive/10 px-2 py-1 font-mono text-[8px] text-red-200">
              I UNDERSTAND THE RISK
            </div>
          </div>
          <p className="text-[8px] text-muted-foreground">Read: everything waits for you.</p>
        </div>
      );
    case "sessions":
      return (
        <div className="overflow-hidden rounded-md border">
          <table className="w-full text-[10px]">
            <thead className="text-[9px]">
              <tr>
                <th>ID</th>
                <th>State</th>
                <th>Target</th>
                <th>Mode</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td className="font-mono">run-3f2a</td>
                <td className="text-emerald-300">completed</td>
                <td className="font-mono">10.0.0.50</td>
                <td>recon</td>
              </tr>
              <tr>
                <td className="font-mono">run-9c1d</td>
                <td className="text-yellow-300">running</td>
                <td className="font-mono">10.0.0.50</td>
                <td>attack</td>
              </tr>
              <tr>
                <td className="font-mono">run-7b0e</td>
                <td className="text-red-300">failed</td>
                <td className="font-mono">10.0.0.51</td>
                <td>recon</td>
              </tr>
            </tbody>
          </table>
        </div>
      );
    case "artifacts":
      return (
        <div className="space-y-2">
          <div className="flex items-center gap-1.5">
            <span className="rounded bg-emerald-500/15 px-1.5 py-0.5 text-[8px] text-emerald-300">
              Chain valid
            </span>
            <span className="text-[8px] text-muted-foreground">audit · 42 records</span>
          </div>
          <div className="space-y-1 rounded-md border bg-card/60 p-2 font-mono text-[9px] text-muted-foreground">
            <div>recon_assessment.json</div>
            <div>enhanced/enhanced_report.json</div>
            <div>terminal.log</div>
          </div>
          <div className="rounded-md border bg-card/60 p-2 font-mono text-[9px]">
            <span className="text-emerald-300">ssh_credential</span>{" "}
            <span className="text-muted-foreground">(10.0.0.50)</span>
          </div>
        </div>
      );
    case "skills":
      return (
        <div className="space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-[9px] font-medium">Skills</span>
            <span className="rounded bg-violet-500/15 px-1.5 py-0.5 text-[8px] text-violet-300">
              140 skills
            </span>
          </div>
          <div className="rounded border bg-background px-2 py-1 text-[9px] text-muted-foreground">
            Search skills…
          </div>
          <div className="flex flex-wrap gap-1">
            {["nmap-scan", "web-fingerprint", "msf-exploit", "cve-lookup", "report-writer"].map(
              (s) => (
                <span
                  key={s}
                  className="rounded border bg-card/60 px-1.5 py-0.5 font-mono text-[8px] text-muted-foreground"
                >
                  {s}
                </span>
              ),
            )}
          </div>
        </div>
      );
    case "system":
      return (
        <div className="space-y-2">
          <div className="flex flex-wrap gap-1">
            {["Config", "Secrets", "Models", "Plugins", "Diagnostics"].map((t, i) => (
              <span
                key={t}
                className={cn(
                  "rounded px-1.5 py-0.5 text-[8px]",
                  i === 0 ? "bg-primary/10 text-primary" : "bg-muted text-muted-foreground",
                )}
              >
                {t}
              </span>
            ))}
          </div>
          <div className="space-y-1 rounded-md border bg-card/60 p-2 font-mono text-[9px]">
            <div>
              permission_mode: <span className="text-yellow-300">read_only</span>
            </div>
            <div>
              target_allowlist: <span className="text-muted-foreground">["10.0.0.0/24"]</span>
            </div>
            <div>
              ollama: <span className="text-emerald-300">online</span>
            </div>
          </div>
        </div>
      );
    case "safety":
      return (
        <div className="flex h-full flex-col items-center justify-center gap-2 p-4 text-center">
          <ShieldCheck className="h-8 w-8 animate-pulse-ring text-primary" />
          <div className="text-[10px] font-medium">Loopback only</div>
          <p className="max-w-[16rem] text-[9px] text-muted-foreground">
            Run only against assets you own or are explicitly authorized to test.
          </p>
          <span className="rounded border bg-card/60 px-1.5 py-0.5 font-mono text-[8px] text-muted-foreground">
            allowlist: 10.0.0.0/24
          </span>
        </div>
      );
    case "cta":
      return (
        <div className="flex h-full flex-col items-center justify-center gap-2 p-4 text-center">
          <Play className="h-8 w-8 animate-pulse-ring text-primary" />
          <div className="text-[10px] font-medium">Ready when you are</div>
          <p className="text-[9px] text-muted-foreground">Launch a recon run from the console.</p>
        </div>
      );
  }
}
