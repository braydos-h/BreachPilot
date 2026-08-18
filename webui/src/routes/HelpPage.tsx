import { BookOpen, ExternalLink, KeyRound, ShieldAlert, Terminal, Zap } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Separator } from "@/components/ui/separator";

const DOC_LINKS: Array<{ href: string; title: string; desc: string }> = [
  { href: "https://github.com/braydos-h/NetAttackAi/blob/main/docs/getting-started.md", title: "Getting Started", desc: "Setup, commands, and the local development loop." },
  { href: "https://github.com/braydos-h/NetAttackAi/blob/main/docs/safety-model.md", title: "Safety Model", desc: "Scope checks, risk checks, permission modes, audit records." },
  { href: "https://github.com/braydos-h/NetAttackAi/blob/main/docs/attack-modules.md", title: "Attack Modules", desc: "The module registry, families, applicability scoring." },
  { href: "https://github.com/braydos-h/NetAttackAi/blob/main/docs/webui.md", title: "WebUI", desc: "This console — stack, pages, auth, real-time transport." },
  { href: "https://github.com/braydos-h/NetAttackAi/blob/main/docs/providers.md", title: "Model Providers", desc: "Ollama cloud/local and the ChatGPT opt-in provider." },
  { href: "https://github.com/braydos-h/NetAttackAi/blob/main/docs/troubleshooting.md", title: "Troubleshooting", desc: "Symptom → cause → check → fix." },
];

const MODES: Array<{ name: string; badge: "default" | "warn" | "danger"; desc: string }> = [
  { name: "Read-only", badge: "default", desc: "Every operator decision waits for you. Nothing is auto-answered. Safest — you drive." },
  { name: "Approve", badge: "warn", desc: "Non-destructive decisions (start, safe tool calls) are auto-answered. Goal selection and destructive confirmations still wait for you." },
  { name: "Full access", badge: "danger", desc: "Every start_confirm and tool_approval is auto-answered, including destructive confirmations. Goal selection still waits for you." },
];

const PHASES: Array<{ phase: string; desc: string }> = [
  { phase: "Recon", desc: "Nmap scan, service/version fingerprinting, OS verdict, CVE lookup, attack-surface assessment." },
  { phase: "Attack", desc: "The agent picks applicable attack modules, runs them via MCP tools, and generates exploit scripts." },
  { phase: "Report", desc: "Outcome classification, evidence collection, and the final run report with audit trail." },
];

export function HelpPage() {
  return (
    <div className="mx-auto max-w-4xl space-y-6 p-4 md:p-6">
      <div>
        <h1 className="text-lg font-semibold">Help &amp; Reference</h1>
        <p className="text-sm text-muted-foreground">
          A quick tour of the console. Loopback only — run only against assets you own or are authorized to test.
        </p>
      </div>

      <Card className="bg-card/40">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-sm">
            <Zap className="h-4 w-4 text-primary" />
            Quick start
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-2 text-sm text-muted-foreground">
          <ol className="list-decimal space-y-1.5 pl-5">
            <li>
              Open <span className="font-mono text-foreground">Sessions</span> and start a new run — pick a target IP,
              a mode (recon / attack), and a goal.
            </li>
            <li>
              The run streams live events. Any decision (start, goal, destructive tool call) shows up as a card —
              answer it or let your permission mode auto-answer it.
            </li>
            <li>
              Follow progress under <span className="font-mono text-foreground">Recon</span>,{" "}
              <span className="font-mono text-foreground">Attack</span>, and{" "}
              <span className="font-mono text-foreground">Report</span> tabs on the run page.
            </li>
            <li>
              Artifacts, loot, credentials, and the attack graph are each a tab on the run page.
            </li>
          </ol>
        </CardContent>
      </Card>

      <Card className="bg-card/40">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-sm">
            <ShieldAlert className="h-4 w-4 text-primary" />
            Permission modes
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          {MODES.map((m) => (
            <div key={m.name} className="rounded-lg border p-3">
              <div className="flex items-center gap-2">
                <span className="text-sm font-semibold">{m.name}</span>
                <Badge
                  variant={m.badge === "danger" ? "danger" : m.badge === "warn" ? "warn" : "muted"}
                  className="text-[10px]"
                >
                  {m.name}
                </Badge>
              </div>
              <p className="mt-1 text-xs leading-relaxed text-muted-foreground">{m.desc}</p>
            </div>
          ))}
          <div className="flex items-start gap-2 rounded-lg border border-yellow-500/30 bg-yellow-500/10 p-3 text-xs text-yellow-200">
            <KeyRound className="mt-0.5 h-3.5 w-3.5 shrink-0" />
            <p>
              The target-IP allowlist lock applies in every mode — nothing escapes the allowlist configured for the
              run, regardless of permission mode.
            </p>
          </div>
        </CardContent>
      </Card>

      <Card className="bg-card/40">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-sm">
            <Terminal className="h-4 w-4 text-primary" />
            How a run flows
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-2">
            {PHASES.map((p, i) => (
              <div key={p.phase} className="flex gap-3">
                <div className="flex flex-col items-center">
                  <span className="flex h-6 w-6 items-center justify-center rounded-full bg-primary/10 text-xs font-semibold text-primary">
                    {i + 1}
                  </span>
                  {i < PHASES.length - 1 && <span className="w-px flex-1 bg-border" />}
                </div>
                <div className="pb-3">
                  <div className="text-sm font-semibold">{p.phase}</div>
                  <p className="text-xs leading-relaxed text-muted-foreground">{p.desc}</p>
                </div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      <Separator />

      <div>
        <div className="mb-2 flex items-center gap-2 text-sm font-semibold">
          <BookOpen className="h-4 w-4 text-primary" />
          Documentation
        </div>
        <div className="grid gap-2 sm:grid-cols-2">
          {DOC_LINKS.map((d) => (
            <a
              key={d.href}
              href={d.href}
              target="_blank"
              rel="noopener noreferrer"
              className="group rounded-lg border p-3 transition-colors hover:bg-accent/50"
            >
              <div className="flex items-center justify-between">
                <span className="text-sm font-medium group-hover:text-primary">{d.title}</span>
                <ExternalLink className="h-3.5 w-3.5 text-muted-foreground" />
              </div>
              <p className="mt-1 text-xs text-muted-foreground">{d.desc}</p>
            </a>
          ))}
        </div>
      </div>
    </div>
  );
}
