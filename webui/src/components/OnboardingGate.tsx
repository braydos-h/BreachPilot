import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { KeyRound, Loader2, LogIn, ShieldCheck } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { ChatGptControls, ProviderPicker, useProviderStatus } from "@/components/ProviderSetup";
import { useSecrets, usePutSecrets } from "@/api/hooks";
import { ApiError } from "@/api/client";
import { useToast } from "@/hooks/use-toast";
import { errorFixFor } from "@/lib/errorFixMap";

const ONBOARDING_KEY = "breachpilot.onboarding.v1";

interface OnboardingGateProps {
  children: React.ReactNode;
}

export function OnboardingGate({ children }: OnboardingGateProps) {
  const secrets = useSecrets();
  const [done, setDone] = useState<boolean>(() => {
    try {
      return sessionStorage.getItem(ONBOARDING_KEY) === "1";
    } catch {
      return false;
    }
  });

  const entries = useMemo(() => {
    const keys = secrets.data?.keys ?? {};
    return Object.entries(keys);
  }, [secrets.data?.keys]);

  const missing = useMemo(() => entries.filter(([, status]) => status === "missing"), [entries]);

  // ponytail: gate only triggers when secrets endpoint resolves with >=1 missing key
  // AND the user hasn't dismissed/completed onboarding this session. Configured keys
  // can still be replaced from System → Secrets, but onboarding is for first-run gaps.
  const showGate = !done && !secrets.isLoading && !secrets.error && missing.length > 0;

  useEffect(() => {
    if (!showGate) return;
    try {
      sessionStorage.removeItem(ONBOARDING_KEY);
    } catch {
      // ignore
    }
  }, [showGate]);

  if (secrets.isLoading || secrets.isError || !secrets.data) {
    // Don't block on secrets failure; let the app render.
    return <>{children}</>;
  }

  if (!showGate) {
    return <>{children}</>;
  }

  return <OnboardingCard entries={entries} onDone={() => setDone(true)} />;
}

type SecretStatus = "missing" | "configured";

interface OnboardingCardProps {
  entries: Array<[string, SecretStatus]>;
  onDone: () => void;
}

function OnboardingCard({ entries, onDone }: OnboardingCardProps) {
  const put = usePutSecrets();
  const { toast } = useToast();
  const [draft, setDraft] = useState<Record<string, string>>({});
  const [step, setStep] = useState(0);
  const providerStatus = useProviderStatus();
  const steps = ["Connect", "Provider", "Readiness check", "First run"] as const;

  // Key tiers (todo 14): only required keys block readiness.
  const tierOf = (name: string): "Required for selected provider" | "Recommended" | "Optional enrichment" => {
    const n = name.toLowerCase();
    if (n.includes("ollama") || n.includes("openai") || n.includes("anthropic") || n.includes("api_key") || n === "opencode_go_api_key") return "Required for selected provider";
    if (n.includes("shodan") || n.includes("censys") || n.includes("virus")) return "Recommended";
    return "Optional enrichment";
  };

  const onSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const payload = Object.fromEntries(
      Object.entries(draft).filter(([, v]) => v.trim()),
    );
    if (Object.keys(payload).length === 0) {
      setStep(2);
      return;
    }
    put.mutate(payload, {
      onSuccess: () => {
        toast({ title: "API keys saved", description: "Values stored in secr.json (write-only)." });
        setDraft({});
        setStep(2);
      },
      onError: (err) => {
        toast({
          title: "Save failed",
          description: err instanceof ApiError ? err.message : "Could not save keys.",
          variant: "destructive",
        });
      },
    });
  };

  const onSkip = () => {
    onDone();
    try {
      sessionStorage.setItem(ONBOARDING_KEY, "1");
    } catch {
      // ignore
    }
  };

  // Show missing first, then configured (replaceable). Both are editable.
  const sorted = [...entries].sort((a, b) => {
    const order = (s: SecretStatus) => (s === "missing" ? 0 : 1);
    return order(a[1]) - order(b[1]);
  });

  return (
    <div className="flex min-h-dvh items-center justify-center bg-background px-4 py-10">
      <Card className="w-full max-w-lg">
        <CardHeader className="space-y-2">
          <div className="flex items-center gap-2 text-muted-foreground">
            <KeyRound className="h-4 w-4" />
            <span className="text-xs uppercase tracking-wide">Setup — step {step + 1} of {steps.length}: {steps[step]}</span>
          </div>
          <div className="flex gap-1.5" aria-label="Setup progress">
            {steps.map((s, i) => (
              <span key={s} className={`h-1 flex-1 rounded-full ${i <= step ? "bg-primary" : "bg-muted"}`} />
            ))}
          </div>
          <CardTitle className="text-xl">Set up BreachPilot</CardTitle>
          <CardDescription>
            Connect → Provider → Readiness check → First run. Tour content is optional and skippable.
            Keys are stored locally in <code className="rounded bg-muted px-1 py-0.5 text-xs">secr.json</code> and
            never sent anywhere except <code className="rounded bg-muted px-1 py-0.5 text-xs">127.0.0.1</code>.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {step === 0 && (
            <div className="space-y-3">
              <p className="text-sm text-muted-foreground">Connect to the local API. You are already connected — continue to choose a provider.</p>
              <div className="flex gap-2">
                <Button className="flex-1" onClick={() => setStep(1)}>Continue</Button>
              </div>
            </div>
          )}
          {step === 1 && (
          <form className="space-y-5" onSubmit={onSubmit}>
            <div className="space-y-2">
              <Label className="text-sm">AI provider</Label>
              <ProviderPicker />
              <p className="text-[13px] text-muted-foreground">
                Ollama runs locally; ChatGPT goes through the openai-oauth proxy. Switch any time.
              </p>
            </div>
            <div className="space-y-2">
              <div className="flex items-center gap-2 text-sm font-medium">
                <KeyRound className="h-4 w-4 text-muted-foreground" /> Provider API keys
              </div>
              <p className="text-[13px] text-muted-foreground">Required keys block readiness. Recommended and optional keys never show error warnings when skipped.</p>
              {(["Required for selected provider", "Recommended", "Optional enrichment"] as const).map((tier) => (
                <div key={tier} className="space-y-2">
                  <div className="text-xs font-medium uppercase tracking-wide text-muted-foreground">{tier}</div>
                  <ul className="space-y-3">
              {sorted.filter(([name]) => tierOf(name) === tier).map(([name, status]) => (
                <li key={name} className="space-y-1.5">
                  <div className="flex items-center gap-2">
                    <Label htmlFor={name} className="font-mono text-xs">{name}</Label>
                    {status === "configured" ? (
                      <Badge variant="success">
                        <ShieldCheck className="h-3 w-3" />configured
                      </Badge>
                    ) : (
                      <Badge variant={tier === "Required for selected provider" ? "warn" : "muted"}>{tier === "Required for selected provider" ? "required" : "optional"}</Badge>
                    )}
                  </div>
                  <Input
                    id={name}
                    type="password"
                    autoComplete="off"
                    spellCheck={false}
                    placeholder={
                      status === "configured"
                        ? `Enter a new value to replace the saved ${name}`
                        : `Paste ${name} value (or leave blank${tier === "Required for selected provider" ? "" : " — optional"})`
                    }
                    value={draft[name] ?? ""}
                    onChange={(e) => setDraft((p) => ({ ...p, [name]: e.target.value }))}
                  />
                </li>
              ))}
            </ul>
                </div>
              ))}
            </div>

            <div className="space-y-2 rounded-md border p-3">
              <div className="flex items-center gap-2 text-sm font-medium">
                <LogIn className="h-4 w-4 text-muted-foreground" /> ChatGPT (optional)
              </div>
              <p className="text-[13px] text-muted-foreground">
                Only needed if you picked ChatGPT. Sign in opens a browser on the server host;
                OAuth tokens stay on the server in <code className="rounded bg-muted px-1 text-xs">~/.codex/auth.json</code>.
              </p>
              <ChatGptControls />
            </div>

            {put.error && (
              <p className="text-[13px] text-destructive">
                {put.error instanceof ApiError ? put.error.message : "Save failed."}
              </p>
            )}
            <div className="flex items-center gap-2">
              <Button type="button" variant="outline" onClick={() => setStep(0)}>Back</Button>
              <Button type="submit" className="flex-1" disabled={put.isPending}>
                {put.isPending ? <Loader2 className="h-4 w-4" /> : <ShieldCheck className="h-4 w-4" />}
                {put.isPending ? "Saving" : "Save & continue"}
              </Button>
              <Button type="button" variant="outline" onClick={onSkip} disabled={put.isPending}>
                Skip for now
              </Button>
            </div>
          </form>
          )}
          {step === 2 && (
            <div className="space-y-3">
              <div role="status" className={`rounded-md border p-3 text-sm ${providerStatus.status === "online" ? "border-emerald-500/40 bg-emerald-500/10" : "border-amber-500/40 bg-amber-500/10"}`}>
                <div className="font-medium">{providerStatus.status === "online" ? "Ready to run ✓" : providerStatus.status === "checking" ? "Checking provider…" : `Blocked: ${providerStatus.statusText}`}</div>
                <p className="mt-0.5 text-[13px] text-muted-foreground">{providerStatus.label} · {providerStatus.statusText}{providerStatus.error ? ` — ${providerStatus.error}` : ""}</p>
                {providerStatus.status !== "online" && (
                  <Link to="/system" className="mt-1 inline-block text-[13px] text-primary hover:underline">{errorFixFor("provider_offline").actionLabel}</Link>
                )}
              </div>
              <div className="flex gap-2">
                <Button variant="outline" onClick={() => setStep(1)}>Back</Button>
                <Button className="flex-1" onClick={() => setStep(3)}>Continue</Button>
              </div>
            </div>
          )}
          {step === 3 && (
            <div className="space-y-3">
              <p className="text-sm text-muted-foreground">Verify with the zero-risk localhost self-test, explore a demo run, or start a real assessment.</p>
              <div className="flex flex-col gap-2">
                <Button asChild><Link to="/system">Run local self-test</Link></Button>
                <Button variant="outline" asChild><Link to="/runs">Explore a demo run</Link></Button>
                <Button variant="outline" asChild><Link to="/runs/new">Start a real run</Link></Button>
                <Button variant="ghost" onClick={onSkip}>Finish setup</Button>
              </div>
              <Button variant="outline" onClick={() => setStep(2)}>Back</Button>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}