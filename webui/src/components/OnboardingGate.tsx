import { useEffect, useMemo, useState } from "react";
import { KeyRound, Loader2, LogIn, ShieldCheck } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { ChatGptControls, ProviderPicker } from "@/components/ProviderSetup";
import { useSecrets, usePutSecrets } from "@/api/hooks";
import { ApiError } from "@/api/client";
import { useToast } from "@/hooks/use-toast";

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

  const onSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const payload = Object.fromEntries(
      Object.entries(draft).filter(([, v]) => v.trim()),
    );
    if (Object.keys(payload).length === 0) {
      onDone();
      try {
        sessionStorage.setItem(ONBOARDING_KEY, "1");
      } catch {
        // ignore
      }
      return;
    }
    put.mutate(payload, {
      onSuccess: () => {
        toast({ title: "API keys saved", description: "Values stored in secr.json (write-only)." });
        setDraft({});
        onDone();
        try {
          sessionStorage.setItem(ONBOARDING_KEY, "1");
        } catch {
          // ignore
        }
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
            <span className="text-xs uppercase tracking-wide">First-run setup</span>
          </div>
          <CardTitle className="text-xl">Set up BreachPilot</CardTitle>
          <CardDescription>
            Pick your AI provider, add provider API keys, and (optionally) sign in to ChatGPT.
            Missing keys are required; configured ones can be replaced. You can change any of this
            later under{" "}
            <code className="rounded bg-muted px-1 py-0.5 text-xs">System → Models</code> /{" "}
            <code className="rounded bg-muted px-1 py-0.5 text-xs">System → Secrets</code>. Keys are
            stored locally in <code className="rounded bg-muted px-1 py-0.5 text-xs">secr.json</code> and
            never sent anywhere except <code className="rounded bg-muted px-1 py-0.5 text-xs">127.0.0.1</code>.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form className="space-y-5" onSubmit={onSubmit}>
            <div className="space-y-2">
              <Label className="text-sm">AI provider</Label>
              <ProviderPicker />
              <p className="text-xs text-muted-foreground">
                Ollama runs locally; ChatGPT goes through the openai-oauth proxy. Switch any time.
              </p>
            </div>
            <div className="space-y-2">
              <div className="flex items-center gap-2 text-sm font-medium">
                <KeyRound className="h-4 w-4 text-muted-foreground" /> Provider API keys
              </div>
              <ul className="space-y-3">
              {sorted.map(([name, status]) => (
                <li key={name} className="space-y-1.5">
                  <div className="flex items-center gap-2">
                    <Label htmlFor={name} className="font-mono text-xs">{name}</Label>
                    {status === "configured" ? (
                      <Badge variant="success">
                        <ShieldCheck className="h-3 w-3" />configured
                      </Badge>
                    ) : (
                      <Badge variant="muted">missing</Badge>
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
                        : `Paste ${name} value (or leave blank)`
                    }
                    value={draft[name] ?? ""}
                    onChange={(e) => setDraft((p) => ({ ...p, [name]: e.target.value }))}
                  />
                </li>
              ))}
            </ul>
            </div>

            <div className="space-y-2 rounded-md border p-3">
              <div className="flex items-center gap-2 text-sm font-medium">
                <LogIn className="h-4 w-4 text-muted-foreground" /> ChatGPT (optional)
              </div>
              <p className="text-xs text-muted-foreground">
                Only needed if you picked ChatGPT. Sign in opens a browser on the server host;
                OAuth tokens stay on the server in <code className="rounded bg-muted px-1 text-xs">~/.codex/auth.json</code>.
              </p>
              <ChatGptControls />
            </div>

            {put.error && (
              <p className="text-xs text-destructive">
                {put.error instanceof ApiError ? put.error.message : "Save failed."}
              </p>
            )}
            <div className="flex items-center gap-2">
              <Button type="submit" className="flex-1" disabled={put.isPending}>
                {put.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <ShieldCheck className="h-4 w-4" />}
                {put.isPending ? "Saving" : "Save & continue"}
              </Button>
              <Button type="button" variant="outline" onClick={onSkip} disabled={put.isPending}>
                Skip for now
              </Button>
            </div>
          </form>
        </CardContent>
      </Card>
    </div>
  );
}