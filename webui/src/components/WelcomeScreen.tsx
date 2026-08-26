// Full-screen welcome experience: an animated hero intro plus a guided tour
// of the project and the WebUI. WelcomeGate is the sessionStorage-gated
// wrapper (mirrors OnboardingGate); the "netattackai:open-welcome" DOM event
// re-opens it from anywhere (HomePage's "Take the tour" button).

import { useEffect, useMemo, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { ArrowLeft, ArrowRight, Compass, ShieldCheck, Terminal, X } from "lucide-react";
import { cn } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { KillChain } from "@/components/welcome/KillChain";
import { ConsoleMockup } from "@/components/welcome/ConsoleMockup";
import { STEPS } from "@/components/welcome/steps";

const WELCOME_KEY = "netattackai.welcome.v1";
const OPEN_EVENT = "netattackai:open-welcome";

const TAGLINE = "Autonomous assessment platform for authorized security testing — local-first, audited, operator-supervised.";

export function WelcomeGate({ children }: { children: React.ReactNode }) {
  const [open, setOpen] = useState<boolean>(() => {
    try {
      return sessionStorage.getItem(WELCOME_KEY) !== "1";
    } catch {
      return true;
    }
  });

  useEffect(() => {
    const onOpen = () => setOpen(true);
    window.addEventListener(OPEN_EVENT, onOpen);
    return () => window.removeEventListener(OPEN_EVENT, onOpen);
  }, []);

  if (!open) return <>{children}</>;
  return <WelcomeScreen onDone={() => setOpen(false)} />;
}

function dismiss() {
  try {
    sessionStorage.setItem(WELCOME_KEY, "1");
  } catch {
    // ignore
  }
}

export function WelcomeScreen({ onDone }: { onDone: () => void }) {
  const [mode, setMode] = useState<"hero" | "tour">("hero");
  const finish = () => {
    dismiss();
    onDone();
  };
  if (mode === "tour") return <Tour onExit={finish} />;
  return <Hero onStart={() => setMode("tour")} onSkip={finish} />;
}

function Hero({ onStart, onSkip }: { onStart: () => void; onSkip: () => void }) {
  const typed = useTypewriter(TAGLINE);
  return (
    <div className="relative flex min-h-dvh flex-col items-center justify-center overflow-hidden bg-background px-4 py-10 text-foreground">
      {/* Background: grid + scanline + floating glows */}
      <div className="absolute inset-0 bg-grid bg-radial-fade" aria-hidden />
      <div className="absolute inset-0 overflow-hidden" aria-hidden>
        <div className="absolute inset-x-0 top-0 h-full animate-scan bg-gradient-to-b from-transparent via-primary/10 to-transparent" />
      </div>
      <div className="absolute inset-x-0 top-0 flex justify-center" aria-hidden>
        <div className="h-48 w-[60%] rounded-full bg-primary/10 blur-3xl animate-float" />
      </div>
      <div className="absolute inset-x-0 bottom-0 flex justify-center" aria-hidden>
        <div className="h-40 w-[70%] rounded-full bg-primary/5 blur-3xl" />
      </div>

      <div className="relative flex w-full max-w-3xl flex-col items-center gap-6 text-center">
        <div className="flex items-center gap-2 animate-fade-in-up">
          <Terminal className="h-5 w-5 text-primary" />
          <Badge variant="outline" className="gap-1.5 text-[10px]">
            <span className="h-1.5 w-1.5 rounded-full bg-primary animate-pulse" />
            v{__APP_VERSION__} beta
          </Badge>
        </div>

        <h1
          className="text-4xl font-semibold leading-tight tracking-tight md:text-6xl animate-fade-in-up"
          style={{ animationDelay: "120ms" }}
        >
          <span className="text-gradient-primary">NetAttack</span>
          <span className="text-foreground">AI</span>
          <span className="text-primary/40">.</span>
        </h1>

        <p
          className="max-w-2xl text-base text-muted-foreground md:text-lg animate-fade-in-up"
          style={{ animationDelay: "240ms" }}
        >
          {typed}
          <span
            className="ml-0.5 inline-block h-[1.1em] w-[2px] translate-y-[0.2em] bg-primary animate-typing-caret"
            aria-hidden
          />
        </p>

        <div className="w-full max-w-xl animate-fade-in-up" style={{ animationDelay: "360ms" }}>
          <KillChain />
        </div>

        <div
          className="flex flex-wrap items-center justify-center gap-3 animate-fade-in-up"
          style={{ animationDelay: "480ms" }}
        >
          <Button size="lg" className="gap-1.5 glow-primary-strong" onClick={onStart}>
            <Compass className="h-4 w-4" />
            Product tour
          </Button>
          <Button size="lg" variant="outline" onClick={onSkip}>
            Continue to console
          </Button>
        </div>

        <p
          className="flex items-center gap-1.5 text-[11px] text-muted-foreground animate-fade-in-up"
          style={{ animationDelay: "600ms" }}
        >
          <ShieldCheck className="h-3.5 w-3.5 text-primary/60" />
          Run only against assets you own or are explicitly authorized to test. Loopback only.
        </p>
      </div>
    </div>
  );
}

function Tour({ onExit }: { onExit: () => void }) {
  const navigate = useNavigate();
  const [index, setIndex] = useState(0);
  const containerRef = useRef<HTMLDivElement>(null);
  const step = STEPS[index];
  const isLast = index === STEPS.length - 1;

  const go = (d: number) =>
    setIndex((i) => Math.min(STEPS.length - 1, Math.max(0, i + d)));

  useEffect(() => {
    containerRef.current?.focus();
  }, []);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const t = e.target as HTMLElement | null;
      if (t && (t.tagName === "INPUT" || t.tagName === "TEXTAREA")) return;
      if (e.key === "ArrowRight") {
        e.preventDefault();
        go(1);
      } else if (e.key === "ArrowLeft") {
        e.preventDefault();
        go(-1);
      } else if (e.key === "Escape") {
        e.preventDefault();
        onExit();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onExit]);

  const onNext = () => {
    if (isLast) {
      navigate("/runs/new");
      onExit();
    } else {
      go(1);
    }
  };

  return (
    <div className="relative flex min-h-dvh flex-col overflow-hidden bg-background text-foreground">
      <div className="absolute inset-0 bg-grid-sm bg-radial-fade" aria-hidden />
      <div className="relative mx-auto flex w-full max-w-5xl flex-1 flex-col px-4 py-6 md:px-8">
        <header className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Terminal className="h-4 w-4 text-primary" />
            <span className="text-sm font-semibold">
              <span className="text-gradient-primary">NetAttack</span>
              <span className="text-foreground">AI</span>
            </span>
            <span className="text-[10px] uppercase tracking-wide text-muted-foreground">Product Tour</span>
          </div>
          <Button variant="ghost" size="sm" className="gap-1.5" onClick={onExit}>
            <X className="h-4 w-4" />
            Exit tour
          </Button>
        </header>

        <div
          ref={containerRef}
          tabIndex={-1}
          className="grid flex-1 items-center gap-6 py-6 outline-none lg:grid-cols-2"
        >
          <ConsoleMockup step={step} />
          <div key={step.id} className="flex flex-col gap-4 animate-fade-in-up">
            <div className="flex items-center gap-2 text-xs text-muted-foreground">
              <span className="font-mono tabular-nums">
                {String(index + 1).padStart(2, "0")} / {String(STEPS.length).padStart(2, "0")}
              </span>
              <span className="h-px flex-1 bg-border" />
              <span className="uppercase tracking-wide">{step.eyebrow}</span>
            </div>
            <h2 className="text-2xl font-semibold leading-tight tracking-tight md:text-3xl">
              {step.title}
            </h2>
            <p className="text-sm leading-relaxed text-muted-foreground md:text-base">
              {step.body}
            </p>
            <div className="flex items-center gap-2 pt-2">
              <Button
                variant="outline"
                size="sm"
                className="gap-1.5"
                onClick={() => go(-1)}
                disabled={index === 0}
              >
                <ArrowLeft className="h-4 w-4" />
                Back
              </Button>
              <Button size="sm" className="gap-1.5 glow-primary" onClick={onNext}>
                {isLast ? "Create first run" : "Next"}
                <ArrowRight className="h-4 w-4" />
              </Button>
            </div>
          </div>
        </div>

        <footer className="flex items-center justify-center gap-1.5 pb-4">
          {STEPS.map((s, i) => (
            <button
              key={s.id}
              type="button"
              aria-label={`Go to step ${i + 1}: ${s.title}`}
              aria-current={i === index ? "step" : undefined}
              onClick={() => setIndex(i)}
              className={cn(
                "h-1.5 rounded-full transition-all",
                i === index
                  ? "w-6 bg-primary"
                  : "w-1.5 bg-muted-foreground/30 hover:bg-muted-foreground/50",
              )}
            />
          ))}
        </footer>
      </div>
    </div>
  );
}

function useTypewriter(text: string, speed = 28, startDelay = 400) {
  const reduced = useMemo(() => {
    if (typeof window === "undefined") return true;
    return window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  }, []);
  const [count, setCount] = useState(() => (reduced ? text.length : 0));

  useEffect(() => {
    if (reduced) return;
    let interval: number | undefined;
    const timeout = window.setTimeout(() => {
      interval = window.setInterval(() => {
        setCount((c) => {
          if (c >= text.length) {
            if (interval) window.clearInterval(interval);
            return c;
          }
          return c + 1;
        });
      }, speed);
    }, startDelay);
    return () => {
      window.clearTimeout(timeout);
      if (interval) window.clearInterval(interval);
    };
  }, [text, speed, startDelay, reduced]);

  return text.slice(0, count);
}
