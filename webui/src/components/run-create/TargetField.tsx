import { useId, useState } from "react";
import { Check, Crosshair } from "lucide-react";
import { cn } from "@/lib/utils";
import { isValidTarget } from "@/lib/targetValidation";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

interface TargetFieldProps {
  value: string;
  onChange: (value: string) => void;
  autoFocus?: boolean;
}

/** Large, primary target input. Validation mirrors the backend's syntax rules
 *  via isValidTarget(); the state stays neutral while empty, turns subtly green
 *  when valid, and only goes fully red after the field has been touched. */
export function TargetField({ value, onChange, autoFocus }: TargetFieldProps) {
  const id = useId();
  const [touched, setTouched] = useState(false);
  const trimmed = value.trim();
  const state = !trimmed ? "neutral" : isValidTarget(trimmed) ? "valid" : "invalid";

  return (
    <div className="space-y-2">
      <div className="flex items-baseline justify-between gap-2">
        <Label htmlFor={id} className="text-base font-semibold">
          Target
        </Label>
        {state === "valid" && (
          <span className="inline-flex items-center gap-1 text-xs text-emerald-400">
            <Check className="h-3.5 w-3.5" aria-hidden /> Valid target
          </span>
        )}
      </div>
      <div className="relative">
        <Crosshair
          className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground"
          aria-hidden
        />
        <Input
          id={id}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          onBlur={() => setTouched(true)}
          placeholder="10.10.10.25"
          autoFocus={autoFocus}
          autoComplete="off"
          spellCheck={false}
          aria-invalid={state === "invalid" && touched ? true : undefined}
          className={cn(
            "h-12 pl-9 pr-10 text-base",
            state === "valid" && "border-emerald-500/40 focus-visible:ring-emerald-500/25",
            state === "invalid" && "border-destructive/50 focus-visible:ring-destructive/30",
          )}
        />
        {state === "valid" && (
          <Check
            className="pointer-events-none absolute right-3 top-1/2 h-4 w-4 -translate-y-1/2 text-emerald-400"
            aria-hidden
          />
        )}
      </div>
      <p className="text-xs text-muted-foreground">
        IPv4, IPv6, or domain name. Only scan systems you own or are explicitly authorized to test.
      </p>
      {state === "invalid" && (
        <p className={cn("text-xs", touched ? "text-destructive" : "text-amber-400")} role="alert">
          Enter a valid IPv4, IPv6 address or domain name.
        </p>
      )}
    </div>
  );
}
