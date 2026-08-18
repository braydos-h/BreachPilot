import { useCallback, useEffect, useState } from "react";
import { Check, Copy } from "lucide-react";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

interface CopyButtonProps {
  value: string;
  label?: string;
  className?: string;
  size?: "sm" | "default" | "icon";
}

export function CopyButton({ value, label = "Copy", className, size = "sm" }: CopyButtonProps) {
  const [copied, setCopied] = useState(false);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    if (!copied && !failed) return;
    const timer = setTimeout(() => {
      setCopied(false);
      setFailed(false);
    }, 2000);
    return () => clearTimeout(timer);
  }, [copied, failed]);

  const onClick = useCallback(async () => {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
    } catch {
      const el = document.createElement("textarea");
      el.value = value;
      el.style.position = "fixed";
      el.style.opacity = "0";
      document.body.appendChild(el);
      el.select();
      try {
        document.execCommand("copy");
        setCopied(true);
      } catch {
        setFailed(true);
      }
      document.body.removeChild(el);
    }
  }, [value]);

  return (
    <Button
      type="button"
      variant="outline"
      size={size === "icon" ? "icon" : size}
      className={cn("gap-1.5", className)}
      onClick={onClick}
      aria-label={copied ? "Copied" : failed ? "Copy failed" : label}
    >
      {copied ? <Check className="h-3.5 w-3.5" /> : <Copy className="h-3.5 w-3.5" />}
      {size !== "icon" && <span>{copied ? "Copied" : failed ? "Copy failed" : label}</span>}
    </Button>
  );
}