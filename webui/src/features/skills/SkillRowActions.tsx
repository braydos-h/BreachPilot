import { useState } from "react";
import { Check, MoreHorizontal, ShieldAlert, ShieldCheck, Trash2, Zap } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { Separator } from "@/components/ui/separator";
import type { SkillState } from "./skillsConfig";

export function SkillRowActions({
  state,
  onEnable,
  onAuto,
  onBlock,
  onDelete,
  disabled,
}: {
  state: SkillState;
  onEnable: () => void;
  onAuto: () => void;
  onBlock: () => void;
  onDelete: () => void;
  disabled?: boolean;
}) {
  const [open, setOpen] = useState(false);
  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <Button variant="ghost" size="sm" className="h-6 w-6 p-0" disabled={disabled} aria-label="Skill actions">
          <MoreHorizontal className="h-3.5 w-3.5" />
        </Button>
      </PopoverTrigger>
      <PopoverContent align="end" className="w-44 p-1">
        <div className="p-1">
          <div className="px-2 py-1 text-[11px] font-semibold uppercase tracking-wide text-muted-foreground">State</div>
          <button
            type="button"
            disabled={disabled || state === "enabled"}
            onClick={() => {
              onEnable();
              setOpen(false);
            }}
            className="flex w-full items-center gap-2 rounded-sm px-2 py-1.5 text-xs hover:bg-accent disabled:opacity-50"
          >
            <ShieldCheck className="h-3.5 w-3.5 text-emerald-500" /> Enable{" "}
            {state === "enabled" && <Check className="ml-auto h-3 w-3" />}
          </button>
          <button
            type="button"
            disabled={disabled || state === "auto"}
            onClick={() => {
              onAuto();
              setOpen(false);
            }}
            className="flex w-full items-center gap-2 rounded-sm px-2 py-1.5 text-xs hover:bg-accent disabled:opacity-50"
          >
            <Zap className="h-3.5 w-3.5 text-zinc-500" /> Set to Auto{" "}
            {state === "auto" && <Check className="ml-auto h-3 w-3" />}
          </button>
          <button
            type="button"
            disabled={disabled || state === "blocked"}
            onClick={() => {
              onBlock();
              setOpen(false);
            }}
            className="flex w-full items-center gap-2 rounded-sm px-2 py-1.5 text-xs hover:bg-accent disabled:opacity-50"
          >
            <ShieldAlert className="h-3.5 w-3.5 text-red-500" /> Block{" "}
            {state === "blocked" && <Check className="ml-auto h-3 w-3" />}
          </button>
          <Separator className="my-1" />
          <button
            type="button"
            disabled={disabled}
            onClick={() => {
              onDelete();
              setOpen(false);
            }}
            className="flex w-full items-center gap-2 rounded-sm px-2 py-1.5 text-xs text-destructive hover:bg-destructive/10"
          >
            <Trash2 className="h-3.5 w-3.5" /> Delete
          </button>
        </div>
      </PopoverContent>
    </Popover>
  );
}
