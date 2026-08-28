import { cn } from "@/lib/utils";
import { Checkbox } from "@/components/ui/checkbox";
import { Label } from "@/components/ui/label";

interface SegmentedControlProps {
  value: string;
  onChange: (value: string) => void;
  options: Array<{ value: string; label: string }>;
}

export function SegmentedControl({ value, onChange, options }: SegmentedControlProps) {
  return (
    <div className="inline-flex h-9 items-center rounded-md border bg-muted/40 p-0.5" role="radiogroup">
      {options.map((opt) => (
        <button
          key={opt.value}
          type="button"
          role="radio"
          aria-checked={value === opt.value}
          onClick={() => onChange(opt.value)}
          className={cn(
            "h-8 rounded px-3 text-sm transition-colors",
            value === opt.value
              ? "bg-background text-foreground shadow"
              : "text-muted-foreground hover:text-foreground",
          )}
        >
          {opt.label}
        </button>
      ))}
    </div>
  );
}

interface TriStateToggleProps {
  value: boolean | null;
  onChange: (value: boolean | null) => void;
  labels: { true: string; false: string; null: string };
}

export function TriStateToggle({ value, onChange, labels }: TriStateToggleProps) {
  return (
    <SegmentedControl
      value={String(value)}
      onChange={(v) => onChange(v === "true" ? true : v === "false" ? false : null)}
      options={[
        { value: "true", label: labels.true },
        { value: "false", label: labels.false },
        { value: "null", label: labels.null },
      ]}
    />
  );
}

interface SkillMultiSelectProps {
  label: string;
  skills: string[];
  selected: string[];
  onChange: (next: string[]) => void;
}

export function SkillMultiSelect({ label, skills, selected, onChange }: SkillMultiSelectProps) {
  const toggle = (name: string) => {
    onChange(selected.includes(name) ? selected.filter((n) => n !== name) : [...selected, name]);
  };
  return (
    <div className="space-y-1.5">
      <Label className="text-xs">{label}</Label>
      <div className="max-h-40 overflow-y-auto rounded-md border p-2 scrollbar-thin">
        {skills.length === 0 ? (
          <p className="text-xs text-muted-foreground">No skills available.</p>
        ) : (
          <ul className="space-y-1">
            {skills.map((name) => (
              <li key={name}>
                <Label className="flex cursor-pointer items-center gap-2 text-xs">
                  <Checkbox checked={selected.includes(name)} onCheckedChange={() => toggle(name)} />
                  <span className="font-mono">{name}</span>
                </Label>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}