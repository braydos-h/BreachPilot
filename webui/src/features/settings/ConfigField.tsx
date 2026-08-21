// Renders one config field as a labeled row with the right control for its
// type: boolean → switch, list → tag editor, dict → collapsible JSON, int →
// number input, string → select / password / text. Friendly labels come from
// SETTING_META; unknown fields fall back to their raw `section.field` key.

import { useEffect, useRef, useState } from "react";
import { ChevronDown, ChevronRight, Eye, EyeOff, X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Switch } from "@/components/ui/switch";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { SettingRow } from "./SettingRow";
import { getSettingMeta, isKnownSetting } from "./settingMeta";
import { REDACTED, safeStringify } from "./useSettingsDraft";

interface ConfigFieldProps {
  section: string;
  field: string;
  value: unknown;
  defaultValue: unknown;
  /** Resolved enumerated values (from meta.options, already draft-aware). */
  options?: string[];
  onChange: (next: unknown) => void;
}

const CONTROL_W = "w-full sm:w-56";

export function ConfigField({ section, field, value, defaultValue, options, onChange }: ConfigFieldProps) {
  const meta = getSettingMeta(section, field);
  const known = isKnownSetting(section, field);
  const label = meta?.label ?? `${section}.${field}`;
  const isRedacted = typeof value === "string" && value === REDACTED;
  const type = inferType(defaultValue, value);
  const fieldId = `cfg-${section}-${field}`.replace(/[^a-zA-Z0-9-]/g, "-");

  if (type === "boolean") {
    return (
      <SettingRow id={`setting-${section}-${field}`} label={label} description={meta?.description} rawKey={known ? `${section}.${field}` : undefined} htmlFor={fieldId}>
        <Switch
          id={fieldId}
          checked={isRedacted ? false : Boolean(value)}
          disabled={isRedacted}
          onCheckedChange={onChange}
          aria-label={label}
        />
      </SettingRow>
    );
  }

  if (type === "list") {
    return (
      <SettingRow id={`setting-${section}-${field}`} label={label} description={meta?.description} rawKey={known ? `${section}.${field}` : undefined}>
        {isRedacted ? (
          <Input value={REDACTED} disabled className={CONTROL_W} aria-label={label} />
        ) : (
          <TagListEditor value={Array.isArray(value) ? value : []} onChange={onChange} ariaLabel={label} />
        )}
      </SettingRow>
    );
  }

  if (type === "dict") {
    return (
      <DictEditor
        id={`setting-${section}-${field}`}
        label={label}
        description={meta?.description}
        rawKey={known ? `${section}.${field}` : undefined}
        value={value}
        isRedacted={isRedacted}
        onChange={onChange}
      />
    );
  }

  if (type === "int") {
    return (
      <SettingRow id={`setting-${section}-${field}`} label={label} description={meta?.description} rawKey={known ? `${section}.${field}` : undefined} htmlFor={fieldId}>
        <Input
          id={fieldId}
          type="number"
          value={isRedacted ? REDACTED : String(value ?? "")}
          onChange={(e) => onChange(e.target.value === "" ? 0 : Number(e.target.value))}
          disabled={isRedacted}
          className={CONTROL_W}
          aria-label={label}
        />
      </SettingRow>
    );
  }

  // string
  if (options && options.length > 0 && !isRedacted) {
    const current = String(value ?? "");
    const all = options.includes(current) ? options : [current, ...options];
    return (
      <SettingRow id={`setting-${section}-${field}`} label={label} description={meta?.description} rawKey={known ? `${section}.${field}` : undefined} htmlFor={fieldId}>
        <Select value={current} onValueChange={onChange}>
          <SelectTrigger id={fieldId} className={CONTROL_W} aria-label={label}>
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {all.map((opt) => (
              <SelectItem key={opt} value={opt}>
                {opt}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </SettingRow>
    );
  }

  if (meta?.secret) {
    return (
      <SettingRow id={`setting-${section}-${field}`} label={label} description={meta?.description} rawKey={known ? `${section}.${field}` : undefined} htmlFor={fieldId}>
        <SecretInput
          id={fieldId}
          value={isRedacted ? REDACTED : String(value ?? "")}
          disabled={isRedacted}
          placeholder={meta.placeholder}
          onChange={onChange}
          className={CONTROL_W}
          ariaLabel={label}
        />
      </SettingRow>
    );
  }

  return (
    <SettingRow id={`setting-${section}-${field}`} label={label} description={meta?.description} rawKey={known ? `${section}.${field}` : undefined} htmlFor={fieldId}>
      <Input
        id={fieldId}
        value={isRedacted ? REDACTED : String(value ?? "")}
        onChange={(e) => onChange(e.target.value)}
        disabled={isRedacted}
        placeholder={meta?.placeholder}
        className={CONTROL_W}
        aria-label={label}
      />
    </SettingRow>
  );
}

function inferType(defaultValue: unknown, value: unknown): "boolean" | "int" | "list" | "dict" | "string" {
  if (typeof value === "boolean") return "boolean";
  if (typeof defaultValue === "boolean") return "boolean";
  if (Array.isArray(value) || Array.isArray(defaultValue)) return "list";
  if (value !== null && typeof value === "object") return "dict";
  if (defaultValue !== null && typeof defaultValue === "object") return "dict";
  if (typeof value === "number" || typeof defaultValue === "number") return "int";
  return "string";
}

/** Chip-style list editor: existing items as removable tags, an input + Add
 *  button for new ones. Enter also adds. */
function TagListEditor({
  value,
  onChange,
  ariaLabel,
}: {
  value: unknown[];
  onChange: (next: unknown) => void;
  ariaLabel: string;
}) {
  const [input, setInput] = useState("");
  const items = value.map((i) => String(i));

  const add = () => {
    const v = input.trim();
    if (!v) return;
    onChange([...items, v]);
    setInput("");
  };

  return (
    <div className="w-full space-y-1.5 sm:w-72">
      <div className="flex flex-wrap gap-1.5" aria-label={ariaLabel}>
        {items.length === 0 && <span className="text-xs text-muted-foreground">None</span>}
        {items.map((item) => (
          <span
            key={item}
            className="inline-flex items-center gap-1 rounded-md border bg-muted/40 px-2 py-0.5 text-xs"
          >
            {item}
            <button
              type="button"
              onClick={() => onChange(items.filter((i) => i !== item))}
              aria-label={`Remove ${item}`}
              className="text-muted-foreground transition-colors hover:text-destructive"
            >
              <X className="h-3 w-3" />
            </button>
          </span>
        ))}
      </div>
      <div className="flex gap-1.5">
        <Input
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") {
              e.preventDefault();
              add();
            }
          }}
          placeholder="Add item"
          className="h-8 text-xs"
          aria-label={`Add to ${ariaLabel}`}
        />
        <Button type="button" size="sm" variant="outline" onClick={add} disabled={!input.trim()}>
          Add
        </Button>
      </div>
    </div>
  );
}

/** Dict field: a compact "N keys" toggle that expands into a JSON textarea.
 *  The JSON stays hidden until the operator explicitly opens it. */
function DictEditor({
  id,
  label,
  description,
  rawKey,
  value,
  isRedacted,
  onChange,
}: {
  id?: string;
  label: string;
  description?: string;
  rawKey?: string;
  value: unknown;
  isRedacted: boolean;
  onChange: (next: unknown) => void;
}) {
  const [open, setOpen] = useState(false);
  const [text, setText] = useState(safeStringify(value ?? {}));
  const [invalid, setInvalid] = useState(false);
  const dirtyRef = useRef(false);
  const serialized = safeStringify(value ?? {});
  const keyCount = value && typeof value === "object" ? Object.keys(value as Record<string, unknown>).length : 0;

  useEffect(() => {
    if (dirtyRef.current) return;
    setText(serialized);
    setInvalid(false);
  }, [serialized]);

  return (
    <div id={id} className="py-3">
      <div className="flex items-center justify-between gap-3">
        <div className="min-w-0">
          <div className="flex items-center gap-1.5">
            <Label className="text-sm font-medium leading-snug">{label}</Label>
            {rawKey && <code className="text-[10px] text-muted-foreground/70">{rawKey}</code>}
          </div>
          {description && <p className="mt-0.5 text-xs leading-relaxed text-muted-foreground">{description}</p>}
        </div>
        <Button
          type="button"
          variant="outline"
          size="sm"
          onClick={() => setOpen((v) => !v)}
          disabled={isRedacted}
          aria-expanded={open}
          className="shrink-0"
        >
          {open ? <ChevronDown className="h-3.5 w-3.5" /> : <ChevronRight className="h-3.5 w-3.5" />}
          {isRedacted ? "Redacted" : open ? "Hide" : `Show ${keyCount} ${keyCount === 1 ? "key" : "keys"}`}
        </Button>
      </div>
      {open && (
        <div className="mt-2 space-y-1.5">
          <Textarea
            value={text}
            onChange={(e) => {
              dirtyRef.current = true;
              setText(e.target.value);
              try {
                onChange(JSON.parse(e.target.value));
                setInvalid(false);
              } catch {
                setInvalid(true);
              }
            }}
            disabled={isRedacted}
            aria-invalid={invalid}
            className="min-h-[6rem] font-mono text-xs"
            aria-label={label}
          />
          {invalid && <p className="text-xs text-destructive">Enter valid JSON before saving.</p>}
        </div>
      )}
    </div>
  );
}

/** Password input with a reveal toggle. */
function SecretInput({
  id,
  value,
  disabled,
  placeholder,
  onChange,
  className,
  ariaLabel,
}: {
  id: string;
  value: string;
  disabled: boolean;
  placeholder?: string;
  onChange: (next: unknown) => void;
  className?: string;
  ariaLabel: string;
}) {
  const [show, setShow] = useState(false);
  return (
    <div className={className}>
      <div className="relative">
        <Input
          id={id}
          type={show ? "text" : "password"}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          disabled={disabled}
          placeholder={placeholder}
          className="pr-8"
          aria-label={ariaLabel}
        />
        <button
          type="button"
          onClick={() => setShow((v) => !v)}
          aria-label={show ? "Hide value" : "Show value"}
          className="absolute right-2 top-1/2 -translate-y-1/2 text-muted-foreground transition-colors hover:text-foreground"
        >
          {show ? <EyeOff className="h-3.5 w-3.5" /> : <Eye className="h-3.5 w-3.5" />}
        </button>
      </div>
    </div>
  );
}
