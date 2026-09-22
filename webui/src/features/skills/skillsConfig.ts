import { ShieldAlert, ShieldCheck, Zap } from "lucide-react";

export interface SkillsConfig {
  enabled?: boolean;
  default_enabled?: string[];
  exclude_names?: string[];
  allow_model_lookup?: boolean;
  inject_startup_context?: boolean;
  roots?: string[];
}

export function readSkillsConfig(cfg: unknown): SkillsConfig {
  if (cfg && typeof cfg === "object") {
    const skills = (cfg as Record<string, unknown>).skills;
    if (skills && typeof skills === "object") {
      return skills as SkillsConfig;
    }
  }
  return {};
}

export type SkillState = "enabled" | "blocked" | "auto";

export function skillState(name: string, cfg: SkillsConfig): SkillState {
  if ((cfg.exclude_names ?? []).includes(name)) return "blocked";
  if ((cfg.default_enabled ?? []).includes(name)) return "enabled";
  return "auto";
}

export const STATE_META: Record<
  SkillState,
  { label: string; variant: "success" | "danger" | "muted"; dot: string; icon: typeof ShieldCheck }
> = {
  enabled: { label: "Enabled", variant: "success", dot: "bg-emerald-500", icon: ShieldCheck },
  blocked: { label: "Blocked", variant: "danger", dot: "bg-red-500", icon: ShieldAlert },
  auto: { label: "Auto", variant: "muted", dot: "bg-zinc-400", icon: Zap },
};

export function isValidUrl(v: string): boolean {
  try {
    const u = new URL(v);
    return u.protocol === "http:" || u.protocol === "https:";
  } catch {
    return false;
  }
}

export const SKILL_TEMPLATE = `---
name: my-skill-name
description: What this skill advises
tags:
  - example
  - methodology
domain: reconnaissance
subdomain: scanning
version: "0.1.0"
nist_csf:
  - PR.AC
mitre_attack:
  - T1595
references:
  - https://example.com/methodology
---

## When to use

Describe the trigger conditions for this skill.

## Methodology

Step-by-step guidance for the agent.

## References

- https://example.com
`;

export type StatusFilter = "all" | SkillState;
export type SortKey = "default" | "name" | "state";

export const STATUS_OPTIONS: Array<{ value: StatusFilter; label: string }> = [
  { value: "all", label: "All" },
  { value: "enabled", label: "Enabled" },
  { value: "auto", label: "Auto" },
  { value: "blocked", label: "Blocked" },
];
