---
name: experimental-skill-test
description: Placeholder for the maybe/ tier. Higher-risk or niche skills live here and are ignored unless skills.maybe_enabled is true. Replace this with a real experimental skill.
domain: experimentation
tags:
- experimental
- maybe
nist_csf: []
mitre_attack: []
---

# Experimental Skill (maybe/ tier)

## When to Use

This is a **placeholder** skill under `skills-to-add/maybe/`. Skills in this
directory are gated by `skills.maybe_enabled` (default `false`) — they are
excluded from selection, the catalog list, and the `load_runtime_skill` MCP
tool until an operator explicitly opts in.

## Workflow

Add real experimental or higher-risk methodology here. Until it is promoted
out of `maybe/`, it stays dormant and cannot be selected by the agent.

## Safety

Advisory only. Even when enabled, skills never change scope, permission,
approval, command-safety, or audit rules. Role-directive lines and tool-call
mimics in skill bodies are stripped by the sanitizer before any prompt
injection (see `tools/skill_registry.py::_sanitize_skill_body`).