export type HelpSection = "start" | "lifecycle" | "permissions" | "directory" | "workflows" | "troubleshooting" | "faq" | "docs";

export type HelpTopic = {
  id: string;
  title: string;
  description: string;
  keywords: string[];
  section: HelpSection;
  anchor: string;
  route?: string;
  href?: string;
};

export type QuickStartCard = {
  id: string;
  title: string;
  description: string;
  icon: string;
  steps: string[];
  cta?: { label: string; to: string; external?: boolean };
  keywords: string[];
};

export type LifecycleStage = {
  id: string;
  label: string;
  shortLabel: string;
  doing: string;
  operator: string;
  output: string;
  hint: string;
};

export type PermissionRow = {
  criteria: string;
  readOnly: string;
  approve: string;
  fullAccess: string;
};

export type DirectoryItem = {
  id: string;
  label: string;
  desc: string;
  icon: string;
  to?: string;
  external?: string;
  note?: string;
};

export type Workflow = {
  id: string;
  title: string;
  desc: string;
  steps: string[];
  icon: string;
};

export type TroubleshootEntry = {
  id: string;
  symptom: string;
  check: string;
  next: string;
  keywords: string[];
};

export type FAQEntry = {
  id: string;
  q: string;
  a: string;
  keywords: string[];
};

export type DocCategory = "Getting started" | "Operating" | "Safety & permissions" | "Models & providers" | "Development" | "Troubleshooting";
export type DocLink = {
  title: string;
  desc: string;
  href: string;
  category: DocCategory;
  keywords: string[];
};

export const QUICK_START_CARDS: QuickStartCard[] = [
  {
    id: "first-run",
    title: "Start your first run",
    description: "Launch a recon or attack assessment against an authorized target.",
    icon: "Rocket",
    steps: ["Choose target", "Pick mode & goal", "Review permissions", "Launch & approve"],
    cta: { label: "New run", to: "/runs/new" },
    keywords: ["new run", "target", "mode", "goal", "wizard", "launch"],
  },
  {
    id: "live-run",
    title: "Understand a live run",
    description: "Follow events, decisions and recon as the agent works.",
    icon: "Activity",
    steps: ["Events stream", "Decisions", "Recon & attack path", "Summary & advisory"],
    cta: { label: "View sessions", to: "/sessions" },
    keywords: ["events", "decisions", "recon", "attack path", "summary", "tools", "advisory", "audit", "swarm", "campaign"],
  },
  {
    id: "evidence",
    title: "Find collected evidence",
    description: "Locate artifacts, loot, credentials, audit and the attack graph.",
    icon: "FolderSearch",
    steps: ["Artifacts & workspace", "Loot & credentials", "Attack graph", "Audit & logs"],
    cta: undefined,
    keywords: ["artifacts", "workspace", "audit", "logs", "loot", "credentials", "attack graph", "evidence"],
  },
  {
    id: "configure",
    title: "Configure BreachPilot",
    description: "Providers, run defaults, integrations and advanced settings.",
    icon: "Settings",
    steps: ["Provider & model", "Run budgets", "Integrations", "System diagnostics"],
    cta: { label: "Open settings", to: "/system" },
    keywords: ["settings", "config", "providers", "models", "integrations", "features", "advanced"],
  },
];

export const LIFECYCLE_STAGES: LifecycleStage[] = [
  {
    id: "target",
    label: "Target",
    shortLabel: "Target",
    doing: "Validates IP/domain, resolves DNS, checks target-IP allowlist.",
    operator: "Enter target & confirm it is authorized. Allowlist must include it.",
    output: "Run header · preview card · target_ip / original_target",
    hint: "Domain targets auto-resolve; domain + IP both threaded to the MCP server.",
  },
  {
    id: "recon",
    label: "Recon",
    shortLabel: "Recon",
    doing: "Nmap scan, service fingerprinting, OS verdict, CVE/KEV lookup.",
    operator: "Review recon assessment — open ports, services, CVEs, risk score.",
    output: "Recon tab · recon_assessment.json · goal suggestions",
    hint: "Read-only, scope-gated. Always safe.",
  },
  {
    id: "decision",
    label: "Decision",
    shortLabel: "Goal",
    doing: "Ranks preset goals by exploit likelihood + operator risk profile.",
    operator: "Pick a goal from the ranked list or provide a custom goal.",
    output: "Goal suggestions card · DecisionCard goal_select",
    hint: "Goal availability depends on authorization profile.",
  },
  {
    id: "attack",
    label: "Attack",
    shortLabel: "Attack",
    doing: "Selects applicable attack modules, runs MCP tools via sandbox, generates scripts.",
    operator: "Monitor events & tool calls; approve destructive confirmations when prompted.",
    output: "Events · Tools & Advisory · tool_result, exploit_audit.jsonl",
    hint: "Allowlist enforced on every tool call.",
  },
  {
    id: "evidence",
    label: "Evidence",
    shortLabel: "Evidence",
    doing: "Collects artifacts, loot, credentials and attack-graph nodes.",
    operator: "Inspect Artifacts / Loot / Attack Graph pages for proof and reuse.",
    output: "Artifacts page · Loot page · /graph · workspace files",
    hint: "Passwords masked; reveal per-credential is audited.",
  },
  {
    id: "report",
    label: "Report",
    shortLabel: "Report",
    doing: "Classifies outcome, links evidence, builds audit chain & summary.",
    operator: "Review Summary → Attack Path → Advisory → Audit for the verdict.",
    output: "Summary tab · session_summary.md · reports/<run_id>/",
    hint: "Audit chain is hash-chained and verified in the UI.",
  },
];

export const PERMISSION_ROWS: PermissionRow[] = [
  { criteria: "Run start (start_confirm)", readOnly: "Waits", approve: "Auto yes", fullAccess: "Auto yes" },
  { criteria: "Safe tool approvals", readOnly: "Waits", approve: "Auto yes", fullAccess: "Auto yes" },
  { criteria: "Destructive confirmations", readOnly: "Waits", approve: "Waits", fullAccess: "Auto required_text" },
  { criteria: "Goal selection", readOnly: "Waits", approve: "Waits", fullAccess: "Waits" },
  { criteria: "Campaign checkpoint", readOnly: "Waits", approve: "Waits", fullAccess: "Waits" },
  { criteria: "Operator load", readOnly: "Every decision", approve: "Only gated/destructive", fullAccess: "Goals & checkpoints only" },
  { criteria: "Recommended for", readOnly: "Learning · safest", approve: "Day-to-day operation", fullAccess: "Lab hosts you own" },
];

export const DIRECTORY_ITEMS: DirectoryItem[] = [
  { id: "sessions", label: "Runs / Sessions", desc: "Paginated run list, create, resume, delete. One active run at a time.", icon: "List", to: "/sessions" },
  { id: "goals", label: "Goals", desc: "Preset objectives grouped by risk (safe / gated / high). Compatibility checked.", icon: "Target", to: "/goals" },
  { id: "modules", label: "Attack Modules", desc: "Exploit recipes by family — web, SMB, SSH, AD, privesc, ICS/IoT, etc.", icon: "Crosshair", to: "/modules" },
  { id: "skills", label: "Skills", desc: "Advisory methodologies loaded as prompt context, never execution authority.", icon: "Sparkles", to: "/skills" },
  { id: "memory", label: "Memory", desc: "Semantic and attack memory: lessons, confidence, and retained facts.", icon: "Brain", to: "/memory" },
  { id: "stats", label: "Stats", desc: "Telemetry, token usage, model performance and recent activity.", icon: "BarChart3", to: "/stats" },
  { id: "graph", label: "Attack Graph", desc: "Interactive graph of findings, hosts, services and confirmed paths.", icon: "GitBranch", to: "/graph" },
  { id: "connections", label: "Connections", desc: "Active operator connections and their health.", icon: "PlugZap", to: "/connections" },
  { id: "benchmarks", label: "Benchmarks", desc: "Reproducible eval suites, verified success rate and regression checks.", icon: "FlaskConical", to: "/benchmarks" },
  { id: "system", label: "Settings / System", desc: "Providers, run defaults, integrations, features, diagnostics.", icon: "Settings", to: "/system" },
  { id: "artifacts", label: "Run Artifacts", desc: "Per-run files: reports, events.jsonl, enhanced_report.json. From the run header.", icon: "Files", note: "Inside a run" },
  { id: "loot", label: "Loot & Credentials", desc: "Captured loot and HMAC-signed credential store; reveal is audited.", icon: "KeyRound", note: "Inside a run" },
  { id: "audit", label: "Audit & Logs", desc: "Hash-chained audit trail and tail-view of mcp_exploit_server.log etc.", icon: "ScrollText", note: "Inside a run" },
];

export const WORKFLOWS: Workflow[] = [
  {
    id: "recon-only",
    title: "Recon only",
    desc: "Low-noise discovery and ranked goal suggestions — no exploitation.",
    icon: "ScanSearch",
    steps: [
      "Start new run → choose Recon path",
      "Enter an allowlisted target (IP or domain)",
      "Review discovered services, OS verdict and CVEs in the Recon tab",
      "Inspect ranked goal suggestions and the recon report artifact",
      "Export or continue to an attack run with a chosen goal",
    ],
  },
  {
    id: "authorized-attack",
    title: "Authorized attack run",
    desc: "Full exploitation against a lab host you own, with approvals.",
    icon: "ShieldCheck",
    steps: [
      "Add the target to exploit.allowed_targets (or enter via wizard — it persists automatically)",
      "Start new run → Attack mode → pick a goal and permission level",
      "Confirm the start_confirm gate (destructive runs require ALLOW <target>)",
      "Monitor the live Events stream and answer tool_approval / goal_select decisions",
      "Review Summary → Attack Path → Advisory → Artifacts → Audit for the verdict",
    ],
  },
  {
    id: "review-finished",
    title: "Review a finished run",
    desc: "Post-run evidence review without re-running anything.",
    icon: "ClipboardList",
    steps: [
      "Open Sessions → select a completed run",
      "Summary tab for outcome, workspace path and telemetry",
      "Attack Path for exploitation chains; Advisory for OPSEC and remediation",
      "Artifacts and Loot pages for files and captured credentials",
      "Audit tab to verify the hash chain; Logs for mcp_exploit_server.log",
    ],
  },
  {
    id: "troubleshoot-failed",
    title: "Troubleshoot a failed run",
    desc: "Diagnose why a run stopped early or produced no evidence.",
    icon: "Wrench",
    steps: [
      "Check the run state and outcome banner in the header",
      "Open Logs → mcp_exploit_server.log and session_error.log",
      "Verify audit chain validity and look for BLOCKED: allowlist messages",
      "Check System → provider health, Model reachability and config validity",
      "Re-run with corrected allowlist, provider key or model selection",
    ],
  },
];

export const TROUBLESHOOTING: TroubleshootEntry[] = [
  {
    id: "run-wont-start",
    symptom: "Run will not start — stays queued or immediately fails",
    check: "Run header error banner; Logs → mcp_exploit_server.log; python main.py --doctor",
    next: "Fix the reported config or provider error, then create a new run. Only one active run is allowed (409 while one is running).",
    keywords: ["run will not start", "queued", "failed", "409", "active run"],
  },
  {
    id: "provider-unavailable",
    symptom: "Provider unavailable — LLM calls fail or retry with 401/503",
    check: "System → Models: provider status badge and error line; GET /api/v1/providers. Verify OLLAMA_API_KEY / OPENCODE_GO_API_KEY.",
    next: "Set the missing key via --setup-api-keys or secr.json, or switch models.provider in config.yaml. Retry the run.",
    keywords: ["provider", "ollama", "chatgpt", "opencode", "401", "llm disconnected", "retry"],
  },
  {
    id: "target-rejected",
    symptom: "Target rejected — BLOCKED: not in allowlist",
    check: "Search tool results for \"is not in the explicit allowlist\"; check exploit.allowed_targets and EXPLOIT_TARGET env union.",
    next: "Add the IP/domain/CIDR/*.wildcard to config.yaml exploit.allowed_targets, or pass --target. Domains auto-authorize discovered subdomains via add_discovered_target.",
    keywords: ["allowlist", "target rejected", "blocked", "not in explicit allowlist", "cidr", "wildcard"],
  },
  {
    id: "no-module",
    symptom: "No attack module selected — agent loops without exploitation",
    check: "Recon tab: did any service/CVE match a module? Check Attack Modules page with a service/CVE search.",
    next: "Ensure recon discovered the expected service/CVE; the top 15 applicable modules are auto-tasked. Check find_modules scoring in docs/attack-modules.md.",
    keywords: ["no module", "applicability", "attack module", "find_modules"],
  },
  {
    id: "waiting-operator",
    symptom: "Run waiting for operator — pending decision badge is lit",
    check: "Right-column Pending decisions card; also Decisions tab on the run page.",
    next: "Answer goal_select / start_confirm / tool_approval. Permission mode approve/full_access auto-answers most of these — switch modes in the sidebar if needed.",
    keywords: ["waiting for operator", "pending decision", "goal_select", "tool_approval", "start_confirm"],
  },
  {
    id: "missing-loot",
    symptom: "Missing loot or credentials — Loot page is empty",
    check: "Check outcome summary and exploitation_chains; was access actually achieved? See Logs for credential-store writes.",
    next: "Not every run captures loot. Review the attack timeline and tool results to see where the chain stopped.",
    keywords: ["missing loot", "no credentials", "loot", "credential store"],
  },
  {
    id: "no-artifacts",
    symptom: "No artifacts — Artifacts tab is empty",
    check: "Wait for the run to reach completed/failed. Check Services vs Artifacts: artifacts appear after the agent writes reports/<run_id>/.",
    next: "If still empty after terminal state, check Logs → session_error.log for write failures or workspace permission errors.",
    keywords: ["no artifacts", "artifacts empty", "reports", "workspace"],
  },
  {
    id: "websocket",
    symptom: "Live updates frozen — events stop streaming",
    check: "Transport badge in the run header: WS / SSE / reconnecting / offline. Open browser devtools Network → WS.",
    next: "Use the reconnect action if available. Check daemon health at /health and token validity (401 closes WS with 4401).",
    keywords: ["websocket", "sse", "live updates", "transport", "reconnect", "4401"],
  },
  {
    id: "config-invalid",
    symptom: "Configuration invalid — config_valid check fails",
    check: "System → Config: validation errors. Run python main.py --doctor and read the config_valid line.",
    next: "Fix the reported key in config.yaml (type/range/unknown key). Re-validate with --doctor before starting a run.",
    keywords: ["config invalid", "config_valid", "yaml", "validation", "schema"],
  },
];

export const FAQ: FAQEntry[] = [
  {
    id: "what-goal",
    q: "What is a goal?",
    a: "A preset objective the agent drives toward (e.g. initial_access, enumerate-then-report). Goals are grouped by risk (safe / gated / high) and ranked by exploit likelihood after recon. Custom free-text goals are also allowed.",
    keywords: ["goal", "objective", "preset"],
  },
  {
    id: "what-module",
    q: "What is an attack module?",
    a: "A self-contained exploit recipe under tools/attack_modules/modules/. Each module declares target services, ports, CVEs and capability metadata (requires/produces), scores its applicability, and emits a script or command when selected.",
    keywords: ["attack module", "module", "family", "applicability"],
  },
  {
    id: "what-skill",
    q: "What is a skill?",
    a: "An advisory SKILL.md (frontmatter + markdown) that is rendered into the agent's prompt as context. Skills never grant execution authority — they only advise. Managed at /skills.",
    keywords: ["skill", "SKILL.md", "advisory", "methodology"],
  },
  {
    id: "what-memory",
    q: "What is attack memory?",
    a: "A per-target store of lessons and confidence signals built from prior runs. The agent recalls what worked on similar services and biases module selection. Viewable at /memory and inside swarm blackboard.",
    keywords: ["attack memory", "semantic memory", "lessons", "confidence"],
  },
  {
    id: "what-audit",
    q: "What is the audit trail?",
    a: "An append-only, SHA-256 hash-chained JSONL (exploit_audit.jsonl, one per target) recording every tool call, answer and policy verdict. The Audit tab verifies chain_valid; any tampering is surfaced immediately.",
    keywords: ["audit", "audit trail", "hash chain", "exploit_audit"],
  },
  {
    id: "what-allowlist",
    q: "What is the allowlist?",
    a: "The target-IP lock — the one attack-mode safety. Union of exploit.allowed_targets plus runtime envs EXPLOIT_TARGET / TARGET_IP / TARGET_DOMAIN / DISCOVERED_TARGETS. Every target-touching tool is gated by @require_allowlist; anything outside is refused with BLOCKED.",
    keywords: ["allowlist", "target lock", "allowed_targets", "require_allowlist"],
  },
  {
    id: "recon-vs-attack",
    q: "Difference between recon and attack?",
    a: "Recon is read-only and scope-gated (nmap + CVE lookup + report). Attack runs the full exploit loop — module selection, sandbox-contained tool execution, and evidence collection. Recon-first does recon, suggests goals, then asks the operator before proceeding.",
    keywords: ["recon", "attack", "recon-first", "read_only"],
  },
  {
    id: "artifacts-vs-loot",
    q: "Difference between artifacts and loot?",
    a: "Artifacts are run reports and files under reports/<run_id>/ and exploit_workspace/ (open via the Artifacts page). Loot is captured evidence (credential dumps, extracted data, exfiltrated artifacts) surfaced on the Loot page; credentials are separately hush-signed and reveal-audited.",
    keywords: ["artifacts", "loot", "reports", "workspace"],
  },
  {
    id: "what-requires-approval",
    q: "What requires operator approval?",
    a: "In read-only mode, everything. In approve mode, only destructive confirmations, goal selection and campaign checkpoints wait. In full_access, only goal selection and campaign checkpoints still wait — the allowlist still applies regardless of mode.",
    keywords: ["approval", "permission", "destructive", "goal_select", "campaign_next_step"],
  },
];

// Keep the original six links plus useful additions; all hrefs must exist in docs/.
export const DOC_LINKS: DocLink[] = [
  { title: "Getting Started", desc: "Setup, commands, and the local development loop.", href: "https://github.com/braydos-h/BreachPilot/blob/main/docs/getting-started.md", category: "Getting started", keywords: ["setup", "install", "commands"] },
  { title: "Tutorial", desc: "End-to-end operator walkthrough: recon-first, exploit, swarm and WebUI.", href: "https://github.com/braydos-h/BreachPilot/blob/main/docs/tutorial.md", category: "Getting started", keywords: ["tutorial", "walkthrough", "first run"] },
  { title: "CLI Reference", desc: "Every flag for main.py and cli.py, exit codes and example workflows.", href: "https://github.com/braydos-h/BreachPilot/blob/main/docs/cli-reference.md", category: "Getting started", keywords: ["cli", "flags", "args", "target"] },
  { title: "Config Reference", desc: "All config.yaml keys, defaults, and where each is consumed.", href: "https://github.com/braydos-h/BreachPilot/blob/main/docs/config-reference.md", category: "Getting started", keywords: ["config.yaml", "config", "validation"] },

  { title: "WebUI", desc: "This console — stack, pages, auth, real-time transport.", href: "https://github.com/braydos-h/BreachPilot/blob/main/docs/webui.md", category: "Operating", keywords: ["webui", "spa", "websocket", "pages"] },
  { title: "Runtime Flows", desc: "Flow A vs Flow B, run lifecycle and orchestration.", href: "https://github.com/braydos-h/BreachPilot/blob/main/docs/runtime-flows.md", category: "Operating", keywords: ["flow", "run lifecycle", "orchestrator"] },
  { title: "Architecture", desc: "System shape, entry points, and module map.", href: "https://github.com/braydos-h/BreachPilot/blob/main/docs/architecture.md", category: "Operating", keywords: ["architecture", "system", "modules"] },
  { title: "Run Service", desc: "Backend run lifecycle, decisions, events and the API daemon.", href: "https://github.com/braydos-h/BreachPilot/blob/main/docs/run-service.md", category: "Operating", keywords: ["run service", "api", "events"] },

  { title: "Safety Model", desc: "Scope checks, risk checks, permission modes and audit records.", href: "https://github.com/braydos-h/BreachPilot/blob/main/docs/safety-model.md", category: "Safety & permissions", keywords: ["safety", "scope", "risk", "permission"] },
  { title: "Sandbox", desc: "Disposable worker container, netns firewall and execution containment.", href: "https://github.com/braydos-h/BreachPilot/blob/main/docs/sandbox.md", category: "Safety & permissions", keywords: ["sandbox", "container", "isolation", "docker"] },

  { title: "Model Providers", desc: "Ollama cloud/local and the ChatGPT opt-in provider.", href: "https://github.com/braydos-h/BreachPilot/blob/main/docs/providers.md", category: "Models & providers", keywords: ["providers", "ollama", "chatgpt", "opencode"] },
  { title: "Provider Development", desc: "Recipe for adding a new LLM provider adapter.", href: "https://github.com/braydos-h/BreachPilot/blob/main/docs/provider-development.md", category: "Models & providers", keywords: ["provider development", "adapter", "registry"] },

  { title: "Attack Modules", desc: "The module registry, families and applicability scoring.", href: "https://github.com/braydos-h/BreachPilot/blob/main/docs/attack-modules.md", category: "Development", keywords: ["attack modules", "registry", "family"] },
  { title: "Skills", desc: "Runtime skill pipeline — selection, injection and feedback.", href: "https://github.com/braydos-h/BreachPilot/blob/main/docs/skills.md", category: "Development", keywords: ["skills", "pipeline", "injection"] },
  { title: "Skill Authoring", desc: "How to write a SKILL.md with frontmatter and methodology.", href: "https://github.com/braydos-h/BreachPilot/blob/main/docs/skill-authoring.md", category: "Development", keywords: ["skill authoring", "SKILL.md"] },
  { title: "MCP Tools", desc: "Exploit MCP tool families, sandbox funnel and registration.", href: "https://github.com/braydos-h/BreachPilot/blob/main/docs/mcp-tools.md", category: "Development", keywords: ["mcp", "tools", "audit"] },
  { title: "Plugin Development", desc: "Writing a trusted plugin that inherits the allowlist lock.", href: "https://github.com/braydos-h/BreachPilot/blob/main/docs/plugin-development.md", category: "Development", keywords: ["plugin", "extension"] },
  { title: "Testing Guide", desc: "Mocked test suite, coverage and conventions.", href: "https://github.com/braydos-h/BreachPilot/blob/main/docs/testing-guide.md", category: "Development", keywords: ["testing", "pytest", "coverage"] },

  { title: "Troubleshooting", desc: "Symptom → cause → check → fix.", href: "https://github.com/braydos-h/BreachPilot/blob/main/docs/troubleshooting.md", category: "Troubleshooting", keywords: ["troubleshooting", "symptom", "fix"] },
  { title: "Evaluation", desc: "Eval harness, graded benchmarks and regression gating.", href: "https://github.com/braydos-h/BreachPilot/blob/main/docs/evaluation.md", category: "Troubleshooting", keywords: ["evaluation", "benchmark", "eval"] },
  { title: "Benchmarks", desc: "Reproducible benchmark suite, report shapes and CI regression.", href: "https://github.com/braydos-h/BreachPilot/blob/main/docs/benchmarks.md", category: "Troubleshooting", keywords: ["benchmarks", "trials", "regression"] },
];

export const HELP_TOPICS: HelpTopic[] = [
  // start
  ...QUICK_START_CARDS.map((c) => ({
    id: `card-${c.id}`,
    title: c.title,
    description: c.description,
    keywords: c.keywords,
    section: "start" as HelpSection,
    anchor: "#start-here",
    route: c.cta?.to,
  })),
  // lifecycle
  ...LIFECYCLE_STAGES.map((s) => ({
    id: `lifecycle-${s.id}`,
    title: s.label,
    description: `${s.doing} ${s.operator}`,
    keywords: [s.label.toLowerCase(), s.doing.toLowerCase(), s.operator.toLowerCase(), s.output.toLowerCase()],
    section: "lifecycle" as HelpSection,
    anchor: "#lifecycle",
  })),
  // permissions
  { id: "perm-read_only", title: "Read-only mode", description: "Every operator decision waits for you. Nothing is auto-answered. Safest.", keywords: ["read-only", "read_only", "permission", "safest", "wait"], section: "permissions", anchor: "#permissions" },
  { id: "perm-approve", title: "Approve mode", description: "Non-destructive decisions auto-answered with yes. Destructive still waits.", keywords: ["approve", "permission", "non-destructive", "auto"], section: "permissions", anchor: "#permissions" },
  { id: "perm-full_access", title: "Full access mode", description: "All start_confirm and tool_approval auto-answered, including destructive via required_text. Goal selection still waits.", keywords: ["full access", "full_access", "permission", "destructive", "required_text"], section: "permissions", anchor: "#permissions" },
  { id: "perm-allowlist", title: "Target allowlist lock", description: "The one attack-mode safety. Applies in every permission mode — nothing escapes the allowlist.", keywords: ["allowlist", "target lock", "allowed_targets", "allowlist lock"], section: "permissions", anchor: "#permissions" },

  // directory
  ...DIRECTORY_ITEMS.map((d) => ({
    id: `dir-${d.id}`,
    title: d.label,
    description: d.desc,
    keywords: [d.label.toLowerCase(), d.desc.toLowerCase()],
    section: "directory" as HelpSection,
    anchor: "#directory",
    route: d.to,
  })),
  // workflows
  ...WORKFLOWS.map((w) => ({
    id: `workflow-${w.id}`,
    title: w.title,
    description: `${w.desc} ${w.steps.join(" ")}`,
    keywords: [w.title.toLowerCase(), w.desc.toLowerCase(), ...w.steps.join(" ").toLowerCase().split(/\s+/)],
    section: "workflows" as HelpSection,
    anchor: "#workflows",
  })),
  // troubleshooting
  ...TROUBLESHOOTING.map((t) => ({
    id: `trouble-${t.id}`,
    title: t.symptom,
    description: `${t.check} → ${t.next}`,
    keywords: t.keywords,
    section: "troubleshooting" as HelpSection,
    anchor: "#troubleshooting",
  })),
  // faq
  ...FAQ.map((f) => ({
    id: `faq-${f.id}`,
    title: f.q,
    description: f.a,
    keywords: f.keywords,
    section: "faq" as HelpSection,
    anchor: "#faq",
  })),
  // docs
  ...DOC_LINKS.map((d) => ({
    id: `doc-${d.title.toLowerCase().replace(/\s+/g, "-")}`,
    title: d.title,
    description: d.desc,
    keywords: [d.category.toLowerCase(), d.title.toLowerCase(), d.desc.toLowerCase(), ...d.keywords],
    section: "docs" as HelpSection,
    anchor: "#docs",
    href: d.href,
  })),
];

export const SECTION_META: Record<HelpSection, { label: string; anchor: string }> = {
  start: { label: "Start here", anchor: "#start-here" },
  lifecycle: { label: "Run lifecycle", anchor: "#lifecycle" },
  permissions: { label: "Permissions", anchor: "#permissions" },
  directory: { label: "Find a feature", anchor: "#directory" },
  workflows: { label: "Workflows", anchor: "#workflows" },
  troubleshooting: { label: "Troubleshooting", anchor: "#troubleshooting" },
  faq: { label: "FAQ", anchor: "#faq" },
  docs: { label: "Documentation", anchor: "#docs" },
};

export const DOC_CATEGORIES: DocCategory[] = ["Getting started", "Operating", "Safety & permissions", "Models & providers", "Development", "Troubleshooting"];
