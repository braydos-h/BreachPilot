// Tour step data for the welcome screen. Copy uses the project's exact
// terminology (runs, decisions, goals, modes, phases, permission modes,
// power-ups, skills, loot, artifacts, audit).

export type MockupKey =
  | "killchain"
  | "home"
  | "wizard"
  | "run"
  | "decisions"
  | "sessions"
  | "artifacts"
  | "skills"
  | "system"
  | "safety"
  | "cta";

export interface TourStep {
  id: string;
  eyebrow: string;
  title: string;
  body: string;
  mockup: MockupKey;
}

export const STEPS: TourStep[] = [
  {
    id: "what",
    eyebrow: "Overview",
    title: "Autonomous assessment platform, local-first",
    body: "BreachPilot is a local-first, AI-driven penetration testing and vulnerability research platform. It operates across the full kill chain — planning, reconnaissance, exploitation, verification, and reporting — against assets you own or are explicitly authorized to assess. Findings are evidence-backed with full auditability. Built on Ollama LLMs, the Model Context Protocol, and a 140-skill advisory knowledge base.",
    mockup: "killchain",
  },
  {
    id: "home",
    eyebrow: "Console",
    title: "Mission Control",
    body: "The Home dashboard provides run statistics, quick actions for Reconnaissance and Attack workflows, and a searchable history of recent sessions. Status and safety context are visible at all times.",
    mockup: "home",
  },
  {
    id: "wizard",
    eyebrow: "Runs",
    title: "Create a run in three steps",
    body: "The Run Wizard guides you through Settings, Target, and Review. Select an operating mode (recon or attack), a risk-classified goal (safe, gated, or high), and optional execution enhancements such as Swarm orchestration, Critic review, Reflection, Adaptive Exploits, and Multi-Model Consultation.",
    mockup: "wizard",
  },
  {
    id: "run",
    eyebrow: "Runs",
    title: "Observe execution in real time",
    body: "Live runs stream phase transitions (Starting, Recon, Enumeration, Vulnerability Research, Validation, Reporting), tool invocations, and progress telemetry. The phase tracker indicates the agent's current position in the assessment lifecycle.",
    mockup: "run",
  },
  {
    id: "decisions",
    eyebrow: "Control",
    title: "Operator approval remains authoritative",
    body: "Every operator decision — start_confirm, goal_select, tool_approval — requires explicit approval in Read-Only mode. Approve automatically handles non-destructive decisions; Full Access handles all decisions, including destructive confirmations. The target-IP allowlist is enforced in every mode.",
    mockup: "decisions",
  },
  {
    id: "sessions",
    eyebrow: "History",
    title: "Complete run history, searchable",
    body: "The Sessions view lists all runs with state, target, mode, goal, and model. Review completed assessments, regenerate titles, or remove runs as needed.",
    mockup: "sessions",
  },
  {
    id: "artifacts",
    eyebrow: "Evidence",
    title: "Evidence-backed reporting",
    body: "Each run produces structured artifacts — reconnaissance assessments, reports, and logs — alongside a hash-chained audit trail and captured findings. Provenance is verifiable end-to-end.",
    mockup: "artifacts",
  },
  {
    id: "skills",
    eyebrow: "Knowledge",
    title: "140-skill advisory knowledge base",
    body: "Skills are curated playbooks and tool guides the agent consults as needed. Manage them under Skills, and configure secrets, models, and plugins under System.",
    mockup: "skills",
  },
  {
    id: "safety",
    eyebrow: "Safety",
    title: "Lab-only, target-locked, fully audited",
    body: "Loopback-only. Execute solely against assets you own or are explicitly authorized to test. Every action is recorded in a tamper-evident audit chain.",
    mockup: "safety",
  },
  {
    id: "cta",
    eyebrow: "Ready",
    title: "Start your first assessment",
    body: "Open the console and launch a reconnaissance run against a lab target. The agent will enumerate the surface, propose goals, and await your approval before proceeding.",
    mockup: "cta",
  },
];
