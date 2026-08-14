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
    title: "An autonomous pentest agent, local-first",
    body: "NetAttackAI is an AI-driven, local-first penetration testing & bug bounty research agent. It plans, reconnoiters, exploits, and reports — end to end — against targets you own or are explicitly authorized to assess. It thinks in kill-chains, not checklists: scout the surface, pick the attack, run it, prove the outcome with evidence, and write the report. Powered by Ollama LLMs, the Model Context Protocol, and a 140-skill advisory knowledge base.",
    mockup: "killchain",
  },
  {
    id: "home",
    eyebrow: "The console",
    title: "Your command center",
    body: "The home screen shows your run stats, quick actions for Recon & Suggest Goals or Attack, and your recent sessions. The safety line keeps you oriented.",
    mockup: "home",
  },
  {
    id: "wizard",
    eyebrow: "Runs",
    title: "Start a run in three steps",
    body: "The wizard walks you through Settings, Target, and Review & confirm. Pick a mode (recon or attack), a goal risk-grouped as safe, gated, or high, and power-ups like Swarm, Critic, Reflection, Adaptive exploits, Long session, Multi-model consult, and Ultrathink.",
    mockup: "wizard",
  },
  {
    id: "run",
    eyebrow: "Runs",
    title: "Watch the agent work",
    body: "A live run streams events as they happen: phase changes (Starting, Recon, Enumeration, Vuln Research, Validation, Reporting), tool calls, and progress telemetry. The phase tracker shows where the agent is in the kill-chain.",
    mockup: "run",
  },
  {
    id: "decisions",
    eyebrow: "Control",
    title: "You stay in control",
    body: "Every operator decision — start_confirm, goal_select, tool_approval — waits for you in Read mode. Approve auto-answers non-destructive decisions; Full access auto-answers everything, including destructive confirmations. The target-IP allowlist lock applies in every mode.",
    mockup: "decisions",
  },
  {
    id: "sessions",
    eyebrow: "History",
    title: "Every run, searchable",
    body: "The Sessions page lists all your runs with state, target, mode, goal, and model. Resume a completed run, regenerate its title, or delete it.",
    mockup: "sessions",
  },
  {
    id: "artifacts",
    eyebrow: "Evidence",
    title: "Proof, not promises",
    body: "Every run produces artifacts (recon assessments, reports, logs), a hash-chained audit trail that verifies 'Chain valid', and loot — captured credentials and findings.",
    mockup: "artifacts",
  },
  {
    id: "skills",
    eyebrow: "Knowledge",
    title: "A 140-skill advisory knowledge base",
    body: "Skills are playbooks and tool guides the agent consults on demand. Manage them under Skills, and tune config, secrets, models, and plugins under System.",
    mockup: "skills",
  },
  {
    id: "safety",
    eyebrow: "Safety",
    title: "Lab-only, target-locked, fully audited",
    body: "Loopback only. Run only against assets you own or are explicitly authorized to test. Every action is recorded in the audit chain.",
    mockup: "safety",
  },
  {
    id: "cta",
    eyebrow: "Ready",
    title: "Start your first assessment",
    body: "Head to the console and launch a recon run against a lab target. The agent will scout, suggest goals, and ask before it acts.",
    mockup: "cta",
  },
];
