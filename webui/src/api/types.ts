export type RunState =
  | "draft"
  | "awaiting_confirmation"
  | "queued"
  | "running"
  | "awaiting_input"
  | "completed"
  | "failed"
  | "cancelled"
  | "interrupted"
  | "cancelling";

export type DecisionKind = "start_confirm" | "goal_select" | "tool_approval";
export type DecisionStatus = "pending" | "answered" | "denied" | "expired";
export type RiskTag = "safe" | "gated" | "high";
export type RunMode = "recon" | "attack";
export type RunKind = "agent" | "manual";
export type SkillsMode = "on" | "off" | "hints" | "lookup";
export type ObserverMode = "heuristic" | "llm" | "hybrid";

export interface Capabilities {
  api_version: string;
  features: string[];
  constraints: {
    max_concurrent_runs: number;
    loopback_only: boolean;
    manual_tool_calls: boolean;
  };
  run_options: {
    modes: RunMode[];
    kinds: RunKind[];
    flags: string[];
  };
}

export interface GoalPreset {
  name: string;
  description: string;
  risk: RiskTag;
  compatible: boolean;
}

export interface SuggestedGoal {
  name?: string;
  description?: string;
  exploit_likelihood: string;
  success_rating: number;
  rationale?: string;
  compatible?: boolean;
  blocked_reason?: string;
  risk_requirement?: RiskTag | string;
  is_ai_generated?: boolean;
}

export interface ReconService {
  name?: string;
  port?: number;
  banner?: string;
  risk?: number;
  [key: string]: unknown;
}

export interface ReconCveFinding {
  service?: string;
  product?: string;
  version?: string;
  count?: number;
  cves?: unknown[];
  [key: string]: unknown;
}

export interface ReconAssessment {
  target_ip: string;
  os_verdict: string;
  os_hints?: string[];
  open_ports?: number[];
  services?: ReconService[];
  cve_findings?: ReconCveFinding[];
  overall_risk_score?: number;
  [key: string]: unknown;
}

export interface ModelRegistryInfo {
  default_alias: string;
  registry: Record<string, string>;
  info?: Record<string, unknown>;
}

export interface LiveModelsResponse {
  models: string[];
  source: "ollama" | "registry";
  error?: string;
}

export interface SkillSummary {
  name: string;
  description: string;
  tags: string[];
}

export interface SkillSearchResult {
  name: string;
  description: string;
}

export interface SkillDetail {
  name: string;
  description: string;
  body: string;
  sections: Record<string, string>;
  tags: string[];
  references: string[];
  nist_csf: string[];
  mitre_attack: string[];
  domain?: string;
  subdomain?: string;
  version?: string;
}

export interface PluginSummary {
  name?: string;
  version?: string;
  capabilities?: string[];
  loaded?: boolean;
  [key: string]: unknown;
}

export interface SecretsStatus {
  keys: Record<string, "configured" | "missing">;
}

export interface SecretWriteResult {
  status: string;
  written: string[];
}

export interface ConfigSchema {
  schema: Record<string, unknown>;
}

export interface RunCreateRequest {
  target: string;
  mode: RunMode;
  goal?: string;
  custom_goal?: string;
  recon_first?: boolean | null;
  model?: string;
  swarm?: boolean;
  parallel_swarm?: boolean;
  critic?: boolean;
  reflection?: boolean;
  adaptive_exploits?: boolean;
  long_session?: boolean;
  multi_model_consult?: boolean | null;
  observer_mode?: ObserverMode;
  ultrathink?: boolean;
  skills?: SkillsMode | null;
  skills_include?: string[];
  skills_exclude?: string[];
  resume?: string;
  kind?: RunKind;
  yes?: boolean;
}

export interface RunPreview {
  run_id: string;
  target_ip: string;
  original_target?: string;
  resolved_ip?: string | null;
  resolved_domain?: string | null;
  mode: RunMode;
  goal_name: string;
  goal_description?: string;
  model_alias: string;
  model_label?: string;
  transport_summary?: string;
  permission: string;
  attack_mode?: boolean;
  destructive: boolean;
  required_confirmation_text: string;
  budgets: Record<string, unknown>;
  swarm: boolean;
  parallel_swarm?: boolean;
  multi_model?: boolean;
  skill_activations?: Array<{ name: string; reason: string }>;
  skill_errors?: string[];
  resumed_from?: string;
  [key: string]: unknown;
}

export interface CreateRunDecisionSummary {
  id: string;
  kind: DecisionKind;
  required_text: string;
  prompt_text: string;
}

export interface CreateRunResponse {
  run_id: string;
  preview: RunPreview;
  state: RunState;
  decision?: CreateRunDecisionSummary;
}

export interface ResumeRunResponse {
  run_id: string;
  resumed_from: string;
  preview: { run_id: string; target_ip: string };
}

export interface RunListRow {
  id: string;
  state: RunState;
  created_at: string;
  target: string;
  mode: RunMode;
  goal_name: string;
  target_ip: string;
  model_alias: string;
}

export interface RunListResponse {
  runs: RunListRow[];
}

export interface RunDetailRequest {
  target?: string;
  mode?: RunMode;
  goal_name?: string;
  custom_goal?: string;
  recon_first?: boolean | null;
  model_alias?: string;
  swarm?: boolean;
  parallel_swarm?: boolean;
  critic?: boolean;
  reflection?: boolean;
  adaptive_exploits?: boolean;
  long_session?: boolean;
  multi_model_consult?: boolean | null;
  observer_mode?: ObserverMode;
  ultrathink?: boolean;
  skills_mode?: SkillsMode | null;
  skills_include?: string[];
  skills_exclude?: string[];
  resume_source?: string;
  kind?: RunKind;
  yes?: boolean;
  [key: string]: unknown;
}

export interface RunDetail {
  id: string;
  state: RunState;
  created_at: string;
  updated_at?: string;
  request: RunDetailRequest;
  preview: Partial<RunPreview> & Record<string, unknown>;
  result: RunResult;
  error: string;
  cancelled_at?: string;
  resumed_from?: string;
  decisions: DecisionListRow[];
}

export interface RunResultTelemetry {
  total_tokens?: number;
  total_calls?: number;
  avg_ctx_pct?: number;
  max_ctx_pct?: number;
  context_window_tokens?: number;
  last_ctx_pct?: number;
  last_estimated_context_tokens?: number;
  [key: string]: unknown;
}

export interface RunResultActiveSkill {
  name: string;
  reason: string;
}

export interface RunResultSafetyReview {
  safe?: boolean;
  reasoning?: string;
  concerns?: string[];
  recommended?: string[];
  [key: string]: unknown;
}

export interface RunResult {
  run_id?: string;
  target_ip?: string;
  mode?: RunMode;
  goal_name?: string;
  goal_description?: string;
  total_actions?: number;
  workspace?: string;
  audit_path?: string;
  error?: string;
  outcome_summary?: string;
  telemetry?: RunResultTelemetry;
  active_skills?: RunResultActiveSkill[];
  safety_review?: RunResultSafetyReview;
  swarm_result?: Record<string, unknown>;
  reports_dir?: string;
  summary_path?: string;
  run_json_path?: string;
  [key: string]: unknown;
}

export interface DecisionListRow {
  id: string;
  kind: string;
  status: DecisionStatus;
  answer: string;
  prompt_text?: string;
  required_text?: string;
  options_json?: unknown[];
  options?: unknown[];
  created_at?: string;
  answered_at?: string;
  [key: string]: unknown;
}

export interface DecisionOut {
  id: string;
  run_id: string;
  kind: string;
  prompt_text: string;
  required_text: string;
  options: unknown[];
  status: DecisionStatus;
  answer: string;
  created_at: string;
  answered_at: string;
}

export interface DecisionAnswerResponse {
  decision_id: string;
  status: string;
}

export interface ArtifactSummary {
  name: string;
  bytes: number;
  exists: boolean;
}

export interface ArtifactListResponse {
  artifacts: ArtifactSummary[];
}

export interface AuditRecord {
  [key: string]: unknown;
}

export interface AuditResponse {
  records: AuditRecord[];
  chain_valid: boolean;
  chain_reason: string;
}

export interface SwarmStateResponse {
  state: Record<string, unknown>;
}

export interface CampaignStateResponse {
  state: Record<string, unknown>;
}

export interface LogResponse {
  name: string;
  lines: string[];
  total_lines_returned: number;
  total_lines_in_file: number;
}

export interface CredentialRecord {
  index: number;
  username: string;
  target_host: string;
  credential_type?: string;
  source_action?: string;
  password: string;
  [key: string]: unknown;
}

export interface CredentialsResponse {
  credentials: CredentialRecord[];
}

export interface CredentialRevealResponse {
  index: number;
  username: string;
  target_host: string;
  password: string;
}

export interface LootItem {
  timestamp?: number;
  source_host?: string;
  loot_type: string;
  description: string;
  content?: string;
  path?: string;
  [key: string]: unknown;
}

export interface LootResponse {
  loot: LootItem[];
}

export interface ToolSchema {
  type?: string;
  function?: {
    name: string;
    description?: string;
    parameters?: Record<string, unknown>;
  };
  [key: string]: unknown;
}

export interface ToolsResponse {
  tools: ToolSchema[];
}

export interface ToolCallRequest {
  arguments: Record<string, unknown>;
}

export interface ToolCallResponse {
  tool: string;
  result: string;
}

export interface DeleteRunResponse {
  run_id: string;
  deleted: boolean;
  purged: boolean;
}

export type EventType =
  | "state"
  | "boot"
  | "ok"
  | "progress"
  | "recon_assessment"
  | "goal_suggestions"
  | "assistant"
  | "tool_request"
  | "tool_start"
  | "tool_result"
  | "approval"
  | "swarm"
  | "artifact"
  | "completion"
  | "error"
  | "heartbeat";

export interface RunEvent {
  sequence: number;
  timestamp: string;
  run_id: string;
  type: EventType;
  payload: Record<string, unknown>;
}

export interface EventReplayResponse {
  run_id: string;
  events: RunEvent[];
}

export interface DiagnosticsResponse {
  exit_code: number;
  output: string;
}

export interface ConfigPatchResponse {
  status: string;
  config: Record<string, unknown>;
}

export interface ConfigValidationErrorResponse {
  error: {
    code: string;
    message: string;
    details: { errors: string[] } | Record<string, unknown>;
    request_id: string;
  };
}

export interface ApiErrorEnvelope {
  error: {
    code: string;
    message: string;
    details: Record<string, unknown>;
    request_id: string;
  };
}

export interface ApiErrorShape {
  status: number;
  code: string;
  message: string;
  details: Record<string, unknown>;
  requestId: string;
  raw: unknown;
}

export const ACTIVE_RUN_STATES: RunState[] = [
  "awaiting_confirmation",
  "queued",
  "running",
  "awaiting_input",
  "cancelling",
];

export const TERMINAL_RUN_STATES: RunState[] = [
  "completed",
  "failed",
  "cancelled",
  "interrupted",
];

export function isActiveState(state: RunState): boolean {
  return ACTIVE_RUN_STATES.includes(state);
}

export function isTerminalState(state: RunState): boolean {
  return TERMINAL_RUN_STATES.includes(state);
}

export function stateCategory(state: RunState): "pending" | "active" | "done" {
  if (state === "draft" || state === "queued") return "pending";
  if (isActiveState(state)) return "active";
  return "done";
}