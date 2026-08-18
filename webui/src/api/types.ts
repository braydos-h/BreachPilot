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

export type DecisionKind = "start_confirm" | "goal_select" | "tool_approval" | "campaign_next_step";
export type DecisionStatus = "pending" | "answered" | "denied" | "expired";
export type RiskTag = "safe" | "gated" | "high";
export type RunMode = "recon" | "attack";
export type RunKind = "agent";
export type SkillsMode = "on" | "off" | "hints" | "lookup";
export type ObserverMode = "heuristic" | "llm" | "hybrid";

/**
 * Mid-run operator checkpoint (CAMPAIGN_NEXT_STEP).
 *
 * The backend builds a Decision of kind "campaign_next_step" at two milestones:
 *  - "access": the authoritative outcome classifier confirmed a compromise or
 *    credential dump ("Verified access obtained").
 *  - "no_path": the agent reached the safe natural-termination boundary after
 *    meaningful recon/service enumeration/vulnerability research with no
 *    verified foothold ("No verified access yet").
 *
 * Each option carries an ``action`` the WebUI submits back as the decision
 * answer (possibly suffixed with a goal name for change_goal/another_goal).
 * Options that offer a goal change include a nested ``goals`` list rendered
 * via GoalSuggestionCard.
 */
export type CampaignCheckpointKind = "access" | "no_path";

export interface CampaignNextStepOption {
  action: string;
  label: string;
  goals?: Array<{ name: string; description: string }>;
}

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

export interface ModelInfo {
  label?: string;
  context_window?: number;
  description?: string;
  [key: string]: unknown;
}

export interface ChatgptModelsBlock {
  default_model?: string;
  context_window?: number;
  configured_models?: string[];
}

export interface ModelRegistryInfo {
  /** Active chat/generate provider: "ollama" (default) or "chatgpt". */
  provider?: string;
  default_alias: string;
  registry: Record<string, string>;
  info?: Record<string, ModelInfo>;
  /** Present only when provider === "chatgpt". */
  chatgpt?: ChatgptModelsBlock;
}

export interface LiveModelsResponse {
  models: string[];
  /** "ollama" | "registry" (ollama path) | "chatgpt" (chatgpt path). */
  source: "ollama" | "registry" | "chatgpt";
  error?: string;
}

export interface ChatgptProviderStatus {
  enabled?: boolean;
  authenticated?: boolean;
  proxy_running?: boolean;
  host?: string;
  port?: number;
  default_model?: string;
  we_started?: boolean;
}

export interface ProvidersResponse {
  provider: string;
  chatgpt?: ChatgptProviderStatus;
}

/** POST /providers/chatgpt/login → {ok, url?, reason?}. Tokens never appear here. */
export interface ChatgptLoginResponse {
  ok: boolean;
  url?: string;
  reason?: string;
}

/** POST /providers/chatgpt/proxy/{start,stop}. */
export interface ChatgptProxyResponse {
  ok?: boolean;
  base_url?: string;
  reason?: string;
  stopped?: boolean;
}

export interface SkillSummary {
  name: string;
  description: string;
  tags: string[];
}

export interface AttackModuleSummary {
  name: string;
  description: string;
  family: string;
  target_services: string[];
  target_ports: number[];
  required_cves: string[];
  destructive_ics: boolean;
}

export interface AttackModulesResponse {
  modules: AttackModuleSummary[];
}

export interface SkillSearchResult {
  name: string;
  description: string;
}

export interface SkillInstallRequest {
  name: string;
  markdown: string;
}

export interface SkillInstallResponse {
  name: string;
  description: string;
  tags: string[];
}

export interface SkillRemoveResponse {
  name: string;
  deleted: boolean;
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
  description?: string;
  author?: string;
  capabilities?: string[];
  loaded?: boolean;
  /** Manifest enablement default (config plugins.enabled/disabled may override). */
  enabled?: boolean;
  /** Manifest config block schema — gating fields (api_key_env/url/enabled) the
   *  WebUI derives a "BLOCKED: no <key>" hint from. */
  config_section?: Record<string, Record<string, unknown>> | null;
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
  title?: string;
}

export interface RunListResponse {
  runs: RunListRow[];
  sort?: string;
  total?: number;
}

export type RunSortKey =
  | "created_desc"
  | "created_asc"
  | "title_asc"
  | "title_desc"
  | "state_asc"
  | "state_desc";

export const RUN_SORT_OPTIONS: { value: RunSortKey; label: string }[] = [
  { value: "created_desc", label: "Newest first" },
  { value: "created_asc", label: "Oldest first" },
  { value: "title_asc", label: "Title A→Z" },
  { value: "title_desc", label: "Title Z→A" },
  { value: "state_asc", label: "State A→Z" },
  { value: "state_desc", label: "State Z→A" },
];

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
  title?: string;
  cancelled_at?: string;
  resumed_from?: string;
  decisions: DecisionListRow[];
}

export interface RunResultTelemetry {
  calls?: number;
  total_tokens?: number;
  avg_ctx?: number | null;
  max_ctx?: number | null;
  context_window_tokens?: number | null;
  last_ctx_pct?: number | null;
  last_estimated_context_tokens?: number | null;
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

// B2: Enhanced report shapes (mirrors tools/enhanced_reporting.py dataclasses).
// The WebUI fetches /artifacts/enhanced/enhanced_report.json and renders the
// attack graph from exploitation_chains[] + technical_findings[].
export interface ChainEntry {
  module: string;
  timestamp?: string;
  result?: string;
  [key: string]: unknown;
}

export interface ExploitationChain {
  chain_id: string;
  target: string;
  entries: ChainEntry[];
  successful: boolean;
  final_privilege: string;
  total_duration?: number;
  [key: string]: unknown;
}

export interface CVSSScore {
  base_score: number;
  severity: string;
  vector_string?: string;
  [key: string]: unknown;
}

export interface TechnicalFinding {
  finding_id: string;
  title: string;
  affected_asset: string;
  vuln_class: string;
  severity: string;
  cvss: CVSSScore;
  confidence: number;
  summary: string;
  reproduction_steps?: string[];
  evidence_refs?: string[];
  exploitation_result?: string;
  persistence_achieved?: boolean;
  privilege_level_gained?: string;
  attack_chain?: ExploitationChain | null;
  remediation?: string;
  references?: string[];
  [key: string]: unknown;
}

export interface EnhancedReport {
  report_metadata?: Record<string, unknown>;
  executive_summary?: string;
  attack_timeline?: Array<Record<string, unknown>>;
  exploitation_chains?: ExploitationChain[];
  technical_findings?: TechnicalFinding[];
  failure_analysis?: Array<Record<string, unknown>>;
  [key: string]: unknown;
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
  confirmed?: boolean;
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
  | "phase"
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
  | "title"
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
  oldest_sequence?: number | null;
  latest_sequence?: number | null;
  has_more_before?: boolean;
}

export interface DiagnosticsResponse {
  exit_code: number;
  output: string;
}

export interface TelemetrySummary {
  alias: string;
  aliases: string[];
  calls: number;
  successful_calls: number;
  failed_calls: number;
  prompt_tokens: number;
  completion_tokens: number;
  total_tokens: number;
  average_tokens_per_second: number | null;
  average_completion_tokens_per_second: number | null;
  average_context_usage_pct: number | null;
  max_context_usage_pct: number | null;
  last_call_at: string;
}

export interface TelemetryRecord {
  alias?: string;
  model_id?: string;
  source?: string;
  started_at?: string;
  ended_at?: string;
  wall_duration_seconds?: number;
  prompt_tokens?: number;
  completion_tokens?: number;
  total_tokens?: number;
  tokens_per_second?: number;
  context_window_tokens?: number;
  estimated_context_tokens?: number;
  context_usage_pct?: number;
  context_remaining_tokens?: number;
  provider?: string;
  error?: string;
  [key: string]: unknown;
}

export interface TelemetryResponse {
  summary: TelemetrySummary;
  recent: TelemetryRecord[];
}

export interface MemoryLesson {
  id: string;
  target_signature: string;
  action_type: string;
  outcome: string;
  confidence: number;
  created_at: string;
  metadata: Record<string, unknown>;
}

export interface MemoryConfidence {
  action_type: string;
  observations: number;
  successes: number;
  failures: number;
  partials: number;
  confidence: number;
  last_seen: string;
}

export interface AttackMemoryItem {
  id: string;
  session_id: string;
  target_ip: string;
  category: string;
  item_key: string;
  item_value: string;
  source_tool: string;
  success: boolean;
  metadata: Record<string, unknown>;
  first_seen_at: string;
  last_seen_at: string;
  seen_count: number;
}

export interface MemoryResponse {
  lessons: MemoryLesson[];
  confidence: MemoryConfidence[];
  attack_memory: AttackMemoryItem[];
}

export interface WorkspaceFile {
  path: string;
  bytes: number;
}

export interface WorkspaceListResponse {
  files: WorkspaceFile[];
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

// ── Attack-path DAG (graph-viz-api) ─────────────────────────────────────────
// Returned by GET /api/v1/runs/{id}/graph (default-off; gated by
// api.graph_route). Nodes = findings/creds/access/tools; edges = "enables".

export interface GraphNode {
  id: string;
  type: "tool" | "target" | "step";
  label: string;
  status?: string;
  chain_id?: string;
  result?: string;
}

export interface GraphEdge {
  source: string;
  target: string;
  relation: "enables" | "targets";
}

export interface RunGraphResponse {
  run_id: string;
  nodes: GraphNode[];
  edges: GraphEdge[];
}

// ── Witness advisory flags (witness feature) ─────────────────────────────────
// Returned by GET /api/v1/runs/{id}/witness (reads reports/witness.jsonl).
// Advisory only — never a gate. The witness agent is advisory-only by design.

export type WitnessSeverity = "critical" | "high" | "medium" | "low";

export interface WitnessFlag {
  signal: string;
  severity: WitnessSeverity | string;
  message: string;
  record?: Record<string, unknown>;
  timestamp?: string;
}

export interface WitnessResponse {
  flags: WitnessFlag[];
}