// Mirrors services/investigator (teger_investigator.models). Keep in sync.
export type CaseVerdict = "malicious" | "suspicious" | "inconclusive" | "no_threat_detected";
export type CaseStatus = "queued" | "running" | "completed" | "failed" | "cancelled";
export type ToolState = "pending" | "running" | "completed" | "failed" | "skipped" | "unavailable";
export type EvidenceMethod = "observed" | "derived" | "model_inference";
export type Stance = "risk" | "legitimacy" | "neutral";
export type ActionState = "proposed" | "approved" | "rejected" | "expired" | "executed" | "failed";

export interface CaseEvidence {
  id: string;
  tool: string;
  source: string;
  collected_at: string;
  method: EvidenceMethod;
  stance: Stance;
  severity: "info" | "low" | "medium" | "high" | "critical";
  kind: string;
  summary: string;
  details: Record<string, string | number | boolean | null | string[]>;
  untrusted_excerpt: string | null;
}

export interface ToolRun {
  seq: number;
  tool: string;
  purpose: string;
  state: ToolState;
  selected_by: string;
  started_at: string | null;
  finished_at: string | null;
  detail: string | null;
  evidence_ids: string[];
}

export interface Finding {
  id: string;
  statement: string;
  evidence_ids: string[];
  stance: Stance;
}

export interface Assessment {
  verdict: CaseVerdict;
  headline: string;
  findings: Finding[];
  contradictions: Finding[];
  uncertainties: string[];
  recommended_next_action: string;
  context_effect: string;
  policy_version: string;
}

export interface ProposedAction {
  id: string;
  case_id: string;
  case_version: number;
  type: "record_warning" | "blocklist_domain" | "request_verification" | "close_as_legitimate";
  title: string;
  params: Record<string, string>;
  params_hash: string;
  enforcement_scope: string;
  state: ActionState;
  proposed_by: string;
  proposed_at: string;
  expires_at: string;
  decided_by: string | null;
  decided_at: string | null;
  decision_note: string | null;
  executed_at: string | null;
  execution_result: string | null;
  demo_only: boolean;
}

export interface CaseInput {
  url: string | null;
  message: string | null;
  sender: string | null;
  subject: string | null;
  source: string;
  ai_planning: boolean;
  cloud_ai_consent: boolean;
}

export interface InvestigationCase {
  id: string;
  mode: "demo" | "live";
  title: string;
  status: CaseStatus;
  version: number;
  created_at: string;
  updated_at: string;
  input: CaseInput;
  planner: string;
  fixture_id: string | null;
  tools: ToolRun[];
  evidence: CaseEvidence[];
  assessment: Assessment | null;
  actions: ProposedAction[];
  resolution: { outcome: string; note: string | null; recorded_by: string; recorded_at: string } | null;
  error: string | null;
  limits: Record<string, number>;
}

export interface CaseSummary {
  id: string;
  mode: "demo" | "live";
  title: string;
  status: CaseStatus;
  verdict: CaseVerdict | null;
  created_at: string;
  updated_at: string;
  pending_approvals: number;
}

export interface CaseEvent {
  seq: number;
  ts: string;
  type: string;
  message: string;
  data: Record<string, unknown>;
}

export interface ContextEntry {
  id: string;
  kind: "supplier" | "identity_provider" | "service";
  name: string;
  domains: string[];
  approved_services: { domain: string; purpose: string }[];
  verified_contact: string | null;
  verification_source: string;
  notes: string | null;
  approved_by: string;
  approved_at: string;
  revoked: boolean;
}

export interface ActivityItem {
  seq: number;
  ts: string;
  type: string;
  case_id: string | null;
  action_id: string | null;
  actor: string;
  message: string;
}

export const VERDICT_LABEL: Record<CaseVerdict, string> = {
  malicious: "Malicious",
  suspicious: "Suspicious",
  inconclusive: "Inconclusive",
  no_threat_detected: "No threat detected",
};

export const VERDICT_NOTE: Record<CaseVerdict, string> = {
  malicious: "Evidence shows impersonation or a known-bad destination.",
  suspicious: "Evidence conflicts with approved context. Treat as untrusted.",
  inconclusive: "Teger could not gather enough evidence to decide.",
  no_threat_detected: "Nothing checked contradicted approved context. Not a guarantee of safety.",
};

export const METHOD_LABEL: Record<EvidenceMethod, string> = {
  observed: "Observed",
  derived: "Derived by rule",
  model_inference: "Model inference",
};

export const ACTION_STATE_LABEL: Record<ActionState, string> = {
  proposed: "Awaiting approval",
  approved: "Approved — not yet executed",
  rejected: "Rejected",
  expired: "Expired",
  executed: "Executed",
  failed: "Failed",
};

export const TOOL_LABEL: Record<string, string> = {
  extract_message: "Read message",
  static_analysis: "Deterministic checks",
  resolve_redirects: "Follow redirects",
  inspect_page: "Read destination",
  compare_context: "Compare business context",
  check_reputation: "Reputation lookup",
  propose_response: "Propose response",
};

/** Route stages shown in the evidence route; each maps to the tools that feed it. */
export const ROUTE_STAGES = [
  { key: "message", label: "Message", tools: ["extract_message", "static_analysis"] },
  { key: "destination", label: "Destination", tools: ["resolve_redirects", "inspect_page", "check_reputation"] },
  { key: "identity", label: "Identity check", tools: ["compare_context"] },
  { key: "decision", label: "Decision", tools: ["propose_response"] },
] as const;

export type StageKey = (typeof ROUTE_STAGES)[number]["key"];

export function stageOf(tool: string): StageKey {
  return (ROUTE_STAGES.find((s) => (s.tools as readonly string[]).includes(tool))?.key ?? "message") as StageKey;
}

export function isActive(status: CaseStatus): boolean {
  return status === "queued" || status === "running";
}

export function shortTime(iso: string): string {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? "" : d.toISOString().slice(11, 19);
}

export function newIdempotencyKey(): string {
  return crypto.randomUUID().replace(/-/g, "").slice(0, 24);
}
