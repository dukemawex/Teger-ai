// Mirrors packages/contracts (teger_contracts.analysis). Keep in sync with the JSON Schemas.
export type Verdict = "malicious" | "suspicious" | "no_threat_detected" | "unknown";
export type RecommendedAction = "block" | "warn" | "caution" | "allow";
export type ModuleStatus = "operational" | "experimental" | "planned" | "unavailable";

export interface Evidence {
  id: string;
  detector: string;
  category: string;
  tactic: string | null;
  severity: "info" | "low" | "medium" | "high" | "critical";
  weight: number;
  description: string;
  indicator: string | null;
}

export interface DetectorReport {
  name: string;
  version: string;
  status: "ok" | "unavailable" | "error" | "skipped";
  provider_mode: "local" | "live" | "mock" | "none";
  required: boolean;
  detail: string | null;
}

export interface AiExplanation {
  status: string;
  provider: string | null;
  summary: string | null;
  key_points: { evidence_ids: string[]; explanation: string }[];
  user_guidance: string | null;
  injection_attempt_observed: boolean;
  ungrounded_points_removed: number;
  redactions_applied: number;
  usage: { model: string; input_tokens: number; output_tokens: number; estimated_cost_usd: number | null } | null;
  detail: string | null;
}

export interface ThreatVerdict {
  analysis_id: string;
  created_at: string;
  verdict: Verdict;
  risk_score: number;
  confidence: number;
  recommended_action: RecommendedAction;
  recommended_action_text: string;
  evidence: Evidence[];
  detection_sources: DetectorReport[];
  intelligence_coverage: "complete" | "partial";
  mock_intelligence_used: boolean;
  policy_version: string;
  url: { normalized: string; host: string; unicode_host: string | null } | null;
  content_type: string;
  explanation: AiExplanation;
}

export interface AnalysisSummary {
  analysis_id: string;
  created_at: string;
  verdict: Verdict;
  risk_score: number;
  recommended_action: RecommendedAction;
  content_type: string;
  url_host: string | null;
  evidence_count: number;
  mock_intelligence_used: boolean;
}

export interface CapabilityModule {
  id: string;
  name: string;
  status: ModuleStatus;
  detail: string;
}

export interface AuditEvent {
  ts: string;
  event: string;
  outcome: string;
  request_id: string;
  key_id: string | null;
  details: Record<string, string | number | boolean | null>;
}

export interface WhoAmI {
  tenant_id: string;
  key_id: string;
  scopes: string[];
  cloud_ai_allowed: boolean;
}
