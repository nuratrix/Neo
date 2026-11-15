// The API's shapes (api/source_neo.py). The web app only knows these.

export type Tier = "P1" | "P2" | "P3" | "P4";
export type PathId = "A" | "B" | "C";

export interface Meta {
  product: string;
  source: string;
  window_days: number;
  read_only: boolean;
}

export interface Recommendation {
  path: PathId;
  path_name: string;
  headline: string;
  why: string;
  next_step: string;
}

export interface Suggestion {
  at: string;
  author: string;
  kind: string; // fix | path | controls | triage | other
  text: string;
}

export interface ItemSummary {
  id: string;
  cve_id: string;
  title: string;
  resource_id: string;
  package: string;
  fixed_version: string;
  tier: Tier | string;
  tier_name: string;
  risk_score: number;
  path: PathId;
  recommendation: Recommendation;
  state: string;
  needs_human: boolean;
  escalated: boolean;
  sla_due: string;
  sla_status: "ok" | "due_soon" | "overdue" | "met" | "missed";
  suggestion: Suggestion | null;
  suggestion_count: number;
  has_proposal: boolean;
  updated_at: string;
  created_at: string;
}

export interface Overview {
  items: ItemSummary[];
  matrix: Record<string, Record<string, number>>;
  needs_human: number;
  no_suggestion: number;
  overdue: number;
  generated_at: string;
  days: number;
  errors: string[];
}

export interface Proposal {
  status: string;
  controls: string[];
  effectiveness: number;
  tag_value: string;
  justification: string;
  approved_by: string;
  expires: string | null;
  controls_applied: boolean;
  change_ref: string;
  tag_drift: string[];
  warnings: string[];
}

export interface HistoryStep {
  at: string;
  state: string;
  event: string;
}

export interface ItemDetail {
  summary: ItemSummary;
  suggestions: Suggestion[];
  proposal: Proposal | null;
  history: HistoryStep[];
  evidence: Record<string, unknown>;
  errors: string[];
}
