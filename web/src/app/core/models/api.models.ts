/** Severity of a finding, from the most to the least critical. */
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

/** Lifecycle status of a finding. */
export type FindingStatus = 'open' | 'fixed' | 'accepted' | 'false_positive';

/** Role attached to the bearer token. */
export type Role = 'mcp' | 'reader' | 'triager' | 'admin';
export type ProjectTokenRole = Exclude<Role, 'admin'>;

export const SEVERITIES: readonly Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

/** Higher is worse (same order as the server). */
export const SEVERITY_RANK: Record<Severity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
};

export const FINDING_STATUSES: readonly FindingStatus[] = [
  'open',
  'fixed',
  'accepted',
  'false_positive',
];

/** Open findings counted by severity. */
export type SeverityCounts = Record<Severity, number>;

/** GET /api/v1/me */
export interface Identity {
  client: string;
  role: Role;
  can_triage: boolean;
  auth_enabled: boolean;
  project: string | null;
  version: string;
}

/** Metadata returned for a project-scoped token; the raw secret is only returned at creation. */
export interface ProjectToken {
  id: string;
  label: string;
  role: Role;
  project: string | null;
  projects: string[] | null;
  pending_projects: string[];
  status: 'active' | 'pending';
  created_at: string;
}

/** A project token requested by a client (enrollment), waiting for an administrator. */
export interface EnrollmentRequest {
  id: string;
  token_id: string;
  label: string;
  role: Role;
  project: string;
  kind: 'new' | 'additional';
  status: 'pending';
  requested_by: string | null;
  requested_from: string | null;
  created_at: string;
}

/** Response returned once when a project-scoped token is created. */
export interface ProjectTokenCreated extends ProjectToken {
  token: string;
}

/** Origin of a stored rule: shipped default (seeded on the first run) or custom. */
export type RuleOrigin = 'builtin' | 'custom';

/** A scan rule stored in the database (default or custom). */
export interface CustomRule {
  id: string;
  title: string;
  severity: Severity;
  cwe: string;
  languages: string[];
  pattern: string;
  advice: string;
  ignore_case: boolean;
  origin: RuleOrigin;
  /** True for a default rule edited by an administrator. */
  modified: boolean;
  enabled: boolean;
  updated_at: string;
}

/** GET /api/v1/rules */
export interface CustomRuleCatalog {
  load_errors: string[];
  rules: CustomRule[];
}

/** Input accepted by POST and PUT /api/v1/rules. */
export type CustomRuleWrite = Pick<
  CustomRule,
  'id' | 'title' | 'severity' | 'languages' | 'pattern'
> &
  Partial<Pick<CustomRule, 'cwe' | 'advice' | 'ignore_case'>>;

/** Summary returned after a rule change or a reload. */
export interface RuleReloadResult {
  loaded_rules: number;
  load_errors: string[];
}

/** Origin of a stored checklist item. */
export type ChecklistItemOrigin = 'builtin' | 'custom';

/** One stored verification point belonging to a checklist domain. */
export interface ChecklistItem {
  domain: string;
  id: string;
  title: string;
  what_to_look_for: string;
  cwe: string;
  origin: ChecklistItemOrigin;
  modified: boolean;
}

/** GET /api/v1/checklists */
export interface ChecklistCatalog {
  checklist_items: ChecklistItem[];
  load_errors: string[];
}

/** Input accepted by POST and PUT /api/v1/checklists. */
export type ChecklistItemWrite = Pick<
  ChecklistItem,
  'domain' | 'id' | 'title' | 'what_to_look_for'
> &
  Partial<Pick<ChecklistItem, 'cwe'>>;

/** Summary returned after a checklist item change. */
export interface ChecklistReloadResult {
  loaded_checklist_items: number;
  load_errors: string[];
}

/** GET /api/v1/projects */
export interface ProjectSummary {
  project: string;
  reports_total: number;
  last_report_at: string;
  open_findings_total: number;
  open_findings_by_severity: SeverityCounts;
  worst_open_severity: Severity | null;
}

/** GET /api/v1/reports */
export interface ReportSummary {
  report_id: number;
  project: string;
  branch: string | null;
  commit_sha: string | null;
  risk_level: Severity;
  reviewer: string | null;
  created_at: string;
  findings_total: number;
  findings_open: number;
  summary: string;
}

/** A finding of a report. */
export interface Finding {
  id: number;
  report_id: number;
  title: string;
  severity: Severity;
  status: FindingStatus;
  status_changed_at: string | null;
  rule_id: string | null;
  category: string;
  cwe: string | null;
  owasp: string | null;
  file_path: string | null;
  line_start: number | null;
  line_end: number | null;
  description: string;
  evidence: string | null;
  recommendation: string | null;
}

/** GET /api/v1/reports/{id} */
export interface Report {
  id: number;
  project: string;
  repository: string | null;
  branch: string | null;
  commit_sha: string | null;
  reviewer: string | null;
  scope: string | null;
  summary: string;
  risk_level: Severity;
  created_at: string;
  findings: Finding[];
}

/** One period of GET /api/v1/trend */
export interface TrendPeriod {
  period: string;
  reports: number;
  worst_report_risk: Severity | null;
  new_total: number;
  fixed_total: number;
  dismissed_total: number;
  open_total: number;
  open_at_end: SeverityCounts;
  risk_score: number;
}

/** GET /api/v1/trend */
export interface Trend {
  project: string;
  window_days: number;
  granularity: 'day' | 'week' | 'month';
  direction: string;
  summary: {
    reports_total: number;
    new_findings: number;
    fixed_findings: number;
    dismissed_findings: number;
    open_now: SeverityCounts;
    open_now_total: number;
    oldest_open_days: Partial<Record<Severity, number>>;
    risk_score_now: number;
    top_open_cwes: { cwe: string; count: number }[];
    mttr_days: Record<string, { count: number; mean_days: number; median_days: number }>;
  };
  periods: TrendPeriod[];
  notes: string[];
}

/** Query parameters of the report list. */
export interface ReportQuery {
  project?: string;
  risk_level?: Severity | '';
  limit: number;
  offset: number;
}
