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

/** GET /api/v1/auth/config: single sign-on (OIDC) offered on the login page. */
export interface AuthConfig {
  oidc: boolean;
  oidc_display_name: string | null;
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

/** Response of an approval; portal_grant is present when an OIDC user got web access. */
export interface EnrollmentApproved extends Omit<EnrollmentRequest, 'status'> {
  status: 'active';
  projects: string[];
  portal_grant?: UserGrant;
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

/** How the controller reaches the OSV exports. */
export type ProxyMode = 'env' | 'custom' | 'none';

/** GET /api/v1/settings (proxy passwords are replaced by ***) */
export interface AppSettings {
  report_language: {
    /** Set in the web interface: null inherits SECREVIEW_REPORT_LANGUAGE, '' lets the agent choose. */
    value: string | null;
    env: string;
    effective: string;
  };
  osv_proxy: {
    mode: ProxyMode;
    url: string | null;
    env: {
      secreview_osv_proxy: string | null;
      https_proxy: string | null;
      http_proxy: string | null;
      no_proxy: string | null;
    };
    effective: {
      url: string | null;
      source: 'web' | 'none' | 'SECREVIEW_OSV_PROXY' | 'environment';
    };
  };
  osv: {
    download_enabled: boolean;
    update_interval_hours: number;
    url: string;
    ecosystems: string;
    cafile: string | null;
    max_download_mb: number;
  };
}

/** Outcome of one ecosystem in an OSV update. */
export interface AdvisoryEcosystemResult {
  downloaded_bytes?: number;
  read?: number;
  imported?: number;
  skipped?: number;
  error?: string;
}

/** One OSV update of the history. */
export interface AdvisoryUpdate {
  id: number;
  trigger: 'schedule' | 'cli' | 'web';
  triggered_by: string | null;
  status: 'running' | 'success' | 'partial' | 'failed' | 'interrupted';
  source: string;
  started_at: string;
  finished_at: string | null;
  /** Per ecosystem, or { error } when the whole update failed. */
  results: Record<string, AdvisoryEcosystemResult | string>;
}

/** GET /api/v1/advisories */
export interface AdvisoryOverview {
  database: {
    loaded: boolean;
    advisories: number;
    by_ecosystem: Record<string, number>;
    last_imported_at: string | null;
    age_days: number | null;
    stale: boolean;
  };
  download_enabled: boolean;
  running: boolean;
  updates: AdvisoryUpdate[];
}

/** Web role an OIDC role mapping may grant. */
export type MappedRole = 'reader' | 'triager' | 'admin';

/** An identity provider group or role mapped to a web role (and projects). */
export interface RoleMapping {
  /** Absent for the mappings of the SECREVIEW_OIDC_*_GROUPS variables. */
  id?: number;
  claim_value: string;
  role: MappedRole;
  /** null: every project. */
  projects: string[] | null;
  source: 'database' | 'environment';
  created_at?: string;
  created_by?: string | null;
}

/** Read access given by name to an OIDC user, usually when approving its enrollment. */
export interface UserGrant {
  id: number;
  /** Exact value of the username claim of the identity provider. */
  username: string;
  role: 'reader';
  projects: string[];
  created_at: string;
  updated_at: string;
  created_by: string | null;
}

/** GET /api/v1/oidc/role-mappings */
export interface RoleMappingCatalog {
  oidc_enabled: boolean;
  roles_claim: string;
  username_claim: string;
  default_role: 'reader' | 'triager' | null;
  mappings: RoleMapping[];
  static_mappings: RoleMapping[];
  user_grants: UserGrant[];
}
