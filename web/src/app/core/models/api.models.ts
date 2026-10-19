/** Severity of a finding, from the most to the least critical. */
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

/** Lifecycle status of a finding. */
export type FindingStatus = 'open' | 'fixed' | 'accepted' | 'false_positive';

/** Role of a bearer token: tokens are for machines, a person signs in with a web user. */
export type TokenRole = 'mcp' | 'admin' | 'ci' | 'api';
/** Role of the caller: the role of its token, or `user` for a web user, whose rights are the
 * permissions of its groups. */
export type Role = TokenRole | 'user';
/** Role of a token managed in the web interface. */
export type ProjectTokenRole = Exclude<TokenRole, 'admin'>;
/** Role of a personal token of a web user (My account). */
export type PersonalTokenRole = Extract<TokenRole, 'api' | 'mcp'>;

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

/** Kind of review that produced a report: the MCP prompt used or the CLI scan. */
export type ReviewType =
  | 'security-review'
  | 'api-security-review'
  | 'configuration-review'
  | 'dependency-review'
  | 'codebase-review'
  | 'code-scan'
  | 'dependency-scan'
  | 'other';

export const REVIEW_TYPES: readonly ReviewType[] = [
  'security-review',
  'api-security-review',
  'configuration-review',
  'dependency-review',
  'codebase-review',
  'code-scan',
  'dependency-scan',
  'other',
];

/** Open findings counted by severity. */
export type SeverityCounts = Record<Severity, number>;

/** Permission a role may hold (access_control.Permission on the server). */
export type Permission =
  | 'reports.read'
  | 'findings.triage'
  | 'rules.manage'
  | 'standards.manage'
  | 'tokens.manage'
  | 'settings.manage'
  | 'users.manage'
  | 'audit.read'
  | 'projects.create';

/** Each permission held, with its projects (null: every project). */
export type Grants = Partial<Record<Permission, string[] | null>>;

/** GET /api/v1/me */
export interface Identity {
  client: string;
  /** Role of a token; for a web user, the web role that sums up its permissions. */
  role: Role;
  can_triage: boolean;
  auth_enabled: boolean;
  /** Projects whose reports the caller reads; null: every project. */
  projects?: string[] | null;
  permissions: Grants;
  /** True for a local web user (logged in with a password, which it may change). */
  local_account?: boolean;
  /** Source of the account of a web user; null for a bearer token (API). */
  auth_source?: AuthSource | null;
  /** Password set by someone else: only My account is reachable until it is changed. */
  must_change_password?: boolean;
  version: string;
}

/** GET /api/v1/about: version and links of the About page. */
export interface About {
  version: string;
  documentation_url: string | null;
  repository_url: string | null;
  issues_url: string | null;
  /** Swagger documentation, null when it is not served. */
  swagger_url: string | null;
  health_url: string;
}

/** GET /api/v1/about/update: latest release on GitHub (SECREVIEW_UPDATE_CHECK_ENABLED). */
export interface UpdateStatus {
  enabled: boolean;
  current: string;
  latest: string | null;
  update_available: boolean;
  release_url: string | null;
  checked_at: string | null;
  /** Why the latest release is unknown while enabled. */
  error: 'unreachable' | 'invalid' | null;
}

/** Theme of the web interface; auto follows the system preference. */
export type ThemeChoice = 'light' | 'dark' | 'auto';

/** GET and PUT /api/v1/me/preferences: preferences of the logged-in web user. */
export interface Preferences {
  theme: ThemeChoice;
}

/** GET /api/v1/auth/config: login methods offered on the login page. */
export interface AuthConfig {
  /** Username and password of a local web user (false with SECREVIEW_OIDC_ONLY). */
  password?: boolean;
  oidc: boolean;
  oidc_display_name: string | null;
}

/** Session returned by POST /api/v1/auth/login and PUT /api/v1/me/password. */
export interface LoginSession {
  session: string;
  expires_in: number;
  username: string;
  /** Password set by someone else: it must be changed before anything else. */
  must_change_password?: boolean;
}

/** Source of a web user: local account (password) or OIDC account (OpenID Connect). */
export type AuthSource = 'local' | 'oidc';

/** Membership of a web user in a group. */
export interface UserGroupMembership {
  group_id: number;
  name: string;
  /** local: given by an administrator; oidc: named by the groups claim at the last login. */
  source: AuthSource;
}

/** A web user, local or OIDC; the password hash is never returned. */
export interface WebUser {
  id: number;
  username: string;
  auth_source: AuthSource;
  groups: UserGroupMembership[];
  /** Permissions given by the roles of its groups; empty: no access. */
  permissions: Grants;
  /** True once an OIDC user logged in (bound to its identity provider account). */
  sso_linked: boolean;
  created_at: string;
  updated_at: string;
  /** null for an OIDC user (no password). */
  password_changed_at: string | null;
  /** Its password was set by someone else: it changes it at its next login. */
  must_change_password: boolean;
  last_login_at: string | null;
  created_by: string | null;
}

/** A deleted OIDC user: a login never creates it again until the revocation is lifted. */
export interface RevokedUser {
  username: string;
  revoked_at: string;
  revoked_by: string | null;
}

/** A web user just created or reset: ``password`` is set when it was generated (shown once). */
export interface WebUserWithPassword extends WebUser {
  password?: string;
}

/**
 * Metadata of a token managed in the web interface (projects null: every project); the raw
 * secret is only returned at creation.
 */
export interface ProjectToken {
  id: string;
  label: string;
  role: ProjectTokenRole;
  /** api token: its role (role token); null for a personal token or another usage. */
  access_role_id: number | null;
  /** api token created by a web user for itself: it holds the current rights of that user. */
  personal: boolean;
  project: string | null;
  projects: string[] | null;
  pending_projects: string[];
  status: 'active' | 'pending';
  created_at: string;
  /** Expiry date; null: the token never expires. */
  expires_at: string | null;
  /** True once the expiry date is past: the token authenticates nothing. */
  expired: boolean;
  /** Date of the latest rotation (new secret), or null. */
  rotated_at: string | null;
  /** End of the grace period of the previous secret after a rotation, or null. */
  grace_until: string | null;
}

/** Kind of an audit event. */
export type AuditAction =
  | 'finding.status_changed'
  | 'finding.status_proposed'
  | 'finding.proposal_rejected'
  | 'token.created'
  | 'token.rotated'
  | 'token.revoked'
  | 'token.projects_changed'
  | 'enrollment.requested'
  | 'enrollment.approved'
  | 'enrollment.rejected'
  | 'role.created'
  | 'role.updated'
  | 'role.deleted'
  | 'group.created'
  | 'group.updated'
  | 'group.deleted'
  | 'group.roles_changed'
  | 'group.members_changed'
  | 'user.groups_changed'
  | 'project.created'
  | 'user.roles_changed'
  | 'user.login'
  | 'user.login_failed'
  | 'user.logout'
  | 'audit_syslog.changed';

export const AUDIT_ACTIONS: readonly AuditAction[] = [
  'finding.status_changed',
  'finding.status_proposed',
  'finding.proposal_rejected',
  'token.created',
  'token.rotated',
  'token.revoked',
  'token.projects_changed',
  'enrollment.requested',
  'enrollment.approved',
  'enrollment.rejected',
  'role.created',
  'role.updated',
  'role.deleted',
  'group.created',
  'group.updated',
  'group.deleted',
  'group.roles_changed',
  'group.members_changed',
  'user.groups_changed',
  'project.created',
  'user.roles_changed',
  'user.login',
  'user.login_failed',
  'user.logout',
  'audit_syslog.changed',
];

/** One entry of the audit log (details never hold a secret). */
export interface AuditEvent {
  id: number;
  created_at: string;
  action: AuditAction;
  /** user:NAME, token:LABEL, cli, anonymous or stdio. */
  actor: string;
  target_type: string;
  target_id: string | null;
  project: string | null;
  details: Record<string, unknown>;
}

/** One page of the audit log (total counts every matching event). */
export interface AuditPage {
  total: number;
  events: AuditEvent[];
}

/** Filters of the audit log. */
export interface AuditQuery {
  action?: AuditAction | null;
  project?: string | null;
  search?: string | null;
  sort_by?: 'created_at' | 'action' | 'actor' | 'target' | 'project';
  sort_direction?: 'asc' | 'desc';
  limit: number;
  offset: number;
}

/** A project token requested by a client (enrollment), waiting for an administrator. */
export interface EnrollmentRequest {
  id: string;
  token_id: string;
  label: string;
  role: ProjectTokenRole;
  project: string;
  kind: 'new' | 'additional';
  status: 'pending';
  requested_by: string | null;
  requested_from: string | null;
  created_at: string;
}

/** Response of an approval; portal_user is present when a web user got read access. */
export interface EnrollmentApproved extends Omit<EnrollmentRequest, 'status'> {
  status: 'active';
  projects: string[];
  portal_user?: WebUser;
}

/** Response returned once when a project-scoped token is created. */
export interface ProjectTokenCreated extends ProjectToken {
  token: string;
}

/** A role an api token may hold (GET /api/v1/project-tokens/roles). */
export interface TokenRoleChoice {
  id: number;
  name: string;
  permissions: Permission[];
  /** Only permissions per project: the token may be limited to projects. */
  scoped: boolean;
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

/** Sections of a rule pack exported by GET /api/v1/packs/rules. */
export type RulePackSection = 'rules' | 'checklist';

/** Answer of POST /api/v1/packs/rules: what the pack held, then the reloaded registry. */
export interface RulePackImportResult extends RuleReloadResult, ChecklistReloadResult {
  files: string[];
  rules: number;
  checklist_items: number;
  disabled_rules: number;
  replaced: boolean;
}

/** Answer of POST /api/v1/packs/standards: the slugs created and replaced. */
export interface StandardPackImportResult {
  file: string;
  created: string[];
  updated: string[];
}

/** One development standard as listed by GET /api/v1/standards (no content). */
export interface DevStandardSummary {
  slug: string;
  title: string;
  description: string;
  technologies: string[];
  file_patterns: string[];
  enabled: boolean;
  content_chars: number;
  updated_at: string;
  updated_by: string | null;
}

/** GET /api/v1/standards/{slug}: a development standard with its Markdown content. */
export interface DevStandard extends DevStandardSummary {
  content: string;
  created_at: string;
}

/** GET /api/v1/standards */
export interface DevStandardCatalog {
  standards: DevStandardSummary[];
}

/** Input accepted by POST and PUT /api/v1/standards. */
export type DevStandardWrite = Pick<
  DevStandard,
  'slug' | 'title' | 'description' | 'technologies' | 'file_patterns' | 'content' | 'enabled'
>;

/** GET /api/v1/projects */
export interface ProjectSummary {
  project: string;
  reports_total: number;
  /** Null for a project without any report yet. */
  last_report_at: string | null;
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
  review_type: ReviewType | null;
  risk_level: Severity;
  reviewer: string | null;
  author: string | null;
  submitted_by: string | null;
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
  /** Triage decision, made by a person: reason, approver and end of an acceptance. */
  status_reason: string | null;
  status_approver: string | null;
  status_expires_at: string | null;
  /** Status proposed by an agent, never applied until a triager approves it. */
  proposed_status: FindingStatus | null;
  proposed_reason: string | null;
  proposed_by: string | null;
  proposed_at: string | null;
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

/** Statuses that need a reason and an expiry date, decided by a person only. */
export const DISMISSED_STATUSES: readonly FindingStatus[] = ['accepted', 'false_positive'];

/** Body of PATCH /api/v1/findings/{id}: a triage decision. */
export interface FindingDecision {
  status: FindingStatus;
  reason?: string;
  /** YYYY-MM-DD: the finding counts as open again from that day. */
  expires_on?: string;
}

/** A finding of GET /api/v1/findings, with the context of its report. */
export interface ProjectFinding extends Finding {
  project: string;
  branch: string | null;
  commit_sha: string | null;
  review_type: ReviewType | null;
  report_created_at: string;
}

/** GET /api/v1/findings: one page of the findings of a project (null: every project). */
export interface ProjectFindingPage {
  project: string | null;
  total: number;
  findings: ProjectFinding[];
}

/** Query of GET /api/v1/findings. */
export interface ProjectFindingQuery {
  /** Omitted: the findings of every project in the scope of the caller. */
  project?: string;
  status: FindingStatus;
  severity: Severity | '';
  reviewType: ReviewType | '';
  limit: number;
  offset: number;
}

/** GET /api/v1/reports/{id} */
export interface Report {
  id: number;
  project: string;
  repository: string | null;
  branch: string | null;
  commit_sha: string | null;
  reviewer: string | null;
  author: string | null;
  submitted_by: string | null;
  scope: string | null;
  review_type: ReviewType | null;
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
  search?: string;
  sort_by?:
    'created_at' | 'project' | 'risk_level' | 'review_type' | 'branch' | 'author' | 'summary';
  sort_direction?: 'asc' | 'desc';
  limit: number;
  offset: number;
}

/** Body of PUT /api/v1/settings/proxy: a field left out is unchanged, null restores the variable. */
export interface ProxyUpdate {
  /** '' connects directly; null deletes the stored value. Refused when the variable is set. */
  url?: string | null;
  no_proxy?: string | null;
}

/**
 * Body of PUT /api/v1/settings/audit-syslog: a field left out is unchanged, null deletes the
 * stored value. Refused (422) when the variable of the field is set.
 */
export interface AuditSyslogUpdate {
  /** udp:// or tcp:// only. */
  address?: string | null;
  facility?: string | null;
}

/** GET /api/v1/settings/audit-syslog: syslog server of the audit log. */
export interface AuditSyslogSettings {
  /** value: set in the web interface; env: SECREVIEW_AUDIT_SYSLOG_ADDRESS and
   * SECREVIEW_AUDIT_SYSLOG_FACILITY; env_set: the variable is set and takes precedence. */
  address: { value: string | null; env: string | null; env_set: boolean };
  facility: { value: string | null; env: string | null; env_set: boolean };
  effective: {
    address: string | null;
    facility: string;
    source: 'web' | 'environment' | 'none';
  };
  /** Names of the syslog facilities (local0, auth...). */
  facilities: string[];
}

/** GET /api/v1/settings (proxy passwords are replaced by ***) */
export interface AppSettings {
  report_language: {
    /** Set in the web interface ('' lets the agent choose); ignored when env_set. */
    value: string | null;
    env: string;
    /** SECREVIEW_REPORT_LANGUAGE is set: it takes precedence over the stored value. */
    env_set: boolean;
    effective: string;
  };
  /** Proxy of the outgoing connections of the controller (OSV download, OIDC provider). */
  proxy: {
    /** value: set in the web interface ('': direct connection); env: HTTPS_PROXY (else
     * HTTP_PROXY) and NO_PROXY; env_set: the variable is set and takes precedence. */
    url: { value: string | null; env: string | null; env_set: boolean };
    no_proxy: { value: string | null; env: string | null; env_set: boolean };
    effective: {
      url: string | null;
      no_proxy: string | null;
      source: 'web' | 'environment' | 'none';
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

/** GET /api/v1/permissions: a permission and whether it can be limited to projects. */
export interface PermissionInfo {
  name: Permission;
  scoped: boolean;
}

/** A role: a named set of permissions, given to groups. */
export interface AccessRole {
  id: number;
  name: string;
  description: string;
  permissions: Permission[];
  /** reader, triager and admin: neither changed nor deleted. */
  system: boolean;
  /** Only scoped permissions: the role may be limited to projects in a group. */
  scoped: boolean;
  /** Number of groups that have the role. */
  groups: number;
  created_at: string;
  updated_at: string;
  created_by: string | null;
}

/** Body of POST /api/v1/roles and PUT /api/v1/roles/{id}. */
export interface AccessRoleWrite {
  name: string;
  description: string;
  permissions: Permission[];
}

/** A role given to a group or to a user, on every project (null) or on some projects. */
export interface GroupRoleBinding {
  role_id: number;
  name: string;
  projects: string[] | null;
}

/** A member of a group. */
export interface GroupMember {
  user_id: number;
  username: string;
  source: AuthSource;
}

/** A group of web users. */
export interface UserGroup {
  id: number;
  name: string;
  description: string;
  /** The OIDC users whose groups claim holds the name are members too. */
  sso: boolean;
  roles: GroupRoleBinding[];
  members: GroupMember[];
  created_at: string;
  updated_at: string;
  created_by: string | null;
}

/** Body of POST /api/v1/groups and PUT /api/v1/groups/{id}. */
export interface UserGroupWrite {
  name: string;
  description: string;
  sso: boolean;
}

/** GET /api/v1/groups */
export interface GroupCatalog {
  oidc_enabled: boolean;
  roles_claim: string;
  /** OIDC groups created with the admin role at the login of a member (OIDC settings). */
  admin_groups: string[];
  /** Group every OIDC user joins at each login (OIDC settings). */
  default_group: string | null;
  groups: UserGroup[];
}

/** OIDC setting an administrator may change (GET/PUT /api/v1/oidc/settings). */
export type OidcSettingName =
  | 'enabled'
  | 'issuer'
  | 'client_id'
  | 'client_secret'
  | 'redirect_uri'
  | 'scope'
  | 'roles_claim'
  | 'username_claim'
  | 'admin_groups'
  | 'default_group'
  | 'auto_create_users'
  | 'display_name';

/** One OIDC setting: stored in the web interface, variable, effective value. */
export interface OidcSettingValue {
  value: string | boolean | null;
  env: string | boolean | null;
  /** The SECREVIEW_OIDC_* variable is set: it takes precedence over the stored value. */
  env_set: boolean;
  effective: string | boolean | null;
}

/** GET /api/v1/oidc/settings (a set client secret is replaced by ***) */
export interface OidcSettings {
  fields: Record<OidcSettingName, OidcSettingValue>;
  /** SECREVIEW_OIDC_CAFILE, variable only. */
  cafile: string | null;
  callback_path: string;
  /** The OIDC login is enabled and valid on this controller. */
  active: boolean;
}

/** Body of PUT /api/v1/oidc/settings: a field left out is unchanged, null restores the variable. */
export type OidcSettingsUpdate = Partial<Record<OidcSettingName, string | boolean | null>>;

/** POST /api/v1/oidc/settings/test */
export interface OidcTestResult {
  success: boolean;
  steps: { name: string; ok: boolean; detail: string }[];
}
