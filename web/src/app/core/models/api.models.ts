/** Severity of a finding, from the most to the least critical. */
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

/** Lifecycle status of a finding. */
export type FindingStatus = 'open' | 'fixed' | 'accepted' | 'false_positive';

/** Role of a bearer token: tokens are for machines, a person signs in with a web user. */
export type TokenRole = 'mcp' | 'admin' | 'ci' | 'api';
/** Role of the caller: the role of its token, or `user` for a web user, whose rights are the
 * permissions of its roles. */
export type Role = TokenRole | 'user';
/** Role of a token managed in the web interface. */
export type ProjectTokenRole = Exclude<TokenRole, 'admin'>;
/** Role of a personal token of a web user (My account). */
export type PersonalTokenRole = Extract<TokenRole, 'api' | 'mcp' | 'ci'>;

export const SEVERITIES: readonly Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

/** Higher is worse (same order as the server). */
export const SEVERITY_RANK: Record<Severity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
};

/**
 * A risk of this severity is accepted by a plain validation, with no reason and no expiry date:
 * it is less severe than ``minSeverity`` (SECREVIEW_RISK_ACCEPTANCE_MIN_SEVERITY; null: never).
 */
export function plainAcceptance(severity: Severity, minSeverity: Severity | null): boolean {
  return minSeverity !== null && SEVERITY_RANK[severity] < SEVERITY_RANK[minSeverity];
}

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

/** Result of a checklist item in a review; not_covered is set by the server. */
export type ChecklistOutcome = 'issue' | 'not_verifiable' | 'not_covered' | 'not_applicable' | 'ok';

/** Display order of the checklist outcomes, the ones that need attention first. */
export const CHECKLIST_OUTCOMES: readonly ChecklistOutcome[] = [
  'issue',
  'not_verifiable',
  'not_covered',
  'not_applicable',
  'ok',
];

/** One checklist item of the coverage of a report. */
export interface ChecklistResult {
  item_id: string;
  title: string;
  domain: string;
  outcome: ChecklistOutcome;
}

/** Review types run by an agent with a review prompt: they declare their coverage. */
export const PROMPT_REVIEW_TYPES: readonly ReviewType[] = [
  'security-review',
  'api-security-review',
  'configuration-review',
  'dependency-review',
  'codebase-review',
];

/** Open findings counted by severity. */
export type SeverityCounts = Record<Severity, number>;

/** Permission a role may hold (access_control.Permission on the server). */
export type Permission =
  | 'reports.read'
  | 'reports.write'
  | 'findings.triage'
  | 'rules.read'
  | 'rules.manage'
  | 'standards.read'
  | 'standards.manage'
  | 'tokens.manage'
  | 'settings.manage'
  | 'users.manage'
  | 'audit.read'
  | 'projects.create'
  | 'projects.delete'
  | 'projects.autojoin';

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
  /** A risk may be accepted without an expiry date (SECREVIEW_PERMANENT_ACCEPTANCE_ENABLED). */
  permanent_acceptance?: boolean;
  /**
   * Lowest severity whose acceptance needs a reason and an expiry date
   * (SECREVIEW_RISK_ACCEPTANCE_MIN_SEVERITY); null: every acceptance needs them.
   */
  risk_acceptance_min_severity?: Severity | null;
  /** False when the server offers no personal MCP token (OAuth login of the MCP clients). */
  personal_mcp_tokens?: boolean;
  /**
   * False when the server turned the personal MCP and CI tokens and the OAuth login off
   * (SECREVIEW_PERSONAL_TOKENS_ENABLED).
   */
  personal_tokens_enabled?: boolean;
  /** True while the OAuth login of the MCP clients is on. */
  mcp_oauth?: boolean;
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

/** A role of a web user. */
export interface UserRoleRef {
  role_id: number;
  name: string;
}

/** A project with the per-project permissions given there. */
export interface UserProjectItem {
  project: string;
  permissions: Permission[];
}

/** What the mapping of a value of the roles claim of an OIDC user (last login) gives. */
export interface UserOidcAccess {
  claim: string;
  roles: string[];
  all_projects_permissions: Permission[];
  projects: UserProjectItem[];
}

/** A web user, local or OIDC; the password hash is never returned. */
export interface WebUser {
  id: number;
  username: string;
  auth_source: AuthSource;
  /** Roles (permissions on the whole server), per-project permissions on every project and
   * projects with their permissions, given by an administrator. */
  roles: UserRoleRef[];
  all_projects_permissions: Permission[];
  projects: UserProjectItem[];
  /** Roles and projects of its OIDC mappings (read only, recomputed at each login). */
  oidc: UserOidcAccess[];
  /** Permissions given by its roles; empty: no access. */
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
  /** api role token: its per-project permissions on its projects. */
  project_permissions: Permission[];
  /** api token created by a web user for itself: it holds the current rights of that user. */
  personal: boolean;
  project: string | null;
  projects: string[] | null;
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
  | 'finding.commented'
  | 'finding.severity_changed'
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
  | 'project.deleted'
  | 'project.joined'
  | 'project.autojoin_changed'
  | 'user.roles_changed'
  | 'user.projects_changed'
  | 'oidc.mappings_changed'
  | 'user.login'
  | 'user.login_failed'
  | 'user.logout'
  | 'audit_syslog.changed'
  | 'controller_url.changed'
  | 'finding.exported'
  | 'connector.target_changed'
  | 'connector.changed'
  | 'oauth.client_registered'
  | 'oauth.grant_approved'
  | 'oauth.grant_denied'
  | 'oauth.grant_revoked'
  | 'oauth.refresh_reused'
  | 'mcp_oauth.changed';

export const AUDIT_ACTIONS: readonly AuditAction[] = [
  'finding.status_changed',
  'finding.status_proposed',
  'finding.proposal_rejected',
  'finding.commented',
  'finding.severity_changed',
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
  'project.deleted',
  'project.joined',
  'project.autojoin_changed',
  'user.roles_changed',
  'user.projects_changed',
  'oidc.mappings_changed',
  'user.login',
  'user.login_failed',
  'user.logout',
  'audit_syslog.changed',
  'controller_url.changed',
  'finding.exported',
  'connector.target_changed',
  'connector.changed',
  'oauth.client_registered',
  'oauth.grant_approved',
  'oauth.grant_denied',
  'oauth.grant_revoked',
  'oauth.refresh_reused',
  'mcp_oauth.changed',
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

/** A pending OAuth request of an MCP client, shown by the consent screen. */
export interface OAuthPendingRequest {
  client_id: string;
  /** Chosen by the client itself: shown, never trusted. */
  client_name: string | null;
  redirect_host: string;
  expires_at: string;
}

/** Where the browser goes after a decision on an OAuth request. */
export interface OAuthRedirect {
  redirect_url: string;
}

/** A registered MCP client (name and redirect URIs chosen by the client). */
export interface OAuthClientAdmin {
  client_id: string;
  client_name: string | null;
  redirect_uris: string[];
  created_at: string;
  /** 0: nobody approved it. */
  grants: number;
}

/** A setting of the OAuth login: stored value, variable (it wins when set), effective value. */
export interface OAuthSetting<T> {
  value: T | null;
  env: T | null;
  env_set: boolean;
  effective: T | null;
}

/** Settings of the OAuth login of the MCP clients that the web interface may change. */
export interface OAuthSettings {
  enabled: OAuthSetting<boolean>;
  mcp_url: OAuthSetting<string>;
}

/**
 * Body of PUT /api/v1/oauth/settings: a field left out is unchanged, null deletes the stored
 * value.
 */
export interface OAuthSettingsUpdate {
  enabled?: boolean | null;
  mcp_url?: string | null;
}

/** The OAuth login of the MCP clients: settings, clients and every grant. */
export interface OAuthOverview {
  enabled: boolean;
  mcp_url: string | null;
  redirect_hosts: string[];
  redirect_schemes: string[];
  access_minutes: number;
  refresh_days: number;
  max_clients: number;
  /** Settings an administrator may change here (settings.manage). */
  settings: OAuthSettings;
  clients: OAuthClientAdmin[];
  grants: (OAuthGrant & { username: string })[];
}

/** An MCP client approved by the logged-in user (never its tokens). */
export interface OAuthGrant {
  id: string;
  client_id: string;
  client_name: string | null;
  created_at: string;
  last_used_at: string | null;
  expires_at: string;
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

/** OpenGrep YAML rule file. */
export interface OpenGrepRule { id: string; content: string; updated_at: string; }
export interface OpenGrepRuleCatalog { rules: OpenGrepRule[]; }
export interface OpenGrepRuleWrite { id: string; content: string; }
export interface OpenGrepRuleValidation { valid: boolean; message: string; }


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

/** GET /api/v1/projects/pending: a project requested by the MCP agent of a user, waiting for an approval. */
export interface PendingProject {
  id: number;
  project: string;
  /** The project already exists: the request asks for an access to it. */
  existing: boolean;
  /** Free text given by the client (not verified), its address and its token (or anonymous). */
  requested_by: string | null;
  requested_from: string | null;
  requested_with: string | null;
  created_at: string;
  /** The request is deleted at this date unless it is approved. */
  expires_at: string;
}

/** POST /api/v1/projects/pending/{id}/approve: the requester, if any, got the reader role. */
export interface PendingProjectApproved extends PendingProject {
  granted_to: string | null;
}

/** GET /api/v1/projects */
export interface ProjectSummary {
  project: string;
  reports_total: number;
  /** Null for a project without any report yet. */
  last_report_at: string | null;
  open_findings_total: number;
  open_findings_by_severity: SeverityCounts;
  worst_open_severity: Severity | null;
  /** The holders of projects.autojoin may not join this project at once. */
  autojoin_blocked: boolean;
}

/** PUT /api/v1/projects/{project}/autojoin: whether the autojoin of a project is blocked. */
export interface ProjectAutojoin {
  project: string;
  autojoin_blocked: boolean;
}

/** DELETE /api/v1/projects/{project}: what the deletion removed. */
export interface ProjectDeleted {
  project: string;
  reports: number;
  findings: number;
  /** Users who lost their roles on the project, claims of the OIDC mappings changed. */
  members_removed: number;
  mappings_changed: string[];
  tokens_revoked: number;
  tokens_changed: number;
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
  /** Severity given by the report, when a security analyst raised it (null: never raised). */
  original_severity: Severity | null;
  /** Justification, author and date of the latest severity change by an analyst. */
  severity_reason: string | null;
  severity_changed_by: string | null;
  severity_changed_at: string | null;
  /** Later occurrence of the same issue that replaces this one (null: current). */
  superseded_by: number | null;
  /** Date of the first occurrence of the issue (reset when it comes back after a fix). */
  first_seen_at: string | null;
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
  /** Exports of the finding through the connectors (one per connector). */
  exports: FindingExport[];
}

/** Kind of a connector: jira, servicenow or a third-party one. */
export type ConnectorKind = string;

/** GET /api/v1/connectors: an available connector. */
export interface ConnectorSystem {
  kind: ConnectorKind;
  name: string;
}

/** sending: request in progress; sent: the record exists; failed: the last attempt failed. */
export type ExportState = 'sending' | 'sent' | 'failed';

/** Export of a finding: key and link of its record once it exists, short reason of the last failure. */
export interface FindingExport {
  kind: ConnectorKind;
  state: ExportState;
  external_key: string | null;
  url: string | null;
  error: string | null;
  created_at: string;
  updated_at: string;
}

/** GET /api/v1/connectors/destinations: a project and a system its findings can be sent to. */
export interface ConnectorDestination {
  project: string;
  kind: ConnectorKind;
}

/** Where the findings of a project go in one system, and its automatic sending. */
export interface ConnectorTarget {
  project: string;
  kind: ConnectorKind;
  /** What the system asks for: Jira project key, ServiceNow assignment group... */
  destination: string;
  /** Lowest severity sent automatically (null: by hand only). */
  auto_min_severity: Severity | null;
  auto_since: string | null;
  updated_at: string;
  updated_by: string | null;
}

/** Body of PUT /api/v1/projects/{project}/connector-targets/{kind}. */
export interface ConnectorTargetUpdate {
  destination: string;
  auto_min_severity: Severity | null;
}

/** A field declared by a connector: English texts, translated by language when it can. */
export interface ConnectorFieldInfo {
  name: string;
  label: string;
  help: string;
  placeholder: string;
  secret: boolean;
  required: boolean;
  /** {"fr": {"label": "...", "help": "..."}} */
  translations: Record<string, Record<string, string>>;
}

/** A field of a connection; secrets are '***' when set. */
export interface ConnectorFieldState extends ConnectorFieldInfo {
  variable: string;
  value: string | null;
  env: string | null;
  env_set: boolean;
  effective: string | null;
}

/** A connector: its connection and what a project chooses. */
export interface ConnectorInfo {
  kind: ConnectorKind;
  name: string;
  builtin: boolean;
  configured: boolean;
  /** Switched on: findings may be sent through it. */
  enabled: boolean;
  fields: ConnectorFieldState[];
  destination: ConnectorFieldInfo;
}

/** GET /api/v1/settings/connectors */
export interface ConnectorSettings {
  /** SECREVIEW_CONNECTORS_ENABLED (false: every connector locked off) */
  enabled: boolean;
  interval_seconds: number;
  cafile: string | null;
  /** Third-party connectors allowed by SECREVIEW_CONNECTORS_PLUGINS */
  plugins: string[];
  connectors: ConnectorInfo[];
}

/** Body of PUT /api/v1/settings/connectors/{kind}: null or '' deletes the stored value. */
export type ConnectorUpdate = Record<string, string | null>;

/** POST /api/v1/settings/connectors/{kind}/test */
export interface ConnectorTestResult {
  ok: boolean;
  error: string | null;
  message: string | null;
}

/** Statuses that need a reason and an expiry date, decided by a person only. */
export const DISMISSED_STATUSES: readonly FindingStatus[] = ['accepted', 'false_positive'];

/** Body of PATCH /api/v1/findings/{id}: a triage decision. */
export interface FindingDecision {
  status: FindingStatus;
  reason?: string;
  /** YYYY-MM-DD: the finding counts as open again from that day; null: no expiry (accepted). */
  expires_on?: string | null;
}

/**
 * Body of PATCH /api/v1/findings/{id}/severity: a severity raised by a security analyst, above
 * the one of the report (or equal to it, to undo the escalation), with its justification.
 */
export interface FindingSeverityChange {
  severity: Severity;
  reason: string;
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

/** An accepted risk of GET /api/v1/risk-acceptances (an expired one counts as open again). */
export interface RiskAcceptance extends ProjectFinding {
  expired: boolean;
  comments_total: number;
}

/** GET /api/v1/risk-acceptances: one page of the accepted risks (project null: every project). */
export interface RiskAcceptancePage {
  project: string | null;
  total: number;
  acceptances: RiskAcceptance[];
}

/** Query of GET /api/v1/risk-acceptances. */
export interface RiskAcceptanceQuery {
  /** Omitted: the acceptances of every project in the scope of the caller. */
  project?: string;
  limit: number;
  offset: number;
}

/** GET /api/v1/findings/{id}/comments: a comment, never edited nor deleted. */
export interface FindingComment {
  id: number;
  finding_id: number;
  author: string;
  body: string;
  created_at: string;
}

/** Query of GET /api/v1/findings. */
export interface ProjectFindingQuery {
  /** Omitted: the findings of every project in the scope of the caller. */
  project?: string;
  /** Any of these statuses (empty: open). */
  status: readonly FindingStatus[];
  /** Any of these severities (empty: every severity). */
  severity: readonly Severity[];
  /** Any of these review types (empty: every type). */
  reviewType: readonly ReviewType[];
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
  checklist_results: ChecklistResult[];
  scan_rules: string[];
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
  /** Any of these projects (empty: every project in the scope). */
  project?: readonly string[];
  /** Any of these risk levels (empty: every level). */
  risk_level?: readonly Severity[];
  search?: string;
  sort_by?:
    'created_at' | 'project' | 'risk_level' | 'review_type' | 'branch' | 'submitted_by' | 'summary';
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
  /** udp://, tcp:// or tls:// only. */
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
  /** Public root URL of the controller; its web interface is given to the agents without a token. */
  controller_url: {
    /** Stored: set here, or copied from SECREVIEW_PUBLIC_URL by the controller at start. */
    value: string | null;
    env: string | null;
    /** SECREVIEW_PUBLIC_URL is set on the controller: it takes precedence over this screen. */
    env_set: boolean;
    effective: string | null;
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

/** A role: a named set of permissions, given to users and by OIDC mappings. */
export interface AccessRole {
  id: number;
  name: string;
  description: string;
  permissions: Permission[];
  /** admin: neither changed nor deleted. */
  system: boolean;
  /** Users who hold the role, and OIDC mappings that give it. */
  users: number;
  mappings: number;
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

/** A known project given to a web user (body of the users routes). */
export type UserProjectBinding = UserProjectItem;

/** A list replaced whole by a PUT, with its version (ETag of the GET, sent back in If-Match
 * so that the PUT does not undo a change made since). */
export interface Versioned<T> {
  data: T;
  version: string | null;
}

/** A web user who has a project (GET/PUT /api/v1/access/projects/{project}/members). */
export interface ProjectMember {
  user_id: number;
  username: string;
  auth_source: AuthSource;
  permissions: Permission[];
}

/** A value of the OIDC roles claim that gives roles, per-project permissions on every project
 * and projects with their permissions. */
export interface OidcRoleMapping {
  id: number;
  claim: string;
  role_ids: number[];
  roles: string[];
  all_projects_permissions: Permission[];
  projects: UserProjectItem[];
  created_at: string;
  created_by: string | null;
}

/** An OIDC mapping as sent to PUT /api/v1/oidc/mappings. */
export interface OidcRoleMappingWrite {
  claim: string;
  role_ids: number[];
  all_projects_permissions: Permission[];
  projects: UserProjectItem[];
}

/** GET /api/v1/oidc/mappings */
export interface OidcMappingCatalog {
  oidc_enabled: boolean;
  roles_claim: string;
  /** Values of the claim mapped to admin at the login of a user who holds one (settings). */
  admin_groups: string[];
  mappings: OidcRoleMapping[];
}

/** GET /api/v1/access/projects: a known project. */
export interface KnownProject {
  name: string;
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
