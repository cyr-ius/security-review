import { HttpClient, HttpParams } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { Observable } from 'rxjs';
import {
  About,
  AccessRole,
  AccessRoleWrite,
  AdvisoryOverview,
  AppSettings,
  AuditPage,
  AuditQuery,
  AuditSyslogSettings,
  AuditSyslogUpdate,
  AuthConfig,
  AuthSource,
  ChecklistCatalog,
  ChecklistItemWrite,
  ChecklistReloadResult,
  CustomRuleCatalog,
  CustomRuleWrite,
  DevStandard,
  DevStandardCatalog,
  DevStandardWrite,
  Finding,
  FindingComment,
  FindingDecision,
  FindingSeverityChange,
  GroupCatalog,
  Identity,
  LoginSession,
  OAuthGrant,
  OAuthOverview,
  OAuthPendingRequest,
  OAuthRedirect,
  OAuthSettings,
  OAuthSettingsUpdate,
  OidcSettings,
  OidcSettingsUpdate,
  OidcTestResult,
  PermissionInfo,
  PersonalTokenRole,
  Preferences,
  ProjectDeleted,
  ProjectFindingPage,
  ProjectFindingQuery,
  PendingProject,
  PendingProjectApproved,
  ProjectAutojoin,
  ProjectSummary,
  ProjectToken,
  ProjectTokenCreated,
  ProjectTokenRole,
  ProxyUpdate,
  Report,
  ReportQuery,
  ReportSummary,
  RevokedUser,
  RiskAcceptancePage,
  RiskAcceptanceQuery,
  RulePackImportResult,
  RulePackSection,
  RuleReloadResult,
  StandardPackImportResult,
  ConnectorDestination,
  ConnectorSystem,
  ConnectorKind,
  ConnectorTarget,
  ConnectorTargetUpdate,
  ConnectorSettings,
  ConnectorTestResult,
  ConnectorUpdate,
  FindingExport,
  TokenRoleChoice,
  Trend,
  UpdateStatus,
  UserGroup,
  UserGroupWrite,
  WebUser,
  WebUserWithPassword,
} from '../models/api.models';

/** Base path of the REST API (served by the same origin as the application). */
export const API_URL = '/api/v1';

/** Typed access to the REST API of security-review-mcp. */
@Injectable({ providedIn: 'root' })
export class ApiService {
  private readonly http = inject(HttpClient);

  /** Version and links of the About page. */
  about(): Observable<About> {
    return this.http.get<About>(`${API_URL}/about`);
  }

  /** Latest release on GitHub against the running version. */
  aboutUpdate(): Observable<UpdateStatus> {
    return this.http.get<UpdateStatus>(`${API_URL}/about/update`);
  }

  /** Preferences of the logged-in web user, kept for every browser it uses. */
  preferences(): Observable<Preferences> {
    return this.http.get<Preferences>(`${API_URL}/me/preferences`);
  }

  setPreferences(preferences: Preferences): Observable<Preferences> {
    return this.http.put<Preferences>(`${API_URL}/me/preferences`, preferences);
  }

  me(): Observable<Identity> {
    return this.http.get<Identity>(`${API_URL}/me`);
  }

  /** Login methods offered besides the access token (public route). */
  authConfig(): Observable<AuthConfig> {
    return this.http.get<AuthConfig>(`${API_URL}/auth/config`);
  }

  /** Log a web user in; the returned session is used as a bearer token (public route). */
  login(username: string, password: string): Observable<LoginSession> {
    return this.http.post<LoginSession>(`${API_URL}/auth/login`, { username, password });
  }

  /** Change the password of the logged-in web user; returns a new session. */
  /** Record the logout of the web user in the audit log (the session is then dropped). */
  logout(): Observable<void> {
    return this.http.post<void>(`${API_URL}/me/logout`, null);
  }

  changePassword(currentPassword: string, newPassword: string): Observable<LoginSession> {
    return this.http.put<LoginSession>(`${API_URL}/me/password`, {
      current_password: currentPassword,
      new_password: newPassword,
    });
  }

  users(): Observable<WebUser[]> {
    return this.http.get<WebUser[]>(`${API_URL}/users`);
  }

  /**
   * Create a web user, member of these groups (the only source of its permissions). A local one
   * without password gets a generated one, returned once; an OIDC one has no password and also
   * joins its OIDC groups at each login.
   */
  createUser(
    username: string,
    authSource: AuthSource,
    groupIds: number[],
    password: string | null,
  ): Observable<WebUserWithPassword> {
    return this.http.post<WebUserWithPassword>(`${API_URL}/users`, {
      username,
      auth_source: authSource,
      group_ids: groupIds,
      password,
    });
  }

  /** Replace the groups given to a web user (its OIDC groups are kept). */
  updateUser(id: number, groupIds: number[]): Observable<WebUser> {
    return this.http.put<WebUser>(`${API_URL}/users/${id}`, { group_ids: groupIds });
  }

  /** Replace the password of a web user (generated when null) and end its sessions. */
  resetUserPassword(id: number, password: string | null): Observable<WebUserWithPassword> {
    return this.http.post<WebUserWithPassword>(`${API_URL}/users/${id}/password`, { password });
  }

  /** Delete a web user; a deleted OIDC user is revoked (never created again by a login). */
  deleteUser(id: number): Observable<void> {
    return this.http.delete<void>(`${API_URL}/users/${id}`);
  }

  revokedUsers(): Observable<RevokedUser[]> {
    return this.http.get<RevokedUser[]>(`${API_URL}/users/revoked`);
  }

  /** Let a deleted OIDC user be created again at its next login. */
  liftRevocation(username: string): Observable<void> {
    return this.http.delete<void>(`${API_URL}/users/revoked/${encodeURIComponent(username)}`);
  }

  customRules(): Observable<CustomRuleCatalog> {
    return this.http.get<CustomRuleCatalog>(`${API_URL}/rules`);
  }

  checklistItems(): Observable<ChecklistCatalog> {
    return this.http.get<ChecklistCatalog>(`${API_URL}/checklists`);
  }

  createChecklistItem(item: ChecklistItemWrite): Observable<ChecklistReloadResult> {
    return this.http.post<ChecklistReloadResult>(`${API_URL}/checklists`, item);
  }

  updateChecklistItem(
    domain: string,
    id: string,
    item: ChecklistItemWrite,
  ): Observable<ChecklistReloadResult> {
    return this.http.put<ChecklistReloadResult>(
      `${API_URL}/checklists/${encodeURIComponent(domain)}/${encodeURIComponent(id)}`,
      item,
    );
  }

  deleteChecklistItem(domain: string, id: string): Observable<void> {
    return this.http.delete<void>(
      `${API_URL}/checklists/${encodeURIComponent(domain)}/${encodeURIComponent(id)}`,
    );
  }

  devStandards(): Observable<DevStandardCatalog> {
    return this.http.get<DevStandardCatalog>(`${API_URL}/standards`);
  }

  devStandard(slug: string): Observable<DevStandard> {
    return this.http.get<DevStandard>(`${API_URL}/standards/${encodeURIComponent(slug)}`);
  }

  createDevStandard(standard: DevStandardWrite): Observable<DevStandard> {
    return this.http.post<DevStandard>(`${API_URL}/standards`, standard);
  }

  updateDevStandard(slug: string, standard: DevStandardWrite): Observable<DevStandard> {
    return this.http.put<DevStandard>(`${API_URL}/standards/${encodeURIComponent(slug)}`, standard);
  }

  deleteDevStandard(slug: string): Observable<void> {
    return this.http.delete<void>(`${API_URL}/standards/${encodeURIComponent(slug)}`);
  }

  createCustomRule(rule: CustomRuleWrite): Observable<RuleReloadResult> {
    return this.http.post<RuleReloadResult>(`${API_URL}/rules`, rule);
  }

  updateCustomRule(id: string, rule: CustomRuleWrite): Observable<RuleReloadResult> {
    return this.http.put<RuleReloadResult>(`${API_URL}/rules/${encodeURIComponent(id)}`, rule);
  }

  deleteCustomRule(id: string): Observable<void> {
    return this.http.delete<void>(`${API_URL}/rules/${encodeURIComponent(id)}`);
  }

  setCustomRuleEnabled(id: string, enabled: boolean): Observable<RuleReloadResult> {
    return this.http.patch<RuleReloadResult>(`${API_URL}/rules/${encodeURIComponent(id)}/enabled`, {
      enabled,
    });
  }

  reloadCustomRules(): Observable<RuleReloadResult> {
    return this.http.post<RuleReloadResult>(`${API_URL}/rules/reload`, {});
  }

  /** TOML pack of the rules and checklist items that differ from the defaults. */
  exportRulePack(sections: RulePackSection[]): Observable<Blob> {
    let params = new HttpParams();
    for (const section of sections) {
      params = params.append('sections', section);
    }
    return this.http.get(`${API_URL}/packs/rules`, { params, responseType: 'blob' });
  }

  importRulePack(name: string, content: string): Observable<RulePackImportResult> {
    return this.http.post<RulePackImportResult>(`${API_URL}/packs/rules`, { name, content });
  }

  /** TOML pack of every development standard (disabled ones included). */
  exportStandardPack(): Observable<Blob> {
    return this.http.get(`${API_URL}/packs/standards`, { responseType: 'blob' });
  }

  importStandardPack(name: string, content: string): Observable<StandardPackImportResult> {
    return this.http.post<StandardPackImportResult>(`${API_URL}/packs/standards`, {
      name,
      content,
    });
  }

  projects(): Observable<ProjectSummary[]> {
    return this.http.get<ProjectSummary[]>(`${API_URL}/projects`);
  }

  /** POST /api/v1/projects: a new project, read by its creator (projects.create). */
  createProject(project: string): Observable<ProjectSummary> {
    return this.http.post<ProjectSummary>(`${API_URL}/projects`, { project });
  }

  /** GET /api/v1/projects/pending: projects requested by MCP agents (projects.create). */
  pendingProjects(): Observable<PendingProject[]> {
    return this.http.get<PendingProject[]>(`${API_URL}/projects/pending`);
  }

  /** Approve a requested project: the requester joins its project group, created when missing. */
  approvePendingProject(id: number): Observable<PendingProjectApproved> {
    return this.http.post<PendingProjectApproved>(
      `${API_URL}/projects/pending/${id}/approve`,
      null,
    );
  }

  /** Reject a requested project: the request is deleted. */
  rejectPendingProject(id: number): Observable<void> {
    return this.http.delete<void>(`${API_URL}/projects/pending/${id}`);
  }

  /** PUT /api/v1/projects/{project}/autojoin: block or allow again the autojoin of a project
   * the caller reads (projects.create). */
  setProjectAutojoin(project: string, blocked: boolean): Observable<ProjectAutojoin> {
    return this.http.put<ProjectAutojoin>(
      `${API_URL}/projects/${encodeURIComponent(project)}/autojoin`,
      { blocked },
    );
  }

  /** DELETE /api/v1/projects/{project}: the project and its references (projects.delete). */
  deleteProject(project: string): Observable<ProjectDeleted> {
    return this.http.delete<ProjectDeleted>(`${API_URL}/projects/${encodeURIComponent(project)}`);
  }

  projectTokens(): Observable<ProjectToken[]> {
    return this.http.get<ProjectToken[]>(`${API_URL}/project-tokens`);
  }

  /**
   * projects null: every project (refused for a CI/CD token). expiresInDays null: the default
   * validity of the server (SECREVIEW_TOKEN_MAX_DAYS). accessRoleId: the role of an api token.
   */
  createProjectToken(
    label: string,
    projects: string[] | null,
    role: ProjectTokenRole,
    expiresInDays: number | null = null,
    accessRoleId: number | null = null,
  ): Observable<ProjectTokenCreated> {
    return this.http.post<ProjectTokenCreated>(`${API_URL}/project-tokens`, {
      label,
      projects,
      role,
      expires_in_days: expiresInDays,
      access_role_id: accessRoleId,
    });
  }

  /** The roles an api token may hold. */
  tokenRoles(): Observable<TokenRoleChoice[]> {
    return this.http.get<TokenRoleChoice[]>(`${API_URL}/project-tokens/roles`);
  }

  /** The personal tokens (REST API and MCP) of the logged-in user. */
  myTokens(): Observable<ProjectToken[]> {
    return this.http.get<ProjectToken[]>(`${API_URL}/me/tokens`);
  }

  /** Create a personal token of the logged-in user: api (its rights) or mcp (the projects it
   * may read); its secret is shown once. */
  createMyToken(
    label: string,
    expiresInDays: number | null,
    role: PersonalTokenRole = 'api',
  ): Observable<ProjectTokenCreated> {
    return this.http.post<ProjectTokenCreated>(`${API_URL}/me/tokens`, {
      label,
      role,
      expires_in_days: expiresInDays,
    });
  }

  deleteMyToken(id: string): Observable<void> {
    return this.http.delete<void>(`${API_URL}/me/tokens/${encodeURIComponent(id)}`);
  }

  /** A pending OAuth request of an MCP client (consent screen). */
  oauthRequest(request: string): Observable<OAuthPendingRequest> {
    return this.http.post<OAuthPendingRequest>(`${API_URL}/oauth/request`, { request });
  }

  /** Approve or deny a pending OAuth request: the answer gives where the browser goes. */
  oauthDecide(request: string, approve: boolean): Observable<OAuthRedirect> {
    const decision = approve ? 'approve' : 'deny';
    return this.http.post<OAuthRedirect>(`${API_URL}/oauth/${decision}`, { request });
  }

  /** The MCP clients the logged-in user approved. */
  myOAuthGrants(): Observable<OAuthGrant[]> {
    return this.http.get<OAuthGrant[]>(`${API_URL}/me/oauth-grants`);
  }

  /** Every OAuth client and grant (tokens.manage). */
  oauthOverview(): Observable<OAuthOverview> {
    return this.http.get<OAuthOverview>(`${API_URL}/oauth/clients`);
  }

  /** Turn the OAuth login on or off and set the URL of the MCP endpoint (settings.manage). */
  setOAuthSettings(values: OAuthSettingsUpdate): Observable<OAuthSettings> {
    return this.http.put<OAuthSettings>(`${API_URL}/oauth/settings`, values);
  }

  revokeOAuthGrant(id: string): Observable<void> {
    return this.http.delete<void>(`${API_URL}/oauth/grants/${encodeURIComponent(id)}`);
  }

  deleteOAuthClient(clientId: string): Observable<void> {
    return this.http.delete<void>(`${API_URL}/oauth/clients/${encodeURIComponent(clientId)}`);
  }

  deleteMyOAuthGrant(id: string): Observable<void> {
    return this.http.delete<void>(`${API_URL}/me/oauth-grants/${encodeURIComponent(id)}`);
  }

  /** Change the projects of a token (null: every project); its secret stays the same. */
  updateProjectTokenProjects(id: string, projects: string[] | null): Observable<ProjectToken> {
    return this.http.put<ProjectToken>(
      `${API_URL}/project-tokens/${encodeURIComponent(id)}/projects`,
      { projects },
    );
  }

  /** Replace the secret of a project token; the previous one works for graceHours more. */
  rotateProjectToken(id: string, graceHours: number): Observable<ProjectTokenCreated> {
    return this.http.post<ProjectTokenCreated>(
      `${API_URL}/project-tokens/${encodeURIComponent(id)}/rotate`,
      { grace_hours: graceHours },
    );
  }

  auditEvents(query: AuditQuery): Observable<AuditPage> {
    let params = new HttpParams().set('limit', query.limit).set('offset', query.offset);
    if (query.action) {
      params = params.set('action', query.action);
    }
    if (query.project) {
      params = params.set('project', query.project);
    }
    if (query.search) {
      params = params.set('search', query.search);
    }
    if (query.sort_by) {
      params = params.set('sort_by', query.sort_by);
    }
    if (query.sort_direction) {
      params = params.set('sort_direction', query.sort_direction);
    }
    return this.http.get<AuditPage>(`${API_URL}/audit`, { params });
  }

  deleteProjectToken(id: string): Observable<void> {
    return this.http.delete<void>(`${API_URL}/project-tokens/${encodeURIComponent(id)}`);
  }

  reports(query: ReportQuery): Observable<ReportSummary[]> {
    let params = new HttpParams()
      .set('limit', query.limit)
      .set('offset', query.offset)
      .appendAll({
        project: [...(query.project ?? [])],
        risk_level: [...(query.risk_level ?? [])],
      });
    if (query.search) {
      params = params.set('search', query.search);
    }
    if (query.sort_by) {
      params = params.set('sort_by', query.sort_by);
    }
    if (query.sort_direction) {
      params = params.set('sort_direction', query.sort_direction);
    }
    return this.http.get<ReportSummary[]>(`${API_URL}/reports`, { params });
  }

  report(id: number): Observable<Report> {
    return this.http.get<Report>(`${API_URL}/reports/${id}`);
  }

  trend(project: string, days: number, granularity: Trend['granularity']): Observable<Trend> {
    const params = new HttpParams()
      .set('project', project)
      .set('days', days)
      .set('granularity', granularity);
    return this.http.get<Trend>(`${API_URL}/trend`, { params });
  }

  /** Findings of a project (or of every project) across all reports, worst first. */
  projectFindings(query: ProjectFindingQuery): Observable<ProjectFindingPage> {
    // Repeated parameters: any of the values matches
    let params = new HttpParams()
      .set('limit', query.limit)
      .set('offset', query.offset)
      .appendAll({
        status: [...query.status],
        severity: [...query.severity],
        review_type: [...query.reviewType],
      });
    if (query.project) {
      params = params.set('project', query.project);
    }
    return this.http.get<ProjectFindingPage>(`${API_URL}/findings`, { params });
  }

  /** Record a triage decision (accepted needs a reason and an expiry, false_positive neither). */
  updateFindingStatus(id: number, decision: FindingDecision): Observable<Finding> {
    return this.http.patch<Finding>(`${API_URL}/findings/${id}`, decision);
  }

  /** Raise the severity of a finding, with the justification of the analyst. */
  updateFindingSeverity(id: number, change: FindingSeverityChange): Observable<Finding> {
    return this.http.patch<Finding>(`${API_URL}/findings/${id}/severity`, change);
  }

  /** Reject the status proposed by an agent (the status does not change). */
  rejectFindingProposal(id: number): Observable<Finding> {
    return this.http.delete<Finding>(`${API_URL}/findings/${id}/proposal`);
  }

  /** Accepted risks of a project (or of every project), expired ones included. */
  riskAcceptances(query: RiskAcceptanceQuery): Observable<RiskAcceptancePage> {
    let params = new HttpParams().set('limit', query.limit).set('offset', query.offset);
    if (query.project) {
      params = params.set('project', query.project);
    }
    return this.http.get<RiskAcceptancePage>(`${API_URL}/risk-acceptances`, { params });
  }

  /** Comments of a finding, oldest first. */
  findingComments(id: number): Observable<FindingComment[]> {
    return this.http.get<FindingComment[]>(`${API_URL}/findings/${id}/comments`);
  }

  /** Comment a finding (a comment can never be edited nor deleted). */
  addFindingComment(id: number, body: string): Observable<FindingComment> {
    return this.http.post<FindingComment>(`${API_URL}/findings/${id}/comments`, { body });
  }

  /** Download the Markdown version of a report. */
  reportMarkdown(id: number): Observable<Blob> {
    return this.http.get(`${API_URL}/reports/${id}/markdown`, { responseType: 'blob' });
  }

  /** Download the SARIF export of a project or of a report. */
  sarif(target: { project: string } | { report_id: number }): Observable<Blob> {
    let params = new HttpParams();
    params =
      'project' in target
        ? params.set('project', target.project)
        : params.set('report_id', target.report_id);
    return this.http.get(`${API_URL}/sarif`, { params, responseType: 'blob' });
  }

  appSettings(): Observable<AppSettings> {
    return this.http.get<AppSettings>(`${API_URL}/settings`);
  }

  /** '' lets the agent choose, null restores SECREVIEW_REPORT_LANGUAGE. */
  setReportLanguage(value: string | null): Observable<AppSettings> {
    return this.http.put<AppSettings>(`${API_URL}/settings/report-language`, { value });
  }

  /** null (or '') removes the stored URL of the controller. */
  setControllerUrl(value: string | null): Observable<AppSettings> {
    return this.http.put<AppSettings>(`${API_URL}/settings/controller-url`, { value });
  }

  /** A field left out is unchanged; null restores the variable, url '' connects directly. */
  setProxy(values: ProxyUpdate): Observable<AppSettings> {
    return this.http.put<AppSettings>(`${API_URL}/settings/proxy`, values);
  }

  auditSyslog(): Observable<AuditSyslogSettings> {
    return this.http.get<AuditSyslogSettings>(`${API_URL}/settings/audit-syslog`);
  }

  /** A field left out is unchanged; null restores the variable, address '' stops forwarding. */
  setAuditSyslog(values: AuditSyslogUpdate): Observable<AuditSyslogSettings> {
    return this.http.put<AuditSyslogSettings>(`${API_URL}/settings/audit-syslog`, values);
  }

  connectors(): Observable<ConnectorSettings> {
    return this.http.get<ConnectorSettings>(`${API_URL}/settings/connectors`);
  }

  /** A field left out is unchanged; null or '' deletes it; a secret sent back as '***' is kept. */
  setConnector(kind: ConnectorKind, values: ConnectorUpdate): Observable<ConnectorSettings> {
    return this.http.put<ConnectorSettings>(`${API_URL}/settings/connectors/${kind}`, values);
  }

  /** Switch a connector on or off (refused while its connection is not configured). */
  switchConnector(kind: ConnectorKind, enabled: boolean): Observable<ConnectorSettings> {
    return this.http.put<ConnectorSettings>(`${API_URL}/settings/connectors/${kind}/enabled`, {
      enabled,
    });
  }

  /** Test the connection with the stored values and ``values`` (not stored). */
  testConnector(kind: ConnectorKind, values: ConnectorUpdate): Observable<ConnectorTestResult> {
    return this.http.post<ConnectorTestResult>(
      `${API_URL}/settings/connectors/${kind}/test`,
      values,
    );
  }

  connectorTargets(): Observable<ConnectorTarget[]> {
    return this.http.get<ConnectorTarget[]>(`${API_URL}/connectors/targets`);
  }

  setConnectorTarget(
    project: string,
    kind: ConnectorKind,
    target: ConnectorTargetUpdate,
  ): Observable<ConnectorTarget> {
    return this.http.put<ConnectorTarget>(
      `${API_URL}/projects/${encodeURIComponent(project)}/connector-targets/${kind}`,
      target,
    );
  }

  deleteConnectorTarget(project: string, kind: ConnectorKind): Observable<void> {
    return this.http.delete<void>(
      `${API_URL}/projects/${encodeURIComponent(project)}/connector-targets/${kind}`,
    );
  }

  /** Available connectors, to label the exports of the findings. */
  connectorSystems(): Observable<ConnectorSystem[]> {
    return this.http.get<ConnectorSystem[]>(`${API_URL}/connectors`);
  }

  /** Projects and systems the current user may send findings to now. */
  connectorDestinations(): Observable<ConnectorDestination[]> {
    return this.http.get<ConnectorDestination[]>(`${API_URL}/connectors/destinations`);
  }

  exportFinding(id: number, kind: ConnectorKind): Observable<FindingExport> {
    return this.http.post<FindingExport>(`${API_URL}/findings/${id}/exports/${kind}`, {});
  }

  advisories(): Observable<AdvisoryOverview> {
    return this.http.get<AdvisoryOverview>(`${API_URL}/advisories`);
  }

  startAdvisoryUpdate(): Observable<{ id: number }> {
    return this.http.post<{ id: number }>(`${API_URL}/advisories/update`, {});
  }

  oidcSettings(): Observable<OidcSettings> {
    return this.http.get<OidcSettings>(`${API_URL}/oidc/settings`);
  }

  /** A field left out is unchanged; null restores the SECREVIEW_OIDC_* variable. */
  setOidcSettings(values: OidcSettingsUpdate): Observable<OidcSettings> {
    return this.http.put<OidcSettings>(`${API_URL}/oidc/settings`, values);
  }

  /** Test the identity provider of these values (over the effective ones), nothing stored. */
  testOidcSettings(values: OidcSettingsUpdate): Observable<OidcTestResult> {
    return this.http.post<OidcTestResult>(`${API_URL}/oidc/settings/test`, values);
  }

  /** Permissions a role may hold, and whether they can be limited to projects. */
  permissions(): Observable<PermissionInfo[]> {
    return this.http.get<PermissionInfo[]>(`${API_URL}/permissions`);
  }

  roles(): Observable<AccessRole[]> {
    return this.http.get<AccessRole[]>(`${API_URL}/roles`);
  }

  createRole(role: AccessRoleWrite): Observable<AccessRole> {
    return this.http.post<AccessRole>(`${API_URL}/roles`, role);
  }

  updateRole(id: number, role: AccessRoleWrite): Observable<AccessRole> {
    return this.http.put<AccessRole>(`${API_URL}/roles/${id}`, role);
  }

  deleteRole(id: number): Observable<void> {
    return this.http.delete<void>(`${API_URL}/roles/${id}`);
  }

  groups(): Observable<GroupCatalog> {
    return this.http.get<GroupCatalog>(`${API_URL}/groups`);
  }

  createGroup(group: UserGroupWrite): Observable<UserGroup> {
    return this.http.post<UserGroup>(`${API_URL}/groups`, group);
  }

  updateGroup(id: number, group: UserGroupWrite): Observable<UserGroup> {
    return this.http.put<UserGroup>(`${API_URL}/groups/${id}`, group);
  }

  /** Replace the roles of a group; an empty project list reaches every project. */
  setGroupRoles(
    id: number,
    roles: { role_id: number; projects: string[] }[],
  ): Observable<UserGroup> {
    return this.http.put<UserGroup>(`${API_URL}/groups/${id}/roles`, { roles });
  }

  /** Replace the members added by an administrator (the OIDC members are kept). */
  setGroupMembers(id: number, userIds: number[]): Observable<UserGroup> {
    return this.http.put<UserGroup>(`${API_URL}/groups/${id}/members`, { user_ids: userIds });
  }

  deleteGroup(id: number): Observable<void> {
    return this.http.delete<void>(`${API_URL}/groups/${id}`);
  }
}

/** Save a downloaded blob as a file (the API needs the bearer header, so no plain link). */
export function saveBlob(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
}
