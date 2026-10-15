import { HttpClient, HttpParams } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { Observable } from 'rxjs';
import {
  AdvisoryOverview,
  AppSettings,
  AuthConfig,
  AuthSource,
  Finding,
  FindingStatus,
  ChecklistCatalog,
  ChecklistItemWrite,
  ChecklistReloadResult,
  CustomRuleCatalog,
  CustomRuleWrite,
  DevStandard,
  DevStandardCatalog,
  DevStandardWrite,
  EnrollmentApproved,
  EnrollmentRequest,
  Identity,
  LoginSession,
  OidcSettings,
  OidcSettingsUpdate,
  OidcTestResult,
  ProjectSummary,
  ProjectToken,
  ProjectTokenCreated,
  ProjectTokenRole,
  MappedRole,
  ProxyMode,
  RoleMapping,
  RevokedUser,
  RoleMappingCatalog,
  Report,
  ReportQuery,
  ReportSummary,
  RuleReloadResult,
  Trend,
  WebUser,
  WebUserRole,
  WebUserWithPassword,
} from '../models/api.models';

/** Base path of the REST API (served by the same origin as the application). */
export const API_URL = '/api/v1';

/** Typed access to the REST API of security-review-mcp. */
@Injectable({ providedIn: 'root' })
export class ApiService {
  private readonly http = inject(HttpClient);

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
   * Create a web user. A local one without password gets a generated one, returned once; an
   * SSO one has no password and may have no role (null).
   */
  createUser(
    username: string,
    authSource: AuthSource,
    role: WebUserRole | null,
    projects: string[],
    password: string | null,
  ): Observable<WebUserWithPassword> {
    return this.http.post<WebUserWithPassword>(`${API_URL}/users`, {
      username,
      auth_source: authSource,
      role,
      projects,
      password,
    });
  }

  updateUser(id: number, role: WebUserRole | null, projects: string[]): Observable<WebUser> {
    return this.http.put<WebUser>(`${API_URL}/users/${id}`, { role, projects });
  }

  /** Replace the password of a web user (generated when null) and end its sessions. */
  resetUserPassword(id: number, password: string | null): Observable<WebUserWithPassword> {
    return this.http.post<WebUserWithPassword>(`${API_URL}/users/${id}/password`, { password });
  }

  /** Delete a web user; a deleted SSO user is revoked (never created again by a login). */
  deleteUser(id: number): Observable<void> {
    return this.http.delete<void>(`${API_URL}/users/${id}`);
  }

  revokedUsers(): Observable<RevokedUser[]> {
    return this.http.get<RevokedUser[]>(`${API_URL}/users/revoked`);
  }

  /** Let a deleted SSO user be created again at its next login. */
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

  projects(): Observable<ProjectSummary[]> {
    return this.http.get<ProjectSummary[]>(`${API_URL}/projects`);
  }

  projectTokens(): Observable<ProjectToken[]> {
    return this.http.get<ProjectToken[]>(`${API_URL}/project-tokens`);
  }

  createProjectToken(
    label: string,
    projects: string[],
    role: ProjectTokenRole,
  ): Observable<ProjectTokenCreated> {
    return this.http.post<ProjectTokenCreated>(`${API_URL}/project-tokens`, {
      label,
      projects,
      role,
    });
  }

  deleteProjectToken(id: string): Observable<void> {
    return this.http.delete<void>(`${API_URL}/project-tokens/${encodeURIComponent(id)}`);
  }

  enrollments(): Observable<EnrollmentRequest[]> {
    return this.http.get<EnrollmentRequest[]>(`${API_URL}/enrollments`);
  }

  /**
   * With portalUser, that web user also reads the project in the web UI (an unknown name
   * becomes an SSO user when OIDC is enabled).
   */
  approveEnrollment(id: string, portalUser: string | null = null): Observable<EnrollmentApproved> {
    return this.http.post<EnrollmentApproved>(
      `${API_URL}/enrollments/${encodeURIComponent(id)}/approve`,
      { portal_user: portalUser },
    );
  }

  rejectEnrollment(id: string): Observable<void> {
    return this.http.delete<void>(`${API_URL}/enrollments/${encodeURIComponent(id)}`);
  }

  reports(query: ReportQuery): Observable<ReportSummary[]> {
    let params = new HttpParams().set('limit', query.limit).set('offset', query.offset);
    if (query.project) {
      params = params.set('project', query.project);
    }
    if (query.risk_level) {
      params = params.set('risk_level', query.risk_level);
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

  updateFindingStatus(id: number, status: FindingStatus): Observable<Finding> {
    return this.http.patch<Finding>(`${API_URL}/findings/${id}`, { status });
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

  setOsvProxy(mode: ProxyMode, url: string | null): Observable<AppSettings> {
    return this.http.put<AppSettings>(`${API_URL}/settings/osv-proxy`, { mode, url });
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

  roleMappings(): Observable<RoleMappingCatalog> {
    return this.http.get<RoleMappingCatalog>(`${API_URL}/oidc/role-mappings`);
  }

  /** An empty project list reaches every project. */
  createRoleMapping(
    claimValue: string,
    role: MappedRole,
    projects: string[],
  ): Observable<RoleMapping> {
    return this.http.post<RoleMapping>(`${API_URL}/oidc/role-mappings`, {
      claim_value: claimValue,
      role,
      projects,
    });
  }

  updateRoleMapping(id: number, projects: string[]): Observable<RoleMapping> {
    return this.http.put<RoleMapping>(`${API_URL}/oidc/role-mappings/${id}`, { projects });
  }

  deleteRoleMapping(id: number): Observable<void> {
    return this.http.delete<void>(`${API_URL}/oidc/role-mappings/${id}`);
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
