import { HttpClient, HttpParams } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { Observable } from 'rxjs';
import {
  AdvisoryOverview,
  AppSettings,
  AuthConfig,
  Finding,
  FindingStatus,
  ChecklistCatalog,
  ChecklistItemWrite,
  ChecklistReloadResult,
  CustomRuleCatalog,
  CustomRuleWrite,
  EnrollmentRequest,
  Identity,
  ProjectSummary,
  ProjectToken,
  ProjectTokenCreated,
  ProjectTokenRole,
  ProxyMode,
  Report,
  ReportQuery,
  ReportSummary,
  RuleReloadResult,
  Trend,
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

  /** Login methods offered besides the password or token (public route). */
  authConfig(): Observable<AuthConfig> {
    return this.http.get<AuthConfig>(`${API_URL}/auth/config`);
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

  approveEnrollment(id: string): Observable<EnrollmentRequest> {
    return this.http.post<EnrollmentRequest>(
      `${API_URL}/enrollments/${encodeURIComponent(id)}/approve`,
      {},
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
