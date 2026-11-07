import { MessageParams } from '../../core/i18n/i18n.service';
import { MessageKey } from '../../core/i18n/messages';
import { ProjectFinding, ReportSummary, Severity } from '../../core/models/api.models';
import { SearchTarget } from './search-query';

/** Group of the list under the field: what to open, then the findings and reports found. */
export type SuggestionSection = 'actions' | 'findings' | 'reports';

/** One entry of the list under the field. */
export interface Suggestion {
  /** Unique in the list, for the ``@for`` track. */
  key: string;
  section: SuggestionSection;
  target: SearchTarget;
  icon: string;
  /** Translated label (actions) or ``text`` as is (a finding or a report found). */
  label?: MessageKey;
  params?: MessageParams;
  text?: string;
  /** Second line: project, file or branch. */
  detail?: string;
  /** Date of the report of the entry. */
  date?: string;
  severity?: Severity;
  /** Number of matching items, shown next to an action once known. */
  count?: number;
}

/** Entry opening a target (a search, a report, a finding or a project). */
export function describe(target: SearchTarget, count?: number): Suggestion {
  const base = { section: 'actions' as const, target, count };
  switch (target.kind) {
    case 'report':
      return {
        ...base,
        key: `report-${target.id}`,
        icon: 'bi-file-earmark-text',
        label: target.text ? 'layout.searchInReport' : 'layout.searchOpenReport',
        params: { id: target.id, text: target.text },
      };
    case 'finding':
      return {
        ...base,
        key: `finding-${target.id}`,
        icon: 'bi-bug',
        label: 'layout.searchOpenFinding',
        params: { id: target.id },
      };
    case 'reports':
      return {
        ...base,
        key: 'reports',
        icon: 'bi-files',
        label: target.text ? 'layout.searchReports' : 'layout.searchAllReports',
        params: { text: target.text },
      };
    case 'findings':
      return {
        ...base,
        key: 'findings',
        icon: 'bi-shield-check',
        label: target.text ? 'layout.searchFindings' : 'layout.searchAllFindings',
        params: { text: target.text },
      };
    case 'project':
      return {
        ...base,
        key: `project-${target.name}`,
        icon: 'bi-grid-1x2',
        label: 'layout.searchOpenProject',
        params: { name: target.name },
      };
    case 'projectFindings':
      return {
        ...base,
        key: `project-findings-${target.name}`,
        icon: 'bi-shield-check',
        label: 'layout.searchProjectFindings',
        params: { name: target.name },
      };
    case 'projectReports':
      return {
        ...base,
        key: `project-reports-${target.name}`,
        icon: 'bi-files',
        label: 'layout.searchProjectReports',
        params: { name: target.name },
      };
  }
}

/** A finding found by the search: opens its report at its card. */
export function foundFinding(finding: ProjectFinding): Suggestion {
  return {
    key: `found-finding-${finding.id}`,
    section: 'findings',
    target: { kind: 'finding', id: finding.id, reportId: finding.report_id },
    icon: 'bi-bug',
    text: finding.title,
    detail: [finding.project, finding.file_path].filter(Boolean).join(' · '),
    severity: finding.severity,
  };
}

/** A report found by the search: opens it. */
export function foundReport(report: ReportSummary): Suggestion {
  return {
    key: `found-report-${report.report_id}`,
    section: 'reports',
    target: { kind: 'report', id: report.report_id, text: '' },
    icon: 'bi-file-earmark-text',
    text: report.summary.split('\n', 1)[0],
    detail: [`#${report.report_id}`, report.project, report.branch].filter(Boolean).join(' · '),
    date: report.created_at,
    severity: report.risk_level,
  };
}
