import { DatePipe, SlicePipe } from '@angular/common';
import { Component, computed, inject, input, signal } from '@angular/core';
import { RouterLink } from '@angular/router';
import { REVIEW_TYPE_META } from '../../../core/constants/labels';
import { I18nService } from '../../../core/i18n/i18n.service';
import { TranslatePipe } from '../../../core/i18n/translate.pipe';
import {
    ReportSummary,
    SEVERITIES,
    SEVERITY_RANK,
    Severity,
} from '../../../core/models/api.models';
import { compareTableText, filterAndSortRows } from '../../utils/table-utils';
import { SeverityBadgeComponent } from '../severity-badge/severity-badge.component';
import {
    TableControlFilter,
    TableControlFilterChange,
    TableControlsComponent,
} from '../table-controls/table-controls.component';

type ReportSortKey =
  | 'created_at'
  | 'project'
  | 'risk_level'
  | 'review_type'
  | 'findings_open'
  | 'branch'
  | 'author'
  | 'summary';

/** Table of reports, newest first. */
@Component({
  selector: 'app-report-table',
  imports: [
    RouterLink,
    DatePipe,
    SlicePipe,
    SeverityBadgeComponent,
    TableControlsComponent,
    TranslatePipe,
  ],
  templateUrl: './report-table.component.html',
  styleUrl: './report-table.component.css',
})
export class ReportTableComponent {
  readonly reports = input.required<ReportSummary[]>();

  /** Hide the project column on a project page. */
  readonly showProject = input(true);
  readonly enableControls = input(false);

  private readonly i18n = inject(I18nService);
  readonly search = signal('');
  readonly sort = signal<ReportSortKey>('created_at');
  readonly direction = signal<'asc' | 'desc'>('desc');
  readonly riskFilter = signal<Severity | ''>('');
  readonly sortOptions = computed(() => [
    { value: 'created_at', label: this.i18n.translate('reportTable.date') },
    ...(this.showProject()
      ? [{ value: 'project', label: this.i18n.translate('reportTable.project') }]
      : []),
    { value: 'risk_level', label: this.i18n.translate('reportTable.risk') },
    { value: 'review_type', label: this.i18n.translate('reportTable.reviewType') },
    { value: 'findings_open', label: this.i18n.translate('reportTable.openTotal') },
    { value: 'branch', label: this.i18n.translate('reportTable.branch') },
    { value: 'author', label: this.i18n.translate('reportTable.author') },
    { value: 'summary', label: this.i18n.translate('reportTable.summary') },
  ]);
  readonly filters = computed<TableControlFilter[]>(() => [
    {
      key: 'risk',
      label: this.i18n.translate('reportTable.risk'),
      value: this.riskFilter(),
      options: [
        { value: '', label: this.i18n.translate('common.all') },
        ...SEVERITIES.map((severity) => ({
          value: severity,
          label: this.i18n.translate(`severity.${severity}` as const),
        })),
      ],
    },
  ]);
  readonly visibleReports = computed(() => {
    if (!this.enableControls()) {
      return this.reports();
    }
    const risk = this.riskFilter();
    const reports = this.reports().filter((report) => !risk || report.risk_level === risk);
    const sort = this.sort();
    return filterAndSortRows(
      reports,
      this.search(),
      this.direction(),
      (report) =>
        [
          report.report_id,
          report.created_at,
          report.project,
          report.risk_level,
          report.review_type ? this.i18n.translate(`reviewType.${report.review_type}`) : '',
          report.branch ?? '',
          report.commit_sha ?? '',
          report.author ?? '',
          report.summary,
        ].join(' '),
      (left, right) => {
        if (sort === 'project') {
          return compareTableText(left.project, right.project);
        }
        if (sort === 'risk_level') {
          return SEVERITY_RANK[left.risk_level] - SEVERITY_RANK[right.risk_level];
        }
        if (sort === 'review_type') {
          return compareTableText(left.review_type ?? '', right.review_type ?? '');
        }
        if (sort === 'findings_open') {
          return left.findings_open - right.findings_open;
        }
        if (sort === 'branch') {
          return compareTableText(left.branch ?? '', right.branch ?? '');
        }
        if (sort === 'author') {
          return compareTableText(left.author ?? '', right.author ?? '');
        }
        if (sort === 'summary') {
          return compareTableText(left.summary, right.summary);
        }
        return left.created_at.localeCompare(right.created_at);
      },
    );
  });

  readonly reviewTypeMeta = REVIEW_TYPE_META;

  onSort(value: string): void {
    if (this.sortOptions().some((option) => option.value === value)) {
      this.sort.set(value as ReportSortKey);
    }
  }

  onFilter(change: TableControlFilterChange): void {
    if (change.key === 'risk') {
      this.riskFilter.set(
        SEVERITIES.includes(change.value as Severity) ? (change.value as Severity) : '',
      );
    }
  }
}
