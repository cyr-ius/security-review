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
import { TableSort } from '../../utils/table-sort';
import { compareTableText, filterAndSortRows } from '../../utils/table-utils';
import { SeverityBadgeComponent } from '../severity-badge/severity-badge.component';
import { SortHeaderComponent } from '../sort-header/sort-header.component';
import {
  TableControlFilter,
  TableControlFilterChange,
  TableControlsComponent,
} from '../table-controls/table-controls.component';

export type ReportSortKey =
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
    SortHeaderComponent,
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
  /**
   * Sort applied by the server to the given reports (paginated list): the rows are shown in
   * their order. Without it, the table sorts its rows itself.
   */
  readonly serverSort = input<TableSort<ReportSortKey> | null>(null);

  private readonly i18n = inject(I18nService);
  readonly search = signal('');
  private readonly localSort = new TableSort<ReportSortKey>(
    'project-reports',
    [
      'created_at',
      'project',
      'risk_level',
      'review_type',
      'findings_open',
      'branch',
      'author',
      'summary',
    ],
    'created_at',
    'desc',
  );
  readonly sort = computed(() => this.serverSort() ?? this.localSort);
  readonly riskFilter = signal<Severity | ''>('');
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
    if (this.serverSort()) {
      return this.reports();
    }
    const risk = this.enableControls() ? this.riskFilter() : '';
    const reports = this.reports().filter((report) => !risk || report.risk_level === risk);
    const sort = this.localSort.key();
    return filterAndSortRows(
      reports,
      this.enableControls() ? this.search() : '',
      this.localSort.direction(),
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

  onFilter(change: TableControlFilterChange): void {
    if (change.key === 'risk') {
      this.riskFilter.set(
        SEVERITIES.includes(change.value as Severity) ? (change.value as Severity) : '',
      );
    }
  }
}
