import { DatePipe } from '@angular/common';
import { Component, computed, inject, signal } from '@angular/core';
import { rxResource } from '@angular/core/rxjs-interop';
import { RouterLink } from '@angular/router';
import { SEVERITY_META } from '../../../core/constants/labels';
import { I18nService } from '../../../core/i18n/i18n.service';
import { TranslatePipe } from '../../../core/i18n/translate.pipe';
import {
  SEVERITIES,
  SEVERITY_RANK,
  Severity,
  SeverityCounts,
} from '../../../core/models/api.models';
import { ApiService } from '../../../core/services/api.service';
import { RefreshButtonComponent } from '../../../shared/components/refresh-button/refresh-button.component';
import { SeverityBadgeComponent } from '../../../shared/components/severity-badge/severity-badge.component';
import { SeverityCountsComponent } from '../../../shared/components/severity-counts/severity-counts.component';
import {
  TableControlFilter,
  TableControlFilterChange,
  TableControlsComponent,
} from '../../../shared/components/table-controls/table-controls.component';
import { filterAndSortRows } from '../../../shared/utils/table-utils';

type SortKey = 'risk' | 'activity' | 'name';

/** Dashboard: every project with its open findings. */
@Component({
  selector: 'app-project-list',
  imports: [
    RouterLink,
    DatePipe,
    SeverityBadgeComponent,
    SeverityCountsComponent,
    RefreshButtonComponent,
    TableControlsComponent,
    TranslatePipe,
  ],
  templateUrl: './project-list.component.html',
  styleUrl: './project-list.component.css',
})
export class ProjectListComponent {
  private readonly api = inject(ApiService);
  private readonly i18n = inject(I18nService);

  readonly severities = SEVERITIES;
  readonly severityMeta = SEVERITY_META;

  readonly projects = rxResource({ stream: () => this.api.projects() });

  readonly search = signal('');
  readonly sort = signal<SortKey>('risk');
  readonly direction = signal<'asc' | 'desc'>('desc');
  readonly severityFilter = signal<Severity | 'none' | ''>('');
  readonly sortOptions = computed(() => [
    { value: 'risk', label: this.i18n.translate('projects.sortRisk') },
    { value: 'activity', label: this.i18n.translate('projects.sortActivity') },
    { value: 'name', label: this.i18n.translate('projects.sortName') },
  ]);
  readonly filters = computed<TableControlFilter[]>(() => [
    {
      key: 'severity',
      label: this.i18n.translate('projects.worst'),
      value: this.severityFilter(),
      options: [
        { value: '', label: this.i18n.translate('common.all') },
        ...SEVERITIES.map((severity) => ({
          value: severity,
          label: this.i18n.translate(this.severityMeta[severity].label),
        })),
        { value: 'none', label: this.i18n.translate('projects.none') },
      ],
    },
  ]);

  /** Open findings of every project added up. */
  readonly totals = computed<SeverityCounts>(() => {
    const totals = Object.fromEntries(SEVERITIES.map((s) => [s, 0])) as SeverityCounts;
    for (const project of this.projects.value() ?? []) {
      for (const severity of SEVERITIES) {
        totals[severity] += project.open_findings_by_severity[severity];
      }
    }
    return totals;
  });

  /** Open findings of every project, shown on the review button. */
  readonly openTotal = computed(() =>
    SEVERITIES.reduce((sum, severity) => sum + this.totals()[severity], 0),
  );

  readonly visible = computed(() => {
    const severity = this.severityFilter();
    const rows = (this.projects.value() ?? []).filter(
      (project) =>
        !severity ||
        (severity === 'none'
          ? project.worst_open_severity === null
          : project.worst_open_severity === severity),
    );
    const sort = this.sort();
    return filterAndSortRows(
      rows,
      this.search(),
      this.direction(),
      (project) => project.project,
      (a, b) => {
        if (sort === 'name') {
          return a.project.localeCompare(b.project, undefined, {
            numeric: true,
            sensitivity: 'base',
          });
        }
        if (sort === 'activity') {
          return a.last_report_at.localeCompare(b.last_report_at);
        }
        return (
          rank(a.worst_open_severity) - rank(b.worst_open_severity) ||
          a.open_findings_total - b.open_findings_total
        );
      },
    );
  });

  onSortValue(value: string): void {
    if (value === 'risk' || value === 'activity' || value === 'name') {
      this.sort.set(value);
    }
  }

  onProjectTableFilter(change: TableControlFilterChange): void {
    if (change.key === 'severity') {
      this.severityFilter.set(
        change.value === 'none' || SEVERITIES.includes(change.value as Severity)
          ? (change.value as Severity | 'none')
          : '',
      );
    }
  }
}

function rank(severity: Severity | null): number {
  return severity ? SEVERITY_RANK[severity] : -1;
}
