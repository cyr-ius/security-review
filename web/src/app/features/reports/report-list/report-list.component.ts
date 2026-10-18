import { Component, computed, inject, input } from '@angular/core';
import { rxResource } from '@angular/core/rxjs-interop';
import { Router } from '@angular/router';
import { SEVERITY_META } from '../../../core/constants/labels';
import { I18nService } from '../../../core/i18n/i18n.service';
import { TranslatePipe } from '../../../core/i18n/translate.pipe';
import { SEVERITIES, Severity } from '../../../core/models/api.models';
import { ApiService } from '../../../core/services/api.service';
import { RefreshButtonComponent } from '../../../shared/components/refresh-button/refresh-button.component';
import { ReportTableComponent } from '../../../shared/components/report-table/report-table.component';
import {
  TableControlsComponent,
  TableSortDirection,
} from '../../../shared/components/table-controls/table-controls.component';

const PAGE_SIZE = 25;
type ReportSortKey =
  'created_at' | 'project' | 'risk_level' | 'review_type' | 'branch' | 'author' | 'summary';

/** All reports, filtered by project and risk level (filters live in the URL). */
@Component({
  selector: 'app-report-list',
  imports: [ReportTableComponent, RefreshButtonComponent, TableControlsComponent, TranslatePipe],
  templateUrl: './report-list.component.html',
  styleUrl: './report-list.component.css',
})
export class ReportListComponent {
  private readonly api = inject(ApiService);
  private readonly router = inject(Router);
  private readonly i18n = inject(I18nService);

  /** Query parameters ?project=&risk=&page= */
  readonly project = input<string>();
  readonly risk = input<string>();
  readonly page = input<string>();
  readonly search = input<string>();
  readonly sort = input<string>();
  readonly direction = input<string>();

  readonly severities = SEVERITIES;
  readonly severityMeta = SEVERITY_META;
  readonly pageSize = PAGE_SIZE;
  readonly sortKey = computed<ReportSortKey>(() => {
    const value = this.sort();
    return [
      'created_at',
      'project',
      'risk_level',
      'review_type',
      'branch',
      'author',
      'summary',
    ].includes(value ?? '')
      ? (value as ReportSortKey)
      : 'created_at';
  });
  readonly sortDirection = computed<TableSortDirection>(() =>
    this.direction() === 'asc' ? 'asc' : 'desc',
  );
  readonly sortOptions = computed(() => [
    { value: 'created_at', label: this.i18n.translate('reportTable.date') },
    { value: 'project', label: this.i18n.translate('reportTable.project') },
    { value: 'risk_level', label: this.i18n.translate('reportTable.risk') },
    { value: 'review_type', label: this.i18n.translate('reportTable.reviewType') },
    { value: 'branch', label: this.i18n.translate('reportTable.branch') },
    { value: 'author', label: this.i18n.translate('reportTable.author') },
    { value: 'summary', label: this.i18n.translate('reportTable.summary') },
  ]);

  readonly pageNumber = computed(() => Math.max(1, Number.parseInt(this.page() ?? '1', 10) || 1));

  readonly riskLevel = computed<Severity | ''>(() => {
    const risk = this.risk() ?? '';
    return (SEVERITIES as readonly string[]).includes(risk) ? (risk as Severity) : '';
  });

  readonly projects = rxResource({ stream: () => this.api.projects() });

  readonly reports = rxResource({
    params: () => ({
      project: this.project() ?? '',
      risk_level: this.riskLevel(),
      search: this.search()?.trim() || undefined,
      sort_by: this.sortKey(),
      sort_direction: this.sortDirection(),
      // One extra row tells whether a next page exists
      limit: PAGE_SIZE + 1,
      offset: (this.pageNumber() - 1) * PAGE_SIZE,
    }),
    stream: ({ params }) => this.api.reports(params),
  });

  readonly rows = computed(() => (this.reports.value() ?? []).slice(0, PAGE_SIZE));
  readonly hasNext = computed(() => (this.reports.value() ?? []).length > PAGE_SIZE);

  onProject(event: Event): void {
    this.navigate({ project: (event.target as HTMLSelectElement).value || null, page: null });
  }

  onRisk(event: Event): void {
    this.navigate({ risk: (event.target as HTMLSelectElement).value || null, page: null });
  }

  onSearch(value: string): void {
    this.navigate({ search: value || null, page: null }, true);
  }

  onSort(value: string): void {
    if (this.sortOptions().some((option) => option.value === value)) {
      this.navigate({ sort: value, page: null });
    }
  }

  onDirection(value: TableSortDirection): void {
    this.navigate({ direction: value, page: null });
  }

  goToPage(page: number): void {
    this.navigate({ page: page > 1 ? page : null });
  }

  private navigate(queryParams: Record<string, string | number | null>, replaceUrl = false): void {
    this.router.navigate([], { queryParams, queryParamsHandling: 'merge', replaceUrl });
  }
}
