import { Component, computed, inject, input } from '@angular/core';
import { rxResource } from '@angular/core/rxjs-interop';
import { Router } from '@angular/router';
import { SEVERITY_META } from '../../../core/constants/labels';
import { I18nService } from '../../../core/i18n/i18n.service';
import { TranslatePipe } from '../../../core/i18n/translate.pipe';
import { SEVERITIES } from '../../../core/models/api.models';
import { ApiService } from '../../../core/services/api.service';
import {
  MultiSelectDropdownComponent,
  MultiSelectOption,
} from '../../../shared/components/multi-select-dropdown/multi-select-dropdown.component';
import { RefreshButtonComponent } from '../../../shared/components/refresh-button/refresh-button.component';
import {
  ReportSortKey,
  ReportTableComponent,
} from '../../../shared/components/report-table/report-table.component';
import { TableControlsComponent } from '../../../shared/components/table-controls/table-controls.component';
import { TableSort } from '../../../shared/utils/table-sort';

const PAGE_SIZE = 25;

/**
 * All reports, filtered by project and risk level (filters live in the URL) and sorted by the
 * server in the column order remembered by the browser.
 */
@Component({
  selector: 'app-report-list',
  imports: [
    MultiSelectDropdownComponent,
    ReportTableComponent,
    RefreshButtonComponent,
    TableControlsComponent,
    TranslatePipe,
  ],
  templateUrl: './report-list.component.html',
  styleUrl: './report-list.component.css',
})
export class ReportListComponent {
  private readonly api = inject(ApiService);
  private readonly router = inject(Router);
  private readonly i18n = inject(I18nService);

  /** Query parameters ?project=&risk=&page= (project and risk may be repeated) */
  readonly project = input<string | string[]>();
  readonly risk = input<string | string[]>();
  readonly page = input<string>();
  readonly search = input<string>();

  readonly pageSize = PAGE_SIZE;
  /** Columns the server sorts by (not the open findings: they depend on the triage). */
  readonly sort = new TableSort<Exclude<ReportSortKey, 'findings_open'>>(
    'reports',
    ['created_at', 'project', 'risk_level', 'review_type', 'branch', 'submitted_by', 'summary'],
    'created_at',
    'desc',
    () => this.goToPage(1),
  );

  readonly pageNumber = computed(() => Math.max(1, Number.parseInt(this.page() ?? '1', 10) || 1));

  readonly projectFilter = computed(() => asList(this.project()));
  readonly riskLevels = computed(() => {
    const risks = asList(this.risk());
    return SEVERITIES.filter((severity) => risks.includes(severity));
  });

  readonly projects = rxResource({ stream: () => this.api.projects() });

  readonly projectOptions = computed<MultiSelectOption[]>(() =>
    (this.projects.value() ?? []).map((p) => ({ value: p.project, label: p.project })),
  );
  readonly riskOptions = computed<MultiSelectOption[]>(() =>
    SEVERITIES.map((severity) => ({
      value: severity,
      label: this.i18n.translate(SEVERITY_META[severity].label),
    })),
  );

  readonly reports = rxResource({
    params: () => ({
      project: this.projectFilter(),
      risk_level: this.riskLevels(),
      search: this.search()?.trim() || undefined,
      sort_by: this.sort.key(),
      sort_direction: this.sort.direction(),
      // One extra row tells whether a next page exists
      limit: PAGE_SIZE + 1,
      offset: (this.pageNumber() - 1) * PAGE_SIZE,
    }),
    stream: ({ params }) => this.api.reports(params),
  });

  readonly rows = computed(() => (this.reports.value() ?? []).slice(0, PAGE_SIZE));
  readonly hasNext = computed(() => (this.reports.value() ?? []).length > PAGE_SIZE);

  onProjects(values: string[]): void {
    this.navigate({ project: values.length ? values : null, page: null });
  }

  onRisks(values: string[]): void {
    this.navigate({ risk: values.length ? values : null, page: null });
  }

  onSearch(value: string): void {
    this.navigate({ search: value || null, page: null }, true);
  }

  goToPage(page: number): void {
    this.navigate({ page: page > 1 ? page : null });
  }

  private navigate(
    queryParams: Record<string, string | string[] | number | null>,
    replaceUrl = false,
  ): void {
    this.router.navigate([], { queryParams, queryParamsHandling: 'merge', replaceUrl });
  }
}

/** Values of a query parameter given once or repeated. */
function asList(value: string | string[] | undefined): string[] {
  return (Array.isArray(value) ? value : [value ?? '']).filter(Boolean);
}
