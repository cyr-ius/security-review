import { Component, computed, inject, input } from '@angular/core';
import { rxResource } from '@angular/core/rxjs-interop';
import { Router } from '@angular/router';
import { SEVERITY_META } from '../../../core/constants/labels';
import { TranslatePipe } from '../../../core/i18n/translate.pipe';
import { SEVERITIES, Severity } from '../../../core/models/api.models';
import { ApiService } from '../../../core/services/api.service';
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
  imports: [ReportTableComponent, RefreshButtonComponent, TableControlsComponent, TranslatePipe],
  templateUrl: './report-list.component.html',
  styleUrl: './report-list.component.css',
})
export class ReportListComponent {
  private readonly api = inject(ApiService);
  private readonly router = inject(Router);

  /** Query parameters ?project=&risk=&page= */
  readonly project = input<string>();
  readonly risk = input<string>();
  readonly page = input<string>();
  readonly search = input<string>();

  readonly severities = SEVERITIES;
  readonly severityMeta = SEVERITY_META;
  readonly pageSize = PAGE_SIZE;
  /** Columns the server sorts by (not the open findings: they depend on the triage). */
  readonly sort = new TableSort<Exclude<ReportSortKey, 'findings_open'>>(
    'reports',
    ['created_at', 'project', 'risk_level', 'review_type', 'branch', 'author', 'summary'],
    'created_at',
    'desc',
    () => this.goToPage(1),
  );

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

  onProject(event: Event): void {
    this.navigate({ project: (event.target as HTMLSelectElement).value || null, page: null });
  }

  onRisk(event: Event): void {
    this.navigate({ risk: (event.target as HTMLSelectElement).value || null, page: null });
  }

  onSearch(value: string): void {
    this.navigate({ search: value || null, page: null }, true);
  }

  goToPage(page: number): void {
    this.navigate({ page: page > 1 ? page : null });
  }

  private navigate(queryParams: Record<string, string | number | null>, replaceUrl = false): void {
    this.router.navigate([], { queryParams, queryParamsHandling: 'merge', replaceUrl });
  }
}
